package scenarios

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"sindri/internal/core"
)

func TestXrayManagedLifecycleKeepsRoutingFailClosed(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("Xray lifecycle test requires a root Linux test container")
	}
	env := testEnvironment(t)
	writeFile(t, hostPath(env, "/etc/os-release"), "ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\n")
	fakeBin := installFakeXrayLifecycleCommands(t)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	t.Setenv("FAKE_BIN", fakeBin)
	t.Setenv("FAKE_STATE_DIR", filepath.Join(env.DataDir, "xray-fake-state"))
	t.Setenv("FAKE_HOST_ROOT", env.HostRoot)
	if err := os.MkdirAll(os.Getenv("FAKE_STATE_DIR"), 0750); err != nil {
		t.Fatal(err)
	}

	originalReleaseLoader := xrayReleaseLoader
	originalIPLookup := proxyIPInfoLookup
	xrayReleaseLoader = func(context.Context) (xrayReleaseBundle, error) {
		return xrayReleaseBundle{
			SHA256: strings.Repeat("a", 64),
			Files: map[string][]byte{
				"xray":        []byte("#!/bin/sh\nif [ \"$1\" = version ]; then echo 'Xray 99.0.0 test'; fi\nexit 0\n"),
				"geoip.dat":   []byte("geoip fixture\n"),
				"geosite.dat": []byte("geosite fixture\n"),
			},
		}, nil
	}
	proxyIPInfoLookup = func(core.Context) (proxyIPInfo, error) {
		return proxyIPInfo{IP: "203.0.113.9", Country: "NL", Region: "North Holland", City: "Amsterdam", Org: "AS64500"}, nil
	}
	t.Cleanup(func() {
		xrayReleaseLoader = originalReleaseLoader
		proxyIPInfoLookup = originalIPLookup
	})
	ctx := core.Context{Context: context.Background(), Env: env}

	installed := xrayInstall(ctx, core.Request{}, nil)
	assertResult(t, "xray install", installed, core.StatusSuccess)
	for _, path := range []string{xrayBinaryPath, xrayGeneratedConfig, xrayProfilesPath, xraySystemdServicePath, xrayRoutingServicePath, xrayRoutingScriptPath} {
		if _, err := os.Stat(hostPath(env, path)); err != nil {
			t.Fatalf("installed Xray path %s: %v", path, err)
		}
	}

	profiles := testVLESSLink("%F0%9F%87%AF%F0%9F%87%B5%20-%20Japan%20-%20Smart") + "\n" + testVLESSLink("%F0%9F%87%B3%F0%9F%87%B1%20-%20Netherlands%20-%20Smart") + "\n"
	if err := atomicWrite(hostPath(env, xrayProfilesPath), []byte(profiles), 0600); err != nil {
		t.Fatal(err)
	}
	choice := xrayOn(ctx, core.Request{}, map[string]interface{}{})
	if choice.Status != core.StatusInputRequired || len(choice.Fields) != 1 || len(choice.Fields[0].Values) != 2 {
		t.Fatalf("Xray profile choice = %#v", choice)
	}
	selected := "🇳🇱 - Netherlands - Smart"
	enabled := xrayOn(ctx, core.Request{}, map[string]interface{}{"profile": selected})
	assertResult(t, "xray on", enabled, core.StatusSuccess)
	if enabled.Data["fail_closed"] != true || enabled.Data["docker_traffic"] != true || enabled.Data["dns"] != true {
		t.Fatalf("Xray transparent mode data = %#v", enabled.Data)
	}
	if !fileExists(filepath.Join(os.Getenv("FAKE_STATE_DIR"), "nft-sindri-xray")) {
		t.Fatal("fail-closed nftables table was not activated")
	}
	generated, err := os.ReadFile(hostPath(env, xrayGeneratedConfig))
	if err != nil || strings.Contains(string(generated), "vless://") || !strings.Contains(string(generated), `"password":`) {
		t.Fatalf("generated Xray config is unsafe or incomplete: %v\n%s", err, generated)
	}
	state := loadXrayRuntimeState(env)
	if !state.Enabled || state.ProfileName != selected {
		t.Fatalf("Xray runtime state = %#v", state)
	}
	assertResult(t, "xray status", xrayStatus(ctx, core.Request{}, nil), core.StatusSuccess)
	t.Setenv("FAKE_XRAY_START_FAIL", "1")
	failedStart := xrayOn(ctx, core.Request{}, map[string]interface{}{"profile": selected})
	if failedStart.Status != core.StatusFailed || failedStart.Error == nil || failedStart.Error.Code != "XRAY_START_FAILED" || failedStart.Data["fail_closed"] != true {
		t.Fatalf("failed Xray start = %#v", failedStart)
	}
	if !fileExists(filepath.Join(os.Getenv("FAKE_STATE_DIR"), "nft-sindri-xray")) {
		t.Fatal("fail-closed nftables table disappeared after Xray failed")
	}
	failedStatus := xrayStatus(ctx, core.Request{}, nil)
	if failedStatus.Status != core.StatusFailed || failedStatus.Error == nil || failedStatus.Error.Code != "XRAY_INACTIVE" || failedStatus.Data["fail_closed"] != true {
		t.Fatalf("failed Xray status = %#v", failedStatus)
	}
	if err := os.Unsetenv("FAKE_XRAY_START_FAIL"); err != nil {
		t.Fatal(err)
	}

	disabled := xrayOff(ctx, core.Request{}, nil)
	assertResult(t, "xray off", disabled, core.StatusSuccess)
	if fileExists(filepath.Join(os.Getenv("FAKE_STATE_DIR"), "nft-sindri-xray")) || loadXrayRuntimeState(env).Enabled {
		t.Fatal("Xray routing remained active after xray off")
	}

	uninstalled := xrayUninstall(ctx, core.Request{}, nil)
	assertResult(t, "xray uninstall", uninstalled, core.StatusSuccess)
	for _, path := range []string{xrayBinaryPath, xrayConfigDirectory, xrayProfilesDirectory, xrayShareDirectory, xraySystemdServicePath, xrayRoutingServicePath, xrayRoutingScriptPath} {
		if _, err := os.Lstat(hostPath(env, path)); !os.IsNotExist(err) {
			t.Fatalf("Xray path remains after uninstall: %s (%v)", path, err)
		}
	}
}

func TestNginxUninstallPurgesFilesButPreservesCertificates(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("Nginx uninstall test requires a root Linux test container")
	}
	env := testEnvironment(t)
	writeFile(t, hostPath(env, "/etc/os-release"), "ID=ubuntu\nVERSION_ID=\"24.04\"\n")
	fakeBin := t.TempDir()
	state := filepath.Join(env.DataDir, "nginx-uninstall-state")
	if err := os.MkdirAll(state, 0750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_BIN", fakeBin)
	t.Setenv("FAKE_STATE_DIR", state)
	script := `#!/bin/sh
set -eu
name=$(basename "$0")
case "$name" in
  apt-get)
    printf '%s\n' "$*" >>"$FAKE_STATE_DIR/apt-calls"
    case " $* " in *" purge "*) rm -f "$FAKE_BIN/nginx" ;; esac
    ;;
  dpkg-query) printf 'nginx\tii \nnginx-common\tii \n' ;;
  systemctl|nginx) exit 0 ;;
esac
`
	for _, command := range []string{"apt-get", "dpkg-query", "systemctl", "nginx"} {
		writeExecutable(t, filepath.Join(fakeBin, command), script)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+"/usr/bin:/bin")
	for _, directory := range []string{"/etc/nginx/sites-available", "/var/log/nginx", "/var/cache/nginx", "/var/lib/nginx"} {
		writeFile(t, hostPath(env, directory+"/fixture"), "fixture\n")
	}
	writeFile(t, hostPath(env, nginxCertbotPre), "hook\n")
	writeFile(t, hostPath(env, nginxCertbotPost), "hook\n")
	certificate := hostPath(env, "/etc/letsencrypt/live/example.test/fullchain.pem")
	writeFile(t, certificate, "certificate\n")
	resources := managedResources{
		Packages: []string{"nginx", "unrelated"}, Services: []string{"nginx.service", "unrelated.service"},
		Files: []string{hostPath(env, nginxSiteAvailable), certificate},
	}
	if err := saveManaged(env, resources); err != nil {
		t.Fatal(err)
	}

	result := nginxUninstall(core.Context{Context: context.Background(), Env: env}, core.Request{}, nil)
	assertResult(t, "nginx uninstall", result, core.StatusSuccess)
	for _, directory := range []string{"/etc/nginx", "/var/log/nginx", "/var/cache/nginx", "/var/lib/nginx"} {
		if _, err := os.Stat(hostPath(env, directory)); !os.IsNotExist(err) {
			t.Fatalf("Nginx directory remains: %s (%v)", directory, err)
		}
	}
	if _, err := os.Stat(certificate); err != nil {
		t.Fatalf("certificate was removed: %v", err)
	}
	remaining := loadManaged(env)
	if containsString(remaining.Packages, "nginx") || containsString(remaining.Services, "nginx.service") || !containsString(remaining.Packages, "unrelated") {
		t.Fatalf("managed resources were not updated safely: %#v", remaining)
	}
}

func TestXrayUninstallRefusesUnmanagedInstallation(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("Xray uninstall test requires a root Linux test container")
	}
	env := testEnvironment(t)
	binary := hostPath(env, xrayBinaryPath)
	writeFile(t, binary, "external xray installation\n")

	result := xrayUninstall(core.Context{Context: context.Background(), Env: env}, core.Request{}, nil)
	if result.Status != core.StatusFailed || result.Error == nil || result.Error.Code != "XRAY_NOT_MANAGED" {
		t.Fatalf("unmanaged Xray uninstall = %#v", result)
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("unmanaged Xray binary was changed: %v", err)
	}
}

func TestXrayInstallRefusesUnmanagedServiceAccount(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("Xray install test requires a root Linux test container")
	}
	env := testEnvironment(t)
	writeFile(t, hostPath(env, "/etc/os-release"), "ID=ubuntu\nVERSION_ID=\"24.04\"\n")
	fakeBin := t.TempDir()
	writeExecutable(t, filepath.Join(fakeBin, "id"), "#!/bin/sh\nprintf '991\\n'\n")
	writeExecutable(t, filepath.Join(fakeBin, "getent"), "#!/bin/sh\nexit 1\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+"/usr/bin:/bin")

	result := xrayInstall(core.Context{Context: context.Background(), Env: env}, core.Request{}, nil)
	if result.Status != core.StatusFailed || result.Error == nil || result.Error.Code != "XRAY_UNMANAGED_INSTALLATION" {
		t.Fatalf("unmanaged Xray account install = %#v", result)
	}
	if fileExists(hostPath(env, xrayManagedMarkerPath)) {
		t.Fatal("unmanaged Xray account was adopted by Sindri")
	}
}

func TestNginxUninstallRefusesUnpackagedBinary(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("Nginx uninstall test requires a root Linux test container")
	}
	env := testEnvironment(t)
	writeFile(t, hostPath(env, "/etc/os-release"), "ID=ubuntu\nVERSION_ID=\"24.04\"\n")
	fakeBin := t.TempDir()
	writeExecutable(t, filepath.Join(fakeBin, "nginx"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(fakeBin, "dpkg-query"), "#!/bin/sh\nexit 1\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+"/usr/bin:/bin")
	config := hostPath(env, "/etc/nginx/nginx.conf")
	writeFile(t, config, "external config\n")

	result := nginxUninstall(core.Context{Context: context.Background(), Env: env}, core.Request{}, nil)
	if result.Status != core.StatusFailed || result.Error == nil || result.Error.Code != "NGINX_UNMANAGED_INSTALLATION" {
		t.Fatalf("unpackaged Nginx uninstall = %#v", result)
	}
	if _, err := os.Stat(config); err != nil {
		t.Fatalf("unmanaged Nginx configuration was changed: %v", err)
	}
}

func installFakeXrayLifecycleCommands(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	script := `#!/bin/sh
set -eu
name=$(basename "$0")
state=${FAKE_STATE_DIR:?}
case "$name" in
  apt-get) printf '%s\n' "$*" >>"$state/apt-calls" ;;
  id)
    if [ "${1:-}" = "-u" ] && [ -f "$state/user-${2:-}" ]; then printf '991\n'; exit 0; fi
    exit 1
    ;;
  useradd)
    for username in "$@"; do :; done
    : >"$state/user-$username"
    : >"$state/group-$username"
    ;;
  userdel) rm -f "$state/user-${1:-}" ;;
  getent) [ "${1:-}" = group ] && [ -f "$state/group-${2:-}" ] ;;
  groupdel) rm -f "$state/group-${1:-}" ;;
  chown|ip) exit 0 ;;
  nft)
    if [ "${1:-}" = "-f" ]; then cat >/dev/null; : >"$state/nft-sindri-xray"; exit 0; fi
    if [ "${1:-}" = delete ]; then rm -f "$state/nft-sindri-xray"; exit 0; fi
    if [ "${1:-}" = list ]; then [ -f "$state/nft-sindri-xray" ]; exit $?; fi
    ;;
  systemctl)
    action=${1:-}
    shift || true
    case "$action" in
      daemon-reload) exit 0 ;;
      enable)
        for service in "$@"; do case "$service" in -*) ;; *) : >"$state/enabled-$service" ;; esac; done
        ;;
      disable)
        for service in "$@"; do case "$service" in -*) ;; *) rm -f "$state/enabled-$service" ;; esac; done
        ;;
      restart|start)
        service=
        for argument in "$@"; do service=$argument; done
        if [ "$service" = "sindri-xray-routing.service" ]; then "$FAKE_HOST_ROOT/usr/local/lib/sindri/xray-routing" on; fi
		if [ "$service" = "xray.service" ] && [ "${FAKE_XRAY_START_FAIL:-}" = "1" ]; then
		  rm -f "$state/active-$service"
		  exit 1
		fi
        : >"$state/active-$service"
        ;;
      stop)
        service=
        for argument in "$@"; do service=$argument; done
        if [ "$service" = "sindri-xray-routing.service" ]; then "$FAKE_HOST_ROOT/usr/local/lib/sindri/xray-routing" off; fi
        rm -f "$state/active-$service"
        ;;
      is-active)
        service=
        for argument in "$@"; do service=$argument; done
        [ -f "$state/active-$service" ]
        ;;
    esac
    ;;
esac
`
	for _, command := range []string{"apt-get", "id", "useradd", "userdel", "getent", "groupdel", "chown", "ip", "nft", "systemctl"} {
		writeExecutable(t, filepath.Join(directory, command), script)
	}
	return directory
}
