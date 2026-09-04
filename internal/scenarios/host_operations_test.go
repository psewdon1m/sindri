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

func TestFail2banSSHDJailUsesConfiguredPorts(t *testing.T) {
	want := `[sshd]
enabled = true
backend = systemd
port = 22,2222
findtime = 10m
maxretry = 5
bantime = 1h
`
	if got := string(fail2banSSHDJail([]int{22, 2222})); got != want {
		t.Fatalf("unexpected Fail2ban SSH jail:\n%s", got)
	}
}

func TestSSHPortsUsesDefaultOnlyWithoutExplicitConfiguration(t *testing.T) {
	env := testEnvironment(t)
	if ports := sshPorts(env); len(ports) != 1 || ports[0] != 22 {
		t.Fatalf("default SSH ports = %#v, want [22]", ports)
	}

	writeFile(t, hostPath(env, "/etc/ssh/sshd_config"), "Port 2222\n")
	writeFile(t, hostPath(env, "/etc/ssh/sshd_config.d/10-secondary.conf"), "Port 2200\nPort 2222\n")
	ports := sshPorts(env)
	if len(ports) != 2 || ports[0] != 2200 || ports[1] != 2222 {
		t.Fatalf("configured SSH ports = %#v, want [2200 2222]", ports)
	}
}

func TestProductionScenariosExposeValidatedTestPlans(t *testing.T) {
	env := testEnvironment(t)
	registry := NewRegistry("test", "1", "test")
	cases := []struct {
		action string
		inputs map[string]interface{}
	}{
		{"system.make_ready", nil},
		{"system.reboot", nil},
		{"system.shutdown", nil},
		{"system.recovery", nil},
		{"system.exterminatus", nil},
		{"firewall.enable", nil},
		{"firewall.disable", nil},
		{"firewall.close", map[string]interface{}{"port": 8080, "protocol": "tcp"}},
		{"docker.install", nil},
		{"docker.uninstall", nil},
		{"docker.up", map[string]interface{}{"path": "."}},
		{"docker.down", map[string]interface{}{"path": "."}},
		{"docker.clean", nil},
		{"docker.logs", map[string]interface{}{"lines": 100}},
		{"geo.get", map[string]interface{}{"container": "node"}},
		{"nginx.install", nil},
		{"nginx.config_edit", nil},
		{"nginx.start", nil},
		{"nginx.reload", nil},
		{"nginx.stop", nil},
		{"nginx.uninstall", nil},
		{"xray.install", nil},
		{"xray.config", nil},
		{"xray.on", nil},
		{"xray.off", nil},
		{"xray.uninstall", nil},
		{"user.add", map[string]interface{}{"username": "sindri-test", "password": "long-test-password", "sudo": false}},
		{"user.delete", map[string]interface{}{"username": "sindri-test", "remove_home": false}},
		{"user.password_change", map[string]interface{}{"username": "sindri-test", "password": "long-test-password"}},
		{"cert.delete", map[string]interface{}{"certificate": "node.example.test"}},
	}
	for _, item := range cases {
		t.Run(item.action, func(t *testing.T) {
			result := core.Execute(context.Background(), registry, env, core.Request{
				Action: item.action,
				Test:   true,
				Inputs: item.inputs,
				Source: "test",
			})
			if result.Status != core.StatusSuccess ||
				(result.ExitCode != core.ExitTestModeCompleted && result.ExitCode != core.ExitSuccess) {
				t.Fatalf("test plan failed: status=%s exit=%d error=%#v", result.Status, result.ExitCode, result.Error)
			}
			if result.Data["test_mode"] != true || len(result.Steps) == 0 {
				t.Fatalf("scenario did not return an executable plan: %#v", result)
			}
			if item.action == "user.add" || item.action == "user.password_change" {
				inputs, _ := result.Data["inputs"].(map[string]interface{})
				if inputs["password"] != "[redacted]" {
					t.Fatalf("secret input was exposed in test plan: %#v", inputs)
				}
			}
		})
	}
}

func TestProductionHandlersAgainstIsolatedSystemAdapters(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("production adapter smoke test requires a root Linux test container")
	}
	env := testEnvironment(t)
	originalCloudflareLoader := cloudflareRangeLoader
	cloudflareRangeLoader = func(context.Context) ([]string, string, error) {
		return append([]string(nil), embeddedCloudflareRanges...), "test", nil
	}
	t.Cleanup(func() { cloudflareRangeLoader = originalCloudflareLoader })
	fakeBin := installFakeSystemCommands(t)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_STATE_DIR", filepath.Join(env.DataDir, "fake-state"))
	if err := os.MkdirAll(os.Getenv("FAKE_STATE_DIR"), 0750); err != nil {
		t.Fatal(err)
	}
	containerDirectory := filepath.Join(os.Getenv("FAKE_STATE_DIR"), "container-node", "usr", "local", "share", "xray")
	writeFile(t, filepath.Join(containerDirectory, "geosite.dat"), "old geosite\n")
	writeFile(t, filepath.Join(containerDirectory, "geoip.dat"), "old geoip\n")
	writeFile(t, filepath.Join(os.Getenv("FAKE_STATE_DIR"), "container-node-running"), "running\n")
	releaseVersion := "new"
	originalGeoDataLoader := geoDataAssetLoader
	geoDataAssetLoader = func(ctx context.Context, directory string) ([]geoDataAsset, error) {
		assets := make([]geoDataAsset, 0, len(geoDataNames))
		for _, name := range geoDataNames {
			path := filepath.Join(directory, name)
			writeFile(t, path, releaseVersion+" "+name+"\n")
			hash, size, err := hashGeoDataFile(path)
			if err != nil {
				return nil, err
			}
			assets = append(assets, geoDataAsset{Name: name, Path: path, SHA256: hash, Size: size})
		}
		return assets, nil
	}
	t.Cleanup(func() { geoDataAssetLoader = originalGeoDataLoader })
	writeFile(t, hostPath(env, "/etc/os-release"), "ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\n")
	if err := os.MkdirAll(hostPath(env, "/var"), 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, hostPath(env, "/etc/ssh/sshd_config"), "Port 2222\n")
	t.Setenv("FAKE_FAIL2BAN_STATUS_FAILURES", "2")
	ctx := core.Context{Context: context.Background(), Env: env}

	assertResult(t, "make ready", makeReady(ctx, core.Request{}, nil), core.StatusSuccess)
	aptCalls, err := os.ReadFile(filepath.Join(os.Getenv("FAKE_STATE_DIR"), "apt-get-calls"))
	if err != nil || !strings.Contains(string(aptCalls), "install -y fail2ban") {
		t.Fatalf("Fail2ban package installation was not requested: %q, %v", aptCalls, err)
	}
	fail2banConfig, err := os.ReadFile(hostPath(env, fail2banJailPath))
	if err != nil {
		t.Fatalf("Fail2ban SSH jail was not written: %v", err)
	}
	for _, expected := range []string{
		"[sshd]", "enabled = true", "backend = systemd", "port = 2222",
		"findtime = 10m", "maxretry = 5", "bantime = 1h",
	} {
		if !strings.Contains(string(fail2banConfig), expected) {
			t.Fatalf("Fail2ban SSH jail is missing %q: %s", expected, fail2banConfig)
		}
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("FAKE_STATE_DIR"), "service-fail2ban-active")); err != nil {
		t.Fatalf("Fail2ban service was not activated: %v", err)
	}
	fail2banCalls, err := os.ReadFile(filepath.Join(os.Getenv("FAKE_STATE_DIR"), "fail2ban-client-calls"))
	if err != nil {
		t.Fatalf("Fail2ban client calls were not recorded: %v", err)
	}
	for _, expected := range []string{"-t", "status sshd", "--version"} {
		if !strings.Contains(string(fail2banCalls), expected) {
			t.Fatalf("Fail2ban client was not called with %q: %s", expected, fail2banCalls)
		}
	}
	if attempts := strings.Count(string(fail2banCalls), "status sshd"); attempts != 3 {
		t.Fatalf("Fail2ban readiness attempts = %d, want 3: %s", attempts, fail2banCalls)
	}
	managed := loadManaged(env)
	if !containsString(managed.Packages, "fail2ban") ||
		!containsString(managed.Packages, "nano") ||
		!containsString(managed.Services, "fail2ban.service") ||
		!containsString(managed.Files, hostPath(env, fail2banJailPath)) {
		t.Fatalf("Fail2ban resources were not tracked: %#v", managed)
	}
	assertResult(t, "reboot", rebootHost(ctx, core.Request{}, nil), core.StatusSuccess)
	assertResult(t, "firewall enable", firewallEnable(ctx, core.Request{}, nil), core.StatusSuccess)
	assertResult(t, "firewall disable", firewallDisable(ctx, core.Request{}, nil), core.StatusSuccess)
	assertResult(t, "firewall close", firewallClose(ctx, core.Request{}, map[string]interface{}{"port": 8080, "protocol": "tcp"}), core.StatusSuccess)
	assertResult(t, "docker install", dockerInstall(ctx, core.Request{}, nil), core.StatusSuccess)
	assertResult(t, "docker logs", dockerLogs(ctx, core.Request{}, map[string]interface{}{"lines": 50}), core.StatusSuccess)
	assertResult(t, "docker clean", dockerClean(ctx, core.Request{}, nil), core.StatusSuccess)
	geoInputs := map[string]interface{}{"container": "node"}
	geoUpdated := geoGet(ctx, core.Request{}, geoInputs)
	assertResult(t, "geodata update", geoUpdated, core.StatusSuccess)
	if !geoUpdated.Changed || geoUpdated.Data["backup"] == "" {
		t.Fatalf("geodata update did not report its change and backup: %#v", geoUpdated)
	}
	for _, name := range geoDataNames {
		body, err := os.ReadFile(filepath.Join(containerDirectory, name))
		if err != nil || string(body) != releaseVersion+" "+name+"\n" {
			t.Fatalf("container %s was not updated: %q, %v", name, body, err)
		}
		backup, _ := geoUpdated.Data["backup"].(string)
		oldBody, err := os.ReadFile(filepath.Join(backup, name))
		if err != nil || string(oldBody) != "old "+strings.TrimSuffix(name, ".dat")+"\n" {
			t.Fatalf("backup %s is invalid: %q, %v", name, oldBody, err)
		}
	}
	geoUnchanged := geoGet(ctx, core.Request{}, geoInputs)
	assertResult(t, "unchanged geodata", geoUnchanged, core.StatusSuccess)
	if geoUnchanged.Changed || geoUnchanged.Data["restarted"] != false {
		t.Fatalf("unchanged geodata restarted the container: %#v", geoUnchanged)
	}
	releaseVersion = "broken"
	writeFile(t, filepath.Join(os.Getenv("FAKE_STATE_DIR"), "fail-next-geodata-install"), "fail\n")
	geoRolledBack := geoGet(ctx, core.Request{}, geoInputs)
	assertResult(t, "geodata rollback", geoRolledBack, core.StatusFailed)
	if geoRolledBack.Data["rolled_back"] != true {
		t.Fatalf("failed geodata update was not rolled back: %#v", geoRolledBack)
	}
	for _, name := range geoDataNames {
		body, err := os.ReadFile(filepath.Join(containerDirectory, name))
		if err != nil || string(body) != "new "+name+"\n" {
			t.Fatalf("rollback did not restore %s: %q, %v", name, body, err)
		}
	}
	assertResult(t, "nginx install", nginxInstall(ctx, core.Request{}, nil), core.StatusSuccess)
	cloudflareConfig, err := os.ReadFile(hostPath(env, nginxCloudflareIP))
	if err != nil || !strings.Contains(string(cloudflareConfig), "real_ip_header CF-Connecting-IP;") {
		t.Fatalf("Cloudflare real-IP configuration was not installed: %q, %v", cloudflareConfig, err)
	}
	if !containsString(loadManaged(env).Files, hostPath(env, nginxCloudflareIP)) {
		t.Fatal("Cloudflare real-IP configuration was not tracked")
	}
	writeFile(t, hostPath(env, nginxSiteAvailable), "server { listen 80; }\n")
	if _, err := os.Lstat(hostPath(env, nginxSiteEnabled)); os.IsNotExist(err) {
		if err := os.Symlink("../sites-available/default", hostPath(env, nginxSiteEnabled)); err != nil {
			t.Fatal(err)
		}
	}
	assertResult(t, "nginx start", nginxStart(ctx, core.Request{}, nil), core.StatusSuccess)
	assertResult(t, "nginx status", nginxStatus(ctx, core.Request{}, nil), core.StatusSuccess)
	assertResult(t, "nginx reload", nginxReload(ctx, core.Request{}, nil), core.StatusSuccess)
	assertResult(t, "nginx stop", nginxStop(ctx, core.Request{}, nil), core.StatusSuccess)
	nginxActiveState := filepath.Join(os.Getenv("FAKE_STATE_DIR"), "service-nginx-active")
	writeFile(t, nginxActiveState, "active\n")
	assertResult(t, "nginx reinstall while active", nginxInstall(ctx, core.Request{}, nil), core.StatusSuccess)
	if _, err := os.Stat(nginxActiveState); err != nil {
		t.Fatalf("nginx install interrupted an existing active service: %v", err)
	}

	composeDir := filepath.Join(env.DataDir, "compose-project")
	writeFile(t, filepath.Join(composeDir, "compose.yaml"), "services: {}\n")
	assertResult(t, "docker up", dockerUp(ctx, core.Request{}, map[string]interface{}{"path": composeDir}), core.StatusSuccess)
	assertResult(t, "docker down", dockerDown(ctx, core.Request{}, map[string]interface{}{"path": composeDir}), core.StatusSuccess)

	addInputs := map[string]interface{}{"username": "sindri-test", "password": "long-test-password", "sudo": true}
	assertResult(t, "user add", userAdd(ctx, core.Request{}, addInputs), core.StatusSuccess)
	assertResult(t, "password change", userPasswordChange(ctx, core.Request{}, map[string]interface{}{"username": "sindri-test", "password": "another-long-password"}), core.StatusSuccess)
	assertResult(t, "user delete", userDelete(ctx, core.Request{}, map[string]interface{}{"username": "sindri-test", "remove_home": true}), core.StatusSuccess)
	assertResult(t, "certificate delete", certificateDelete(ctx, core.Request{}, map[string]interface{}{"certificate": "node.example.test"}), core.StatusSuccess)
	if value, err := os.ReadFile(filepath.Join(os.Getenv("FAKE_STATE_DIR"), "certbot-res-options")); err != nil || string(value) != "attempts:5 timeout:2\n" {
		t.Fatalf("Certbot DNS retry options were not applied: %q, %v", value, err)
	}

	assertResult(t, "shutdown", shutdownHost(ctx, core.Request{}, nil), core.StatusSuccess)
	assertResult(t, "recovery", recoverHost(ctx, core.Request{}, nil), core.StatusSuccess)
	replayedRecovery := recoverHost(ctx, core.Request{}, nil)
	assertResult(t, "replayed recovery", replayedRecovery, core.StatusFailed)
	if replayedRecovery.Error == nil || replayedRecovery.Error.Code != "RECOVERY_STATE_INACTIVE" {
		t.Fatalf("recovered bundle was replayable: %#v", replayedRecovery)
	}

	hostname, _ := os.Hostname()
	exterminatus := exterminatusHost(ctx, core.Request{
		Approval: &core.Approval{
			ConfirmationPhrase:   "EXTERMINATUS",
			HostnameConfirmation: hostname,
		},
	}, nil)
	assertResult(t, "exterminatus", exterminatus, core.StatusPartial)
	if exterminatus.Data["provider_action_required"] == nil {
		t.Fatal("exterminatus must report the remaining provider-side actions")
	}
}

func TestDockerUninstallVerifiesTheBinaryWasRemoved(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("production adapter smoke test requires a root Linux test container")
	}
	env := testEnvironment(t)
	fakeBin := t.TempDir()
	writeExecutable(t, filepath.Join(fakeBin, "apt-get"), "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", fakeBin)
	ctx := core.Context{Context: context.Background(), Env: env}
	resources := managedResources{
		Packages: []string{"docker-ce", "docker-ce-cli", "unrelated-package"},
		Services: []string{"docker.service", "containerd.service", "unrelated.service"},
		Files: []string{
			hostPath(env, "/etc/apt/sources.list.d/docker.list"),
			hostPath(env, "/etc/apt/keyrings/docker.asc"),
			hostPath(env, "/etc/docker/daemon.json"),
		},
	}
	if err := saveManaged(env, resources); err != nil {
		t.Fatal(err)
	}
	assertResult(t, "docker uninstall", dockerUninstall(ctx, core.Request{}, nil), core.StatusSuccess)
	resources = loadManaged(env)
	if containsString(resources.Packages, "docker-ce") || containsString(resources.Services, "docker.service") || containsString(resources.Files, hostPath(env, "/etc/docker/daemon.json")) {
		t.Fatalf("Docker resources remain in managed inventory: %#v", resources)
	}
	if !containsString(resources.Packages, "unrelated-package") || !containsString(resources.Services, "unrelated.service") {
		t.Fatalf("unrelated inventory was removed: %#v", resources)
	}
}

func TestCertificateCopyRepairsPrivateKeyModeAndTracksFiles(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("certificate copy test requires root Linux")
	}
	env := testEnvironment(t)
	ctx := core.Context{Context: context.Background(), Env: env}
	source := hostPath(env, "/etc/letsencrypt/live/example.test")
	for _, name := range []string{"fullchain.pem", "privkey.pem", "cert.pem", "chain.pem"} {
		writeFile(t, filepath.Join(source, name), "fixture-"+name+"\n")
	}
	destination := hostPath(env, "/opt/certificate-copy")
	writeFile(t, filepath.Join(destination, "privkey.pem"), "old-mode\n")
	if err := os.Chmod(filepath.Join(destination, "privkey.pem"), 0644); err != nil {
		t.Fatal(err)
	}
	result := certificateCopy(ctx, core.Request{}, map[string]interface{}{"certificate": "example.test", "destination": "/opt/certificate-copy"})
	assertResult(t, "certificate copy", result, core.StatusSuccess)
	info, err := os.Stat(filepath.Join(destination, "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("private key mode = %o, want 600", info.Mode().Perm())
	}
	resources := loadManaged(env)
	if !containsString(resources.Files, filepath.Join(destination, "privkey.pem")) {
		t.Fatalf("copied private key was not tracked: %#v", resources.Files)
	}
}

func TestCertificateNewInstallsCertbotAfterConnectivityPreflight(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("certificate issuance adapter test requires root Linux")
	}
	env := testEnvironment(t)
	writeFile(t, hostPath(env, "/etc/os-release"), "ID=ubuntu\nVERSION_ID=\"24.04\"\n")
	fakeBin := t.TempDir()
	template := filepath.Join(t.TempDir(), "certbot-template")
	writeExecutable(t, template, `#!/bin/sh
domain=
previous=
for argument in "$@"; do
  if [ "$previous" = "-d" ]; then domain=$argument; fi
  previous=$argument
done
target="${FAKE_HOST_ROOT:?}/etc/letsencrypt/live/$domain"
/bin/mkdir -p "$target"
printf fullchain >"$target/fullchain.pem"
printf private >"$target/privkey.pem"
printf '%s\n' "${RES_OPTIONS:-}" >"${FAKE_STATE_DIR:?}/certbot-res-options"
`)
	writeExecutable(t, filepath.Join(fakeBin, "apt-get"), `#!/bin/sh
install_certbot=0
for argument in "$@"; do
  if [ "$argument" = "certbot" ]; then install_certbot=1; fi
done
if [ "$install_certbot" = "1" ]; then
  /bin/cp "${FAKE_CERTBOT_TEMPLATE:?}" "${FAKE_BIN:?}/certbot"
  /bin/chmod 0755 "${FAKE_BIN:?}/certbot"
fi
exit 0
`)
	writeExecutable(t, filepath.Join(fakeBin, "systemctl"), "#!/bin/sh\nexit 1\n")
	state := filepath.Join(env.DataDir, "fake-cert-state")
	if err := os.MkdirAll(state, 0750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin)
	t.Setenv("FAKE_BIN", fakeBin)
	t.Setenv("FAKE_CERTBOT_TEMPLATE", template)
	t.Setenv("FAKE_HOST_ROOT", env.HostRoot)
	t.Setenv("FAKE_STATE_DIR", state)
	originalCheck := acmeConnectivityCheck
	acmeConnectivityCheck = func(core.Context, string) (string, error) { return "", nil }
	t.Cleanup(func() { acmeConnectivityCheck = originalCheck })

	ctx := core.Context{Context: context.Background(), Env: env}
	result := certificateNew(ctx, core.Request{}, map[string]interface{}{"domain": "service.example.test"})
	assertResult(t, "certificate issue", result, core.StatusSuccess)
	resources := loadManaged(env)
	if !containsString(resources.Packages, "certbot") {
		t.Fatalf("Certbot package was not tracked: %#v", resources)
	}
	options, err := os.ReadFile(filepath.Join(state, "certbot-res-options"))
	if err != nil || string(options) != "attempts:5 timeout:2\n" {
		t.Fatalf("Certbot resolver retries were not applied: %q, %v", options, err)
	}
}

func testEnvironment(t *testing.T) core.Environment {
	t.Helper()
	root := t.TempDir()
	return core.Environment{
		Version:         "test",
		ProtocolVersion: "1",
		BuildID:         "test",
		DataDir:         filepath.Join(root, "var", "lib", "sindri"),
		LogDir:          filepath.Join(root, "var", "log", "sindri"),
		ConfigDir:       filepath.Join(root, "etc", "sindri"),
		HostRoot:        root,
	}
}

func assertResult(t *testing.T, name string, result core.Result, expected core.Status) {
	t.Helper()
	if result.Status != expected {
		t.Fatalf("%s: status=%s exit=%d error=%#v data=%#v", name, result.Status, result.ExitCode, result.Error, result.Data)
	}
}

func writeFile(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}

func writeExecutable(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
}

func installFakeSystemCommands(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	script := `#!/bin/sh
name=${0##*/}
state=${FAKE_STATE_DIR:?}
mkdir -p "$state"
case "$name" in
  apt-get)
    printf '%s\n' "$*" >>"$state/apt-get-calls"
    exit 0
    ;;
  sync|sysctl)
    exit 0
    ;;
  systemctl)
    service=""
    for argument in "$@"; do service=$argument; done
    case "$1" in
      is-active)
        if [ -f "$state/service-$service-active" ]; then exit 0; fi
        exit 1
        ;;
      start|restart) : >"$state/service-$service-active" ;;
      stop) rm -f "$state/service-$service-active" ;;
      reload)
        if [ -f "$state/service-$service-active" ]; then exit 0; fi
        exit 1
        ;;
      enable)
        case " $* " in
          *" --now "*) : >"$state/service-$service-active" ;;
        esac
        ;;
      *) exit 0 ;;
    esac
    ;;
  git|gpg)
    printf '%s version test\n' "$name"
    ;;
	 nano)
	if [ "$1" = "--version" ]; then printf 'GNU nano test\n'; fi
	;;
  curl)
    output=""
    previous=""
    for value in "$@"; do
      if [ "$previous" = "-o" ]; then output=$value; fi
      previous=$value
    done
    if [ -n "$output" ]; then
      mkdir -p "$(dirname "$output")"
      printf 'fake-key\n' >"$output"
    else
      printf 'curl version test\n'
    fi
    ;;
  ufw)
    case "$*" in
      "--force enable") printf active >"$state/ufw" ;;
      "--force disable") printf inactive >"$state/ufw" ;;
      "status"|"status verbose")
        current=$(cat "$state/ufw" 2>/dev/null || printf active)
        printf 'Status: %s\n22/tcp ALLOW Anywhere\n' "$current"
        if [ ! -f "$state/ufw-8080-removed" ]; then printf '8080/tcp ALLOW Anywhere\n'; fi
        ;;
      "show added") printf 'ufw allow 22/tcp\nufw allow 8080/tcp\n' ;;
      *"delete allow 8080/tcp"*) : >"$state/ufw-8080-removed" ;;
    esac
    ;;
  docker)
	if [ "$1" = "cp" ]; then
	  source=$2
	  destination=$3
	  case "$source" in
		node:*)
		  local_source="$state/container-node${source#node:}"
		  mkdir -p "$(dirname "$destination")"
		  /bin/cp "$local_source" "$destination"
		  ;;
		*)
		  case "$destination" in
			node:*)
			  if [ -f "$state/fail-next-geodata-install" ]; then
				case "$source" in
				  */release/*) rm -f "$state/fail-next-geodata-install"; printf 'simulated copy failure\n' >&2; exit 1 ;;
				esac
			  fi
			  local_destination="$state/container-node${destination#node:}"
			  mkdir -p "$(dirname "$local_destination")"
			  /bin/cp "$source" "$local_destination"
			  ;;
			*) exit 1 ;;
		  esac
		  ;;
	  esac
	  exit $?
	fi
	if [ "$1" = "stop" ] && [ "$4" = "node" ]; then
	  rm -f "$state/container-node-running"
	  printf 'node\n'
	  exit 0
	fi
	if [ "$1" = "start" ] && [ "$2" = "node" ]; then
	  : >"$state/container-node-running"
	  printf 'node\n'
	  exit 0
	fi
	if [ "$1" = "exec" ] && [ "$2" = "node" ] && [ "$3" = "test" ] && [ "$4" = "-s" ]; then
	  [ -f "$state/container-node-running" ] || exit 1
	  [ -s "$state/container-node$5" ]
	  exit $?
	fi
    case "$*" in
      "--version") printf 'Docker version test\n' ;;
      "compose version") printf 'Docker Compose version test\n' ;;
      "buildx version") printf 'docker buildx test\n' ;;
      "ps -q") printf 'container-running\n' ;;
      "ps -aq") printf 'container-a\n' ;;
      "images -aq") printf 'image-a\n' ;;
      "volume ls -q") printf 'volume-a\n' ;;
      "network ls --filter type=custom -q") printf 'network-a\n' ;;
	  "inspect --type container --format {{.State.Running}} node")
		if [ -f "$state/container-node-running" ]; then printf 'true\n'; else printf 'false\n'; fi
		;;
      "inspect --format {{.Name}}"*) printf '/container-a\n' ;;
      "logs --timestamps --tail"*) printf '2026-07-27T12:00:00Z fake log\n' ;;
    esac
    ;;
  containerd)
    printf 'containerd test\n'
    ;;
  id)
    [ -f "$state/user-$1" ] || exit 1
    printf 'uid=1001(%s) gid=1001(%s)\n' "$1" "$1"
    ;;
  useradd)
    for username in "$@"; do :; done
    : >"$state/user-$username"
    ;;
  userdel)
    for username in "$@"; do :; done
    rm -f "$state/user-$username"
    ;;
  usermod)
    exit 0
    ;;
  groups)
    printf '%s : %s sudo\n' "$1" "$1"
    ;;
  chpasswd)
    IFS= read -r credentials
    printf '%s\n' "$credentials" >"$state/last-password"
    ;;
  certbot)
	printf '%s\n' "${RES_OPTIONS:-}" >"$state/certbot-res-options"
    exit 0
    ;;
  fail2ban-client)
    printf '%s\n' "$*" >>"$state/fail2ban-client-calls"
    case "$*" in
      "--version") printf 'Fail2Ban vtest\n' ;;
	  "status sshd")
		failures=${FAKE_FAIL2BAN_STATUS_FAILURES:-0}
		attempt=$(cat "$state/fail2ban-status-attempt" 2>/dev/null || printf '0')
		attempt=$((attempt + 1))
		printf '%s' "$attempt" >"$state/fail2ban-status-attempt"
		if [ "$attempt" -le "$failures" ]; then
		  printf 'ERROR Failed to access socket path: /var/run/fail2ban/fail2ban.sock. Is fail2ban running?\n' >&2
		  exit 1
		fi
		printf 'Status for the jail: sshd\n'
		;;
      "-t") printf 'OK: configuration test is successful\n' ;;
    esac
    ;;
  nginx)
    case "$1" in
      -v) printf 'nginx version: nginx/test\n' >&2 ;;
      -t) printf 'nginx configuration test is successful\n' >&2 ;;
	  -T) printf '# configuration file /etc/nginx/conf.d/sindri-cloudflare-real-ip.conf:\nreal_ip_header CF-Connecting-IP;\n' ;;
    esac
    ;;
esac
exit 0
`
	for _, name := range []string{
		"apt-get", "sync", "sysctl", "systemctl", "git", "gpg", "nano", "curl", "ufw",
		"docker", "containerd", "id", "useradd", "userdel", "usermod", "groups",
		"chpasswd", "certbot", "fail2ban-client", "nginx",
	} {
		writeExecutable(t, filepath.Join(directory, name), script)
	}
	return directory
}
