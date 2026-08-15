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
		{"nginx.install", nil},
		{"nginx.start", nil},
		{"nginx.reload", nil},
		{"nginx.stop", nil},
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
	writeFile(t, hostPath(env, "/etc/os-release"), "ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\n")
	if err := os.MkdirAll(hostPath(env, "/var"), 0755); err != nil {
		t.Fatal(err)
	}
	ctx := core.Context{Context: context.Background(), Env: env}

	assertResult(t, "make ready", makeReady(ctx, core.Request{}, nil), core.StatusSuccess)
	assertResult(t, "reboot", rebootHost(ctx, core.Request{}, nil), core.StatusSuccess)
	assertResult(t, "firewall enable", firewallEnable(ctx, core.Request{}, nil), core.StatusSuccess)
	assertResult(t, "firewall disable", firewallDisable(ctx, core.Request{}, nil), core.StatusSuccess)
	assertResult(t, "firewall close", firewallClose(ctx, core.Request{}, map[string]interface{}{"port": 8080, "protocol": "tcp"}), core.StatusSuccess)
	assertResult(t, "docker install", dockerInstall(ctx, core.Request{}, nil), core.StatusSuccess)
	assertResult(t, "docker logs", dockerLogs(ctx, core.Request{}, map[string]interface{}{"lines": 50}), core.StatusSuccess)
	assertResult(t, "docker clean", dockerClean(ctx, core.Request{}, nil), core.StatusSuccess)
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
  apt-get|sync|sysctl)
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
      start) : >"$state/service-$service-active" ;;
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
    case "$*" in
      "--version") printf 'Docker version test\n' ;;
      "compose version") printf 'Docker Compose version test\n' ;;
      "buildx version") printf 'docker buildx test\n' ;;
      "ps -q") printf 'container-running\n' ;;
      "ps -aq") printf 'container-a\n' ;;
      "images -aq") printf 'image-a\n' ;;
      "volume ls -q") printf 'volume-a\n' ;;
      "network ls --filter type=custom -q") printf 'network-a\n' ;;
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
		"apt-get", "sync", "sysctl", "systemctl", "git", "gpg", "curl", "ufw",
		"docker", "containerd", "id", "useradd", "userdel", "usermod", "groups",
		"chpasswd", "certbot", "nginx",
	} {
		writeExecutable(t, filepath.Join(directory, name), script)
	}
	return directory
}
