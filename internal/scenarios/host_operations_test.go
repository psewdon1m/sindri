package scenarios

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
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
	writeFile(t, hostPath(env, nginxSiteAvailable), "server { listen 80; }\n")
	if err := os.Symlink("../sites-available/exocortex.conf", hostPath(env, nginxSiteEnabled)); err != nil {
		t.Fatal(err)
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

	assertResult(t, "shutdown", shutdownHost(ctx, core.Request{}, nil), core.StatusSuccess)
	assertResult(t, "recovery", recoverHost(ctx, core.Request{}, nil), core.StatusSuccess)

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
	assertResult(t, "docker uninstall", dockerUninstall(ctx, core.Request{}, nil), core.StatusSuccess)
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
        printf 'Status: %s\n22/tcp ALLOW Anywhere\n8080/tcp ALLOW Anywhere\n' "$current"
        ;;
      "show added") printf 'ufw allow 22/tcp\nufw allow 8080/tcp\n' ;;
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
    exit 0
    ;;
  nginx)
    case "$1" in
      -v) printf 'nginx version: nginx/test\n' >&2 ;;
      -t) printf 'nginx configuration test is successful\n' >&2 ;;
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
