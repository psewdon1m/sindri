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

func TestDiscoverNginxConfigsReturnsOnlyRegularConfigurationFiles(t *testing.T) {
	directory := t.TempDir()
	writeFile(t, filepath.Join(directory, "zeta"), "server {}\n")
	writeFile(t, filepath.Join(directory, "alpha"), "server {}\n")
	writeFile(t, filepath.Join(directory, ".hidden"), "ignored\n")
	writeFile(t, filepath.Join(directory, "backup~"), "ignored\n")
	writeFile(t, filepath.Join(directory, "swap.swp"), "ignored\n")
	if err := os.Mkdir(filepath.Join(directory, "nested"), 0755); err != nil {
		t.Fatal(err)
	}

	configs, err := discoverNginxConfigs(directory)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(configs, ","); got != "alpha,zeta" {
		t.Fatalf("configs = %q, want alpha,zeta", got)
	}
}

func TestNginxConfigEditRequestsAChoiceForMultipleFiles(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("Nginx editor scenario requires root Linux")
	}
	env := testEnvironment(t)
	directory := hostPath(env, nginxSitesAvailableDirectory)
	writeFile(t, filepath.Join(directory, "second"), "server {}\n")
	writeFile(t, filepath.Join(directory, "first"), "server {}\n")

	result := nginxConfigEdit(core.Context{Context: context.Background(), Env: env}, core.Request{Source: "cli"}, nil)
	if result.Status != core.StatusInputRequired || result.ExitCode != core.ExitInputRequired {
		t.Fatalf("result = %#v", result)
	}
	if len(result.Fields) != 1 || strings.Join(result.Fields[0].Values, ",") != "first,second" {
		t.Fatalf("choices = %#v", result.Fields)
	}
}

func TestNginxConfigEditImmediatelyOpensTheOnlyFile(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("Nginx editor scenario requires root Linux")
	}
	env := testEnvironment(t)
	configPath := hostPath(env, nginxSitesAvailableDirectory+"/default")
	writeFile(t, configPath, "server {}\n")
	fakeBin := t.TempDir()
	writeExecutable(t, filepath.Join(fakeBin, "nano"), "#!/bin/sh\nprintf '\\n# edited by test\\n' >>\"$1\"\n")
	t.Setenv("PATH", fakeBin)

	result := nginxConfigEdit(core.Context{Context: context.Background(), Env: env}, core.Request{Source: "cli"}, nil)
	assertResult(t, "Nginx config editor", result, core.StatusSuccess)
	if !result.Changed || result.Data["config"] != "default" {
		t.Fatalf("result = %#v", result)
	}
	body, err := os.ReadFile(configPath)
	if err != nil || !strings.Contains(string(body), "edited by test") {
		t.Fatalf("edited config = %q, %v", body, err)
	}
}

func TestNginxConfigEditRejectsMachineMode(t *testing.T) {
	result := nginxConfigEdit(core.Context{Context: context.Background()}, core.Request{Source: "machine"}, nil)
	if result.Status != core.StatusFailed || result.Error == nil || result.Error.Code != "NGINX_CONFIG_EDITOR_CLI_ONLY" {
		t.Fatalf("result = %#v", result)
	}
}

func TestNginxConfigEditIsRegisteredAsInteractiveCLICommand(t *testing.T) {
	registry := NewRegistry("test", "1", "test")
	match, positional, ok := registry.MatchCLI([]string{"nginx", "conf", "example"})
	if !ok || match.Scenario.ID != "nginx.config_edit" || !match.Scenario.Interactive {
		t.Fatalf("match = %#v, positional = %#v, ok = %v", match, positional, ok)
	}
	if len(positional) != 1 || positional[0] != "example" {
		t.Fatalf("positional = %#v", positional)
	}
}
