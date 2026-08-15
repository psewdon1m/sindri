package machine

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"sindri/internal/core"
)

func TestHandleRejectsTrailingJSON(t *testing.T) {
	registry := core.NewRegistry()
	registry.Add(core.Scenario{
		ID: "meta.version", Risk: core.RiskRead, ReadOnly: true,
		Handler: func(_ core.Context, _ core.Request, _ map[string]interface{}) core.Result {
			return core.Result{Status: core.StatusSuccess}
		},
	})
	root := t.TempDir()
	env := core.Environment{
		ProtocolVersion: "1",
		DataDir:         filepath.Join(root, "lib"),
		LogDir:          filepath.Join(root, "log"),
		ConfigDir:       filepath.Join(root, "etc"),
		HostRoot:        root,
	}
	input := strings.NewReader(`{"protocol_version":"1","action":"meta.version"}{"action":"meta.version"}`)
	var output bytes.Buffer
	if code := Handle(context.Background(), input, &output, registry, env); code != core.ExitInvalidCommand {
		t.Fatalf("expected invalid command exit, got %d: %s", code, output.String())
	}
	if !strings.Contains(output.String(), "Only one JSON request is allowed") {
		t.Fatalf("unexpected response: %s", output.String())
	}
}
