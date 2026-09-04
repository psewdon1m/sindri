package scenarios

import (
	"context"
	"strings"
	"testing"

	"sindri/internal/core"
)

func TestProductionRegistryCLIAliases(t *testing.T) {
	registry := NewRegistry("test", "1", "test")
	cases := []struct {
		name       string
		args       []string
		action     string
		positional []string
	}{
		{name: "make ready", args: []string{"mir"}, action: "system.make_ready"},
		{name: "firewall status", args: []string{"fw", "status"}, action: "firewall.status"},
		{name: "firewall on", args: []string{"fw", "on"}, action: "firewall.enable"},
		{name: "firewall off", args: []string{"fw", "off"}, action: "firewall.disable"},
		{name: "firewall open", args: []string{"fw", "open", "443", "tcp"}, action: "firewall.open", positional: []string{"443", "tcp"}},
		{name: "firewall close", args: []string{"fw", "close", "53", "udp"}, action: "firewall.close", positional: []string{"53", "udp"}},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			match, positional, ok := registry.MatchCLI(test.args)
			if !ok {
				t.Fatalf("alias did not match: %v", test.args)
			}
			if match.Scenario.ID != test.action {
				t.Fatalf("action = %q, want %q", match.Scenario.ID, test.action)
			}
			if !equalStringSlices(positional, test.positional) {
				t.Fatalf("positional arguments = %#v, want %#v", positional, test.positional)
			}
		})
	}
}

func TestGeoGetRequestsContainerAndAcceptsItPositionally(t *testing.T) {
	registry := NewRegistry("test", "1", "test")
	match, positional, ok := registry.MatchCLI([]string{"geo", "get", "custom-node"})
	if !ok || match.Scenario.ID != "geo.get" {
		t.Fatalf("geo get did not match: %#v, %v", match, ok)
	}
	inputs := core.PositionalInputs(match.Scenario, positional)
	if inputs["container"] != "custom-node" {
		t.Fatalf("container input = %#v", inputs["container"])
	}

	missing := core.Execute(context.Background(), registry, testEnvironment(t), core.Request{
		Action: "geo.get", Test: true, Source: "test",
	})
	if missing.Status != core.StatusInputRequired || len(missing.Fields) != 1 {
		t.Fatalf("missing container result = %#v", missing)
	}
	if missing.Fields[0].Name != "container" || missing.Fields[0].Prompt != "Enter the Docker container name:" {
		t.Fatalf("unexpected container prompt: %#v", missing.Fields[0])
	}
}

func TestCertStatusMatchesCLIAndIsReadOnly(t *testing.T) {
	registry := NewRegistry("test", "1", "test")
	match, positional, ok := registry.MatchCLI([]string{"cert", "status"})
	if !ok || match.Scenario.ID != "cert.status" {
		t.Fatalf("cert status did not match: %#v, %v", match, ok)
	}
	if !match.Scenario.ReadOnly || match.Scenario.Risk != core.RiskRead {
		t.Fatalf("cert status is not read-only: %#v", match.Scenario)
	}
	if len(positional) != 0 {
		t.Fatalf("cert status positional arguments = %#v", positional)
	}
}

func TestProxyCommandsMatchExpectedCLIPaths(t *testing.T) {
	registry := NewRegistry("test", "1", "test")
	cases := map[string]string{
		"ip status": "ip.status", "xray install": "xray.install", "xray status": "xray.status",
		"xray config": "xray.config", "xray on": "xray.on", "xray off": "xray.off",
		"xray uninstall": "xray.uninstall", "nginx uninstall": "nginx.uninstall",
	}
	for cli, action := range cases {
		match, _, ok := registry.MatchCLI(strings.Fields(cli))
		if !ok || match.Scenario.ID != action {
			t.Fatalf("%s matched %#v, want %s", cli, match, action)
		}
	}
}

func equalStringSlices(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
