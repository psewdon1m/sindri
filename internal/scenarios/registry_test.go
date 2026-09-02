package scenarios

import (
	"context"
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
