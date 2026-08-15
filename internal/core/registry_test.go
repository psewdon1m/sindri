package core

import "testing"

func TestMatchCLIChoosesLongestPath(t *testing.T) {
	r := NewRegistry()
	r.Add(Scenario{ID: "firewall.group", CLIPath: []string{"firewall"}})
	r.Add(Scenario{ID: "firewall.open", CLIPath: []string{"firewall", "open"}})
	match, rest, ok := r.MatchCLI([]string{"firewall", "open", "80"})
	if !ok {
		t.Fatal("expected match")
	}
	if match.Scenario.ID != "firewall.open" {
		t.Fatalf("expected firewall.open, got %s", match.Scenario.ID)
	}
	if len(rest) != 1 || rest[0] != "80" {
		t.Fatalf("unexpected rest: %#v", rest)
	}
}

func TestValidatePositionalCountRejectsExtraArguments(t *testing.T) {
	scenario := Scenario{ID: "meta.version"}
	if err := ValidatePositionalCount(scenario, []string{"unexpected"}); err == nil {
		t.Fatal("expected extra argument to be rejected")
	}
}
