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

func TestMatchCLIAliasUsesTheSameScenarioAndPreservesArguments(t *testing.T) {
	r := NewRegistry()
	r.Add(Scenario{
		ID:         "firewall.open",
		CLIPath:    []string{"firewall", "open"},
		CLIAliases: [][]string{{"fw", "open"}},
	})

	match, rest, ok := r.MatchCLI([]string{"FW", "OPEN", "443", "tcp"})
	if !ok {
		t.Fatal("expected alias to match")
	}
	if match.Scenario.ID != "firewall.open" {
		t.Fatalf("expected firewall.open, got %s", match.Scenario.ID)
	}
	if len(rest) != 2 || rest[0] != "443" || rest[1] != "tcp" {
		t.Fatalf("unexpected positional arguments: %#v", rest)
	}
}

func TestFindCLIGroupIncludesAliasesWithoutDuplicates(t *testing.T) {
	r := NewRegistry()
	r.Add(Scenario{
		ID:         "firewall.status",
		CLIPath:    []string{"firewall", "status"},
		CLIAliases: [][]string{{"fw", "status"}, {"FW", "STATUS"}},
	})

	matches := r.FindCLIGroup([]string{"fw"})
	if len(matches) != 1 || matches[0].ID != "firewall.status" {
		t.Fatalf("unexpected alias group matches: %#v", matches)
	}
}

func TestValidatePositionalCountRejectsExtraArguments(t *testing.T) {
	scenario := Scenario{ID: "meta.version"}
	if err := ValidatePositionalCount(scenario, []string{"unexpected"}); err == nil {
		t.Fatal("expected extra argument to be rejected")
	}
}
