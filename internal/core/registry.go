package core

import (
	"fmt"
	"strings"
)

type Registry struct {
	byAction map[string]Scenario
	items    []Scenario
}

type CLIMatch struct {
	Scenario Scenario
	Length   int
}

func NewRegistry() *Registry {
	return &Registry{byAction: map[string]Scenario{}}
}

func (r *Registry) Add(s Scenario) {
	r.byAction[s.ID] = s
	r.items = append(r.items, s)
}

func (r *Registry) FindAction(action string) (Scenario, bool) {
	s, ok := r.byAction[action]
	return s, ok
}

func (r *Registry) All() []Scenario {
	out := make([]Scenario, len(r.items))
	copy(out, r.items)
	return out
}

func (r *Registry) MatchCLI(args []string) (CLIMatch, []string, bool) {
	best := CLIMatch{}
	found := false
	for _, item := range r.items {
		for _, path := range scenarioCLIPaths(item) {
			if len(path) == 0 || len(path) > len(args) {
				continue
			}
			if equalWords(path, args[:len(path)]) && len(path) > best.Length {
				best = CLIMatch{Scenario: item, Length: len(path)}
				found = true
			}
		}
	}
	if !found {
		return CLIMatch{}, nil, false
	}
	return best, args[best.Length:], true
}

func (r *Registry) FindCLIGroup(path []string) []Scenario {
	var out []Scenario
	for _, item := range r.items {
		if scenarioMatchesCLIGroup(item, path) {
			out = append(out, item)
		}
	}
	return out
}

func scenarioCLIPaths(s Scenario) [][]string {
	paths := make([][]string, 0, 1+len(s.CLIAliases))
	paths = append(paths, s.CLIPath)
	paths = append(paths, s.CLIAliases...)
	return paths
}

func scenarioMatchesCLIGroup(s Scenario, group []string) bool {
	for _, path := range scenarioCLIPaths(s) {
		if len(path) >= len(group) && equalWords(group, path[:len(group)]) {
			return true
		}
	}
	return false
}

func equalWords(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.ToLower(a[i]) != strings.ToLower(b[i]) {
			return false
		}
	}
	return true
}

func PositionalInputs(s Scenario, positional []string) map[string]interface{} {
	inputs := map[string]interface{}{}
	for _, spec := range s.Inputs {
		if spec.Position <= 0 || spec.Position > len(positional) {
			continue
		}
		inputs[spec.Name] = positional[spec.Position-1]
	}
	return inputs
}

func ValidatePositionalCount(s Scenario, positional []string) error {
	maximum := 0
	for _, spec := range s.Inputs {
		if spec.Position > maximum {
			maximum = spec.Position
		}
	}
	if len(positional) > maximum {
		return fmt.Errorf("too many arguments: expected at most %d, got %d", maximum, len(positional))
	}
	return nil
}
