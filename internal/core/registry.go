package core

import "strings"

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
		if len(item.CLIPath) == 0 || len(item.CLIPath) > len(args) {
			continue
		}
		if equalWords(item.CLIPath, args[:len(item.CLIPath)]) && len(item.CLIPath) > best.Length {
			best = CLIMatch{Scenario: item, Length: len(item.CLIPath)}
			found = true
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
		if len(item.CLIPath) < len(path) {
			continue
		}
		if equalWords(path, item.CLIPath[:len(path)]) {
			out = append(out, item)
		}
	}
	return out
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
