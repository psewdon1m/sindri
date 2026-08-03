package core

import (
	"encoding/json"
	"fmt"
	"strconv"
)

func ValidateInputs(s Scenario, raw map[string]interface{}) (map[string]interface{}, []FieldRequirement, error) {
	if raw == nil {
		raw = map[string]interface{}{}
	}
	normalized := map[string]interface{}{}
	var missing []FieldRequirement
	for _, spec := range s.Inputs {
		value, ok := raw[spec.Name]
		if !ok || value == nil || value == "" {
			if spec.Default != nil {
				normalized[spec.Name] = spec.Default
				continue
			}
			if spec.Required {
				missing = append(missing, fieldRequirement(spec))
			}
			continue
		}

		converted, err := convertInput(spec, value)
		if err != nil {
			return nil, nil, err
		}
		normalized[spec.Name] = converted
	}
	return normalized, missing, nil
}

func fieldRequirement(spec InputSpec) FieldRequirement {
	return FieldRequirement{
		Name:     spec.Name,
		Type:     spec.Type,
		Minimum:  spec.Minimum,
		Maximum:  spec.Maximum,
		Required: spec.Required,
		Prompt:   spec.Prompt,
		Values:   spec.Values,
		Default:  spec.Default,
	}
}

func convertInput(spec InputSpec, value interface{}) (interface{}, error) {
	switch spec.Type {
	case InputInteger:
		n, err := toInt(value)
		if err != nil {
			return nil, fmt.Errorf("%s must be an integer", spec.Name)
		}
		if spec.Minimum != 0 && n < spec.Minimum {
			return nil, fmt.Errorf("%s must be at least %d", spec.Name, spec.Minimum)
		}
		if spec.Maximum != 0 && n > spec.Maximum {
			return nil, fmt.Errorf("%s must be at most %d", spec.Name, spec.Maximum)
		}
		return n, nil
	case InputChoice:
		text := fmt.Sprint(value)
		for _, allowed := range spec.Values {
			if text == allowed {
				return text, nil
			}
		}
		return nil, fmt.Errorf("%s must be one of %v", spec.Name, spec.Values)
	case InputBoolean:
		switch v := value.(type) {
		case bool:
			return v, nil
		case string:
			parsed, err := strconv.ParseBool(v)
			if err != nil {
				return nil, fmt.Errorf("%s must be boolean", spec.Name)
			}
			return parsed, nil
		default:
			return nil, fmt.Errorf("%s must be boolean", spec.Name)
		}
	default:
		return fmt.Sprint(value), nil
	}
}

func toInt(value interface{}) (int, error) {
	switch v := value.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	case json.Number:
		return strconv.Atoi(string(v))
	case string:
		return strconv.Atoi(v)
	default:
		return 0, fmt.Errorf("not an integer")
	}
}
