package core

import "testing"

func TestValidateInputsReportsMissingRequiredField(t *testing.T) {
	scenario := Scenario{
		ID: "firewall.open",
		Inputs: []InputSpec{
			{Name: "port", Type: InputInteger, Minimum: 1, Maximum: 65535, Required: true},
		},
	}
	_, missing, err := ValidateInputs(scenario, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(missing) != 1 || missing[0].Name != "port" {
		t.Fatalf("expected missing port, got %#v", missing)
	}
}

func TestValidateInputsConvertsInteger(t *testing.T) {
	scenario := Scenario{
		ID: "firewall.open",
		Inputs: []InputSpec{
			{Name: "port", Type: InputInteger, Minimum: 1, Maximum: 65535, Required: true},
		},
	}
	inputs, missing, err := ValidateInputs(scenario, map[string]interface{}{"port": "443"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("unexpected missing fields: %#v", missing)
	}
	if inputs["port"] != 443 {
		t.Fatalf("expected integer port, got %#v", inputs["port"])
	}
}

func TestValidateInputsRejectsUnknownFields(t *testing.T) {
	scenario := Scenario{ID: "firewall.open", Inputs: []InputSpec{{Name: "protocol", Type: InputChoice, Values: []string{"tcp", "udp"}, Default: "tcp"}}}
	_, _, err := ValidateInputs(scenario, map[string]interface{}{"protcol": "udp"})
	if err == nil {
		t.Fatal("expected unknown input to be rejected")
	}
}

func TestValidateInputsRejectsFractionalInteger(t *testing.T) {
	scenario := Scenario{ID: "firewall.open", Inputs: []InputSpec{{Name: "port", Type: InputInteger, Minimum: 1, Maximum: 65535, Required: true}}}
	_, _, err := ValidateInputs(scenario, map[string]interface{}{"port": 80.9})
	if err == nil {
		t.Fatal("expected fractional integer to be rejected")
	}
}
