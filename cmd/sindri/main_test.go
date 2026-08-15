package main

import (
	"bytes"
	"strings"
	"testing"

	"sindri/internal/core"
)

func TestCLIResultUsesHumanOutputInsteadOfJSON(t *testing.T) {
	result := core.Result{
		Status:  core.StatusSuccess,
		Action:  "nginx.status",
		Message: "Status collected",
		Data: map[string]interface{}{
			"active":         false,
			"site_available": "/etc/nginx/sites-available/default",
			"ports":          []int{80, 443},
		},
	}
	var output bytes.Buffer
	printResult(&output, result)
	text := output.String()
	if strings.ContainsAny(text, "{}\"") {
		t.Fatalf("CLI output contains JSON syntax: %q", text)
	}
	for _, expected := range []string{"Status collected", "Active: false", "Site available: /etc/nginx/sites-available/default", "- 80"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("CLI output is missing %q: %q", expected, text)
		}
	}
}

func TestCLIInputRequiredIsNotJSON(t *testing.T) {
	result := core.Result{
		Status: core.StatusInputRequired,
		Action: "cert.new",
		Fields: []core.FieldRequirement{{Name: "domain", Prompt: "Enter a domain name:"}},
	}
	var output bytes.Buffer
	printResult(&output, result)
	if text := output.String(); strings.Contains(text, "{") || !strings.Contains(text, "domain") {
		t.Fatalf("unexpected input prompt: %q", text)
	}
}
