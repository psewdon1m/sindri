package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
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

func TestDynamicChoicePromptListsOptionsAndAcceptsNumber(t *testing.T) {
	fields := []core.FieldRequirement{{
		Name: "config", Type: core.InputChoice, Required: true,
		Prompt: "Available Nginx configurations:", Values: []string{"default 1", "default 2"},
	}}
	inputs := map[string]interface{}{}
	reader := bufio.NewReader(strings.NewReader("invalid\n2\n"))
	var output bytes.Buffer
	if err := promptFieldRequirements(&output, reader, fields, inputs); err != nil {
		t.Fatal(err)
	}
	if inputs["config"] != "default 2" {
		t.Fatalf("selected config = %#v", inputs["config"])
	}
	for _, expected := range []string{
		"Available Nginx configurations:", "1. default 1", "2. default 2",
		"Choose an option (1-2):", "Choose a listed number or name.",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("prompt is missing %q: %q", expected, output.String())
		}
	}
}

func TestCLIInputRequiredListsDynamicChoices(t *testing.T) {
	result := core.Result{
		Status: core.StatusInputRequired,
		Fields: []core.FieldRequirement{{
			Name: "config", Prompt: "Available Nginx configurations:", Values: []string{"first", "second"},
		}},
	}
	var output bytes.Buffer
	printResult(&output, result)
	for _, expected := range []string{"1. first", "2. second"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("input-required output is missing %q: %q", expected, output.String())
		}
	}
}

func TestCLIHelpShowsAliasesAndAcceptsAliasPaths(t *testing.T) {
	registry := core.NewRegistry()
	registry.Add(core.Scenario{
		ID:         "firewall.status",
		CLIPath:    []string{"firewall", "status"},
		CLIAliases: [][]string{{"fw", "status"}},
		Usage:      "sindri firewall status",
		Title:      "Show firewall status",
		Risk:       core.RiskRead,
	})

	var overview bytes.Buffer
	printHelp(&overview, registry)
	if text := overview.String(); !strings.Contains(text, "aliases: sindri fw status") {
		t.Fatalf("overview is missing the alias: %q", text)
	}

	var command bytes.Buffer
	printCommandHelp(&command, registry, []string{"fw", "status"})
	if text := command.String(); !strings.Contains(text, "Usage: sindri firewall status") || !strings.Contains(text, "Aliases: sindri fw status") {
		t.Fatalf("command help did not resolve the alias: %q", text)
	}
}

func TestFramedOutputUsesExactTerminalColorsAndResets(t *testing.T) {
	var output bytes.Buffer
	printFramed(&output, true, func(w io.Writer) {
		fmt.Fprintln(w, colorize(true, toneGood, "Ready"))
		fmt.Fprintln(w, colorize(true, toneBad, "Failed"))
	})

	text := output.String()
	if !strings.HasPrefix(text, ansiNeutral+outputSeparator+"\n") {
		t.Fatalf("colored frame does not start in neutral white: %q", text)
	}
	if !strings.Contains(text, ansiGood+"Ready"+ansiNeutral) {
		t.Fatalf("successful output does not use #62FF8C: %q", text)
	}
	if !strings.Contains(text, ansiBad+"Failed"+ansiNeutral) {
		t.Fatalf("failed output does not use #F83D3D: %q", text)
	}
	if !strings.HasSuffix(text, outputSeparator+"\n"+ansiReset) {
		t.Fatalf("colored frame does not reset the terminal: %q", text)
	}
}

func TestFramedOutputStaysPlainWithoutTerminalColor(t *testing.T) {
	var output bytes.Buffer
	printFramed(&output, false, func(w io.Writer) {
		fmt.Fprintln(w, colorize(false, toneGood, "Ready"))
	})

	want := outputSeparator + "\nReady\n" + outputSeparator + "\n"
	if got := output.String(); got != want || strings.Contains(got, "\x1b[") {
		t.Fatalf("plain framed output = %q, want %q", got, want)
	}
}

func TestColoredResultHighlightsSemanticStatuses(t *testing.T) {
	result := core.Result{
		Status:  core.StatusSuccess,
		Message: "Everything is ready",
		Data: map[string]interface{}{
			"active": true,
			"status": "HEALTHY",
		},
		Steps: []core.StepResult{
			{Name: "Configured", Status: "completed"},
			{Name: "Skipped after error", Status: "failed"},
		},
		Error: &core.ErrorInfo{Code: "TEST_FAILURE", Message: "example"},
	}

	var output bytes.Buffer
	printResultWithColor(&output, result, true)
	text := output.String()
	for _, good := range []string{"Everything is ready", "true", "HEALTHY", "[completed] Configured"} {
		if !strings.Contains(text, ansiGood+good+ansiNeutral) {
			t.Fatalf("successful value %q is not green: %q", good, text)
		}
	}
	for _, bad := range []string{"[failed] Skipped after error", "Error: TEST_FAILURE: example"} {
		if !strings.Contains(text, ansiBad+bad+ansiNeutral) {
			t.Fatalf("failed value %q is not red: %q", bad, text)
		}
	}
}
