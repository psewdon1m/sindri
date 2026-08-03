package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"sindri/internal/core"
	"sindri/internal/machine"
	"sindri/internal/scenarios"
)

var (
	version         = "1.0.0-dev"
	protocolVersion = "1"
	buildID         = "source"
)

func main() {
	registry := scenarios.NewRegistry(version, protocolVersion, buildID)
	env := core.NewEnvironment(version, protocolVersion, buildID)

	args, testMode := stripGlobalFlags(os.Args[1:])
	if len(args) == 0 {
		printHelp(os.Stdout, registry)
		os.Exit(core.ExitSuccess)
	}

	if args[0] == "machine" {
		code := machine.Handle(context.Background(), os.Stdin, os.Stdout, registry, env)
		os.Exit(code)
	}

	if args[0] == "help" {
		if len(args) == 1 {
			printHelp(os.Stdout, registry)
		} else {
			printCommandHelp(os.Stdout, registry, args[1:])
		}
		os.Exit(core.ExitSuccess)
	}

	match, positional, ok := registry.MatchCLI(args)
	if !ok {
		fmt.Fprintf(os.Stderr, "Invalid command: %s\n\n", strings.Join(args, " "))
		printHelp(os.Stderr, registry)
		os.Exit(core.ExitInvalidCommand)
	}

	inputs := core.PositionalInputs(match.Scenario, positional)
	req := core.Request{
		RequestID: core.NewRequestID(),
		Action:    match.Scenario.ID,
		Test:      testMode,
		Inputs:    inputs,
		Source:    "cli",
	}

	result := core.Execute(context.Background(), registry, env, req)
	printResult(os.Stdout, result)
	os.Exit(result.ExitCode)
}

func stripGlobalFlags(args []string) ([]string, bool) {
	clean := make([]string, 0, len(args))
	test := false
	for _, arg := range args {
		if arg == "--test" {
			test = true
			continue
		}
		clean = append(clean, arg)
	}
	return clean, test
}

func printHelp(w io.Writer, registry *core.Registry) {
	fmt.Fprintln(w, "Sindri - system CLI assistant for Ubuntu Server")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  sindri <command> [arguments] [--test]")
	fmt.Fprintln(w, "  sindri machine")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	items := registry.All()
	sort.Slice(items, func(i, j int) bool {
		return strings.Join(items[i].CLIPath, " ") < strings.Join(items[j].CLIPath, " ")
	})
	for _, item := range items {
		if len(item.CLIPath) == 0 {
			continue
		}
		fmt.Fprintf(w, "  %-28s %-10s %s\n", strings.Join(item.CLIPath, " "), item.Risk, item.Title)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Machine mode accepts a single JSON request on stdin and returns JSON on stdout.")
}

func printCommandHelp(w io.Writer, registry *core.Registry, path []string) {
	items := registry.FindCLIGroup(path)
	if len(items) == 0 {
		fmt.Fprintf(w, "No help found for: %s\n", strings.Join(path, " "))
		return
	}
	for _, item := range items {
		fmt.Fprintf(w, "%s\n", item.Title)
		fmt.Fprintf(w, "Usage: %s\n", item.Usage)
		fmt.Fprintf(w, "Risk: %s\n", item.Risk)
		if item.Description != "" {
			fmt.Fprintf(w, "%s\n", item.Description)
		}
		if len(item.Inputs) > 0 {
			fmt.Fprintln(w, "Inputs:")
			for _, input := range item.Inputs {
				required := "optional"
				if input.Required {
					required = "required"
				}
				fmt.Fprintf(w, "  %-12s %-8s %s\n", input.Name, input.Type, required)
			}
		}
		fmt.Fprintln(w)
	}
}

func printResult(w io.Writer, result core.Result) {
	if result.Action == "meta.version" && result.Status == core.StatusSuccess {
		fmt.Fprintf(w, "Sindri %s\n", result.Data["version"])
		fmt.Fprintf(w, "Protocol version: %s\n", result.Data["protocol_version"])
		fmt.Fprintf(w, "Platform: %s\n", result.Data["platform"])
		fmt.Fprintf(w, "Build: %s\n", result.Data["build"])
		return
	}

	if result.Action == "meta.history" && result.Status == core.StatusSuccess {
		rows, _ := result.Data["entries"].([]core.HistoryEntry)
		fmt.Fprintln(w, "ID                         DATE                  ACTION                    RESULT")
		for _, row := range rows {
			fmt.Fprintf(w, "%-26s %-21s %-25s %s\n", row.ID, row.Time.Format("2006-01-02 15:04:05"), row.Action, row.Status)
		}
		return
	}

	if result.Status == core.StatusInputRequired || result.Status == core.StatusApprovalRequired {
		b, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(w, string(b))
		return
	}

	if result.Message != "" {
		fmt.Fprintln(w, result.Message)
	}
	if len(result.Data) > 0 && result.Action != "meta.version" && result.Action != "meta.history" {
		b, err := json.MarshalIndent(result.Data, "", "  ")
		if err == nil {
			fmt.Fprintln(w, string(b))
		}
	}
	if len(result.Steps) > 0 {
		for _, step := range result.Steps {
			fmt.Fprintf(w, "[%s] %s\n", step.Status, step.Name)
		}
	}
	if result.Error != nil {
		fmt.Fprintf(w, "Error: %s: %s\n", result.Error.Code, result.Error.Message)
	}
	if result.LogReference != "" {
		fmt.Fprintf(w, "Log reference: %s\n", result.LogReference)
	}
	if result.DurationMS > 0 {
		fmt.Fprintf(w, "Duration: %s\n", time.Duration(result.DurationMS)*time.Millisecond)
	}
}
