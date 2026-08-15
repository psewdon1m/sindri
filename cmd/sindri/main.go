package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"sort"
	"strings"
	"time"

	"sindri/internal/core"
	"sindri/internal/machine"
	"sindri/internal/scenarios"
)

var (
	version         = "1.2.0"
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
	if err := core.ValidatePositionalCount(match.Scenario, positional); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\nUsage: %s\n", err, match.Scenario.Usage)
		os.Exit(core.ExitInvalidCommand)
	}
	interactive := isInteractiveTerminal()
	reader := bufio.NewReader(os.Stdin)
	if interactive {
		if err := promptRequiredInputs(os.Stdout, reader, match.Scenario, inputs); err != nil {
			fmt.Fprintf(os.Stderr, "Input cancelled: %s\n", err)
			os.Exit(core.ExitCancelledByUser)
		}
	}
	req := core.Request{
		RequestID: core.NewRequestID(),
		Action:    match.Scenario.ID,
		Test:      testMode,
		Inputs:    inputs,
		Source:    "cli",
	}

	result := executeCLI(context.Background(), registry, env, match.Scenario, req, interactive)
	if result.Status == core.StatusApprovalRequired && interactive {
		approval, approved := promptApproval(os.Stdout, reader, match.Scenario, result)
		if !approved {
			fmt.Fprintln(os.Stdout, "Operation cancelled.")
			os.Exit(core.ExitCancelledByUser)
		}
		req.Approval = approval
		result = executeCLI(context.Background(), registry, env, match.Scenario, req, interactive)
	}
	printResult(os.Stdout, result)
	os.Exit(result.ExitCode)
}

func isInteractiveTerminal() bool {
	stdin, stdinErr := os.Stdin.Stat()
	stderr, stderrErr := os.Stderr.Stat()
	return stdinErr == nil && stderrErr == nil &&
		stdin.Mode()&os.ModeCharDevice != 0 &&
		stderr.Mode()&os.ModeCharDevice != 0
}

func promptRequiredInputs(w io.Writer, reader *bufio.Reader, scenario core.Scenario, inputs map[string]interface{}) error {
	for _, spec := range scenario.Inputs {
		value, present := inputs[spec.Name]
		if present && value != nil && fmt.Sprint(value) != "" {
			continue
		}
		if !spec.Required {
			continue
		}
		for {
			prompt := strings.TrimSpace(spec.Prompt)
			if prompt == "" {
				prompt = "Enter " + spec.Name
			}
			if spec.Type == core.InputChoice && len(spec.Values) > 0 {
				prompt += " (" + strings.Join(spec.Values, "/") + ")"
			}
			fmt.Fprintf(w, "%s ", prompt)
			line, err := readCLIValue(reader, spec.Secret)
			if err != nil {
				return err
			}
			line = strings.TrimSpace(line)
			if line == "" {
				fmt.Fprintln(w, "A value is required.")
				continue
			}
			inputs[spec.Name] = line
			break
		}
	}
	return nil
}

func readCLIValue(reader *bufio.Reader, secret bool) (string, error) {
	if !secret {
		return reader.ReadString('\n')
	}
	hidden := false
	disable := osexec.Command("stty", "-echo")
	disable.Stdin = os.Stdin
	if disable.Run() == nil {
		hidden = true
		defer func() {
			restore := osexec.Command("stty", "echo")
			restore.Stdin = os.Stdin
			_ = restore.Run()
			fmt.Fprintln(os.Stdout)
		}()
	}
	value, err := reader.ReadString('\n')
	if !hidden {
		fmt.Fprintln(os.Stdout, "Warning: terminal echo could not be disabled.")
	}
	return value, err
}

func promptApproval(w io.Writer, reader *bufio.Reader, scenario core.Scenario, result core.Result) (*core.Approval, bool) {
	fmt.Fprintf(w, "\nDangerous operation: %s\n", scenario.Title)
	if len(result.Plan) > 0 {
		fmt.Fprintln(w, "Plan:")
		for _, step := range result.Plan {
			fmt.Fprintf(w, "  - %s\n", step.Name)
		}
	}
	approval := &core.Approval{ApprovalID: result.ApprovalID, PlanHash: result.PlanHash}
	if scenario.ID == "system.exterminatus" {
		hostname, _ := os.Hostname()
		fmt.Fprint(w, "Type EXTERMINATUS to continue: ")
		phrase, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(phrase) != "EXTERMINATUS" {
			return nil, false
		}
		fmt.Fprintf(w, "Type the server hostname (%s): ", hostname)
		confirmedHostname, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(confirmedHostname) != hostname {
			return nil, false
		}
		approval.ConfirmationPhrase = "EXTERMINATUS"
		approval.HostnameConfirmation = hostname
		return approval, true
	}
	fmt.Fprint(w, "Continue? Type yes: ")
	answer, err := reader.ReadString('\n')
	return approval, err == nil && strings.EqualFold(strings.TrimSpace(answer), "yes")
}

func executeCLI(ctx context.Context, registry *core.Registry, env core.Environment, scenario core.Scenario, req core.Request, interactive bool) core.Result {
	showProgress := interactive && !scenario.ReadOnly && !req.Test &&
		(scenario.Risk != core.RiskDangerous || req.Approval != nil)
	if !showProgress {
		return core.Execute(ctx, registry, env, req)
	}
	resultChannel := make(chan core.Result, 1)
	go func() {
		resultChannel <- core.Execute(ctx, registry, env, req)
	}()
	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()
	started := time.Now()
	frame := 0
	for {
		select {
		case result := <-resultChannel:
			fmt.Fprint(os.Stderr, "\r\033[2K")
			return result
		case <-ticker.C:
			renderProgress(os.Stderr, scenario.ID, frame, time.Since(started))
			frame++
		}
	}
}

func renderProgress(w io.Writer, action string, frame int, elapsed time.Duration) {
	const width = 24
	const blockWidth = 5
	travel := width - blockWidth
	cycle := travel * 2
	position := frame % cycle
	if position > travel {
		position = cycle - position
	}
	bar := strings.Repeat(" ", position) + strings.Repeat("=", blockWidth)
	bar += strings.Repeat(" ", width-len(bar))
	fmt.Fprintf(w, "\r\033[2K[%s] %s %s", bar, action, elapsed.Truncate(time.Second))
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

	if result.Status == core.StatusInputRequired {
		fmt.Fprintln(w, "Input required:")
		for _, field := range result.Fields {
			message := field.Prompt
			if message == "" {
				message = "Provide " + field.Name
			}
			fmt.Fprintf(w, "  %s — %s\n", field.Name, message)
		}
		return
	}

	if result.Status == core.StatusApprovalRequired {
		fmt.Fprintln(w, "This dangerous operation requires interactive confirmation.")
		if len(result.Plan) > 0 {
			fmt.Fprintln(w, "Plan:")
			for _, step := range result.Plan {
				fmt.Fprintf(w, "  - %s\n", step.Name)
			}
		}
		return
	}

	if result.Message != "" {
		fmt.Fprintln(w, result.Message)
	}
	if len(result.Data) > 0 && result.Action != "meta.version" && result.Action != "meta.history" {
		printHumanData(w, result.Data, 0)
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

func printHumanData(w io.Writer, data map[string]interface{}, indent int) {
	body, err := json.Marshal(data)
	if err != nil {
		return
	}
	var normalized map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&normalized); err != nil {
		return
	}
	keys := make([]string, 0, len(normalized))
	for key := range normalized {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		printHumanValue(w, humanLabel(key), normalized[key], indent)
	}
}

func printHumanValue(w io.Writer, label string, value interface{}, indent int) {
	padding := strings.Repeat(" ", indent)
	switch typed := value.(type) {
	case map[string]interface{}:
		fmt.Fprintf(w, "%s%s:\n", padding, label)
		printHumanData(w, typed, indent+2)
	case []interface{}:
		if len(typed) == 0 {
			fmt.Fprintf(w, "%s%s: none\n", padding, label)
			return
		}
		fmt.Fprintf(w, "%s%s:\n", padding, label)
		for _, item := range typed {
			if nested, ok := item.(map[string]interface{}); ok {
				fmt.Fprintf(w, "%s-\n", strings.Repeat(" ", indent+2))
				printHumanData(w, nested, indent+4)
				continue
			}
			fmt.Fprintf(w, "%s- %s\n", strings.Repeat(" ", indent+2), humanScalar(item))
		}
	case string:
		if typed == "" {
			fmt.Fprintf(w, "%s%s: none\n", padding, label)
			return
		}
		if strings.Contains(typed, "\n") {
			fmt.Fprintf(w, "%s%s:\n", padding, label)
			for _, line := range strings.Split(typed, "\n") {
				fmt.Fprintf(w, "%s%s\n", strings.Repeat(" ", indent+2), line)
			}
			return
		}
		fmt.Fprintf(w, "%s%s: %s\n", padding, label, typed)
	default:
		fmt.Fprintf(w, "%s%s: %s\n", padding, label, humanScalar(typed))
	}
}

func humanLabel(value string) string {
	value = strings.ReplaceAll(value, "_", " ")
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

func humanScalar(value interface{}) string {
	if value == nil {
		return "none"
	}
	return fmt.Sprint(value)
}
