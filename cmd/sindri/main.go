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
	"strconv"
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

const (
	outputSeparator = "-----------------------------------------------"
	ansiGood        = "\x1b[38;2;98;255;140m"
	ansiBad         = "\x1b[38;2;248;61;61m"
	ansiNeutral     = "\x1b[38;2;255;255;255m"
	ansiReset       = "\x1b[0m"
)

type outputTone int

const (
	toneNeutral outputTone = iota
	toneGood
	toneBad
)

func main() {
	registry := scenarios.NewRegistry(version, protocolVersion, buildID)
	env := core.NewEnvironment(version, protocolVersion, buildID)
	stdoutColor := terminalColorEnabled(os.Stdout)
	stderrColor := terminalColorEnabled(os.Stderr)

	args, testMode := stripGlobalFlags(os.Args[1:])
	if len(args) == 0 {
		printFramed(os.Stdout, stdoutColor, func(w io.Writer) {
			printHelp(w, registry)
		})
		os.Exit(core.ExitSuccess)
	}

	if args[0] == "machine" {
		code := machine.Handle(context.Background(), os.Stdin, os.Stdout, registry, env)
		os.Exit(code)
	}

	if args[0] == "help" {
		printFramed(os.Stdout, stdoutColor, func(w io.Writer) {
			if len(args) == 1 {
				printHelp(w, registry)
			} else {
				printCommandHelp(w, registry, args[1:])
			}
		})
		os.Exit(core.ExitSuccess)
	}

	match, positional, ok := registry.MatchCLI(args)
	if !ok {
		printFramed(os.Stderr, stderrColor, func(w io.Writer) {
			fmt.Fprintf(w, "%s\n\n", colorize(stderrColor, toneBad, "Invalid command: "+strings.Join(args, " ")))
			printHelp(w, registry)
		})
		os.Exit(core.ExitInvalidCommand)
	}

	inputs := core.PositionalInputs(match.Scenario, positional)
	if err := core.ValidatePositionalCount(match.Scenario, positional); err != nil {
		printFramed(os.Stderr, stderrColor, func(w io.Writer) {
			fmt.Fprintln(w, colorize(stderrColor, toneBad, "Error: "+err.Error()))
			fmt.Fprintf(w, "Usage: %s\n", match.Scenario.Usage)
		})
		os.Exit(core.ExitInvalidCommand)
	}
	interactive := isInteractiveTerminal()
	reader := bufio.NewReader(os.Stdin)
	if interactive {
		if err := promptRequiredInputs(os.Stdout, reader, match.Scenario, inputs); err != nil {
			printFramed(os.Stderr, stderrColor, func(w io.Writer) {
				fmt.Fprintln(w, colorize(stderrColor, toneBad, "Input cancelled: "+err.Error()))
			})
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

	result := executeCLI(context.Background(), registry, env, match.Scenario, req, interactive, stderrColor)
	for attempts := 0; result.Status == core.StatusInputRequired && interactive && attempts < 3; attempts++ {
		if err := promptFieldRequirements(os.Stdout, reader, result.Fields, inputs); err != nil {
			printFramed(os.Stderr, stderrColor, func(w io.Writer) {
				fmt.Fprintln(w, colorize(stderrColor, toneBad, "Input cancelled: "+err.Error()))
			})
			os.Exit(core.ExitCancelledByUser)
		}
		req.Inputs = inputs
		result = executeCLI(context.Background(), registry, env, match.Scenario, req, interactive, stderrColor)
	}
	if result.Status == core.StatusApprovalRequired && interactive {
		approval, approved := promptApproval(os.Stdout, reader, match.Scenario, result)
		if !approved {
			printFramed(os.Stdout, stdoutColor, func(w io.Writer) {
				fmt.Fprintln(w, colorize(stdoutColor, toneBad, "Operation cancelled."))
			})
			os.Exit(core.ExitCancelledByUser)
		}
		req.Approval = approval
		result = executeCLI(context.Background(), registry, env, match.Scenario, req, interactive, stderrColor)
	}
	printFramed(os.Stdout, stdoutColor, func(w io.Writer) {
		printResultWithColor(w, result, stdoutColor)
	})
	os.Exit(result.ExitCode)
}

func terminalColorEnabled(file *os.File) bool {
	if _, disabled := os.LookupEnv("NO_COLOR"); disabled || strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func printFramed(w io.Writer, color bool, render func(io.Writer)) {
	if color {
		fmt.Fprint(w, ansiNeutral)
	}
	fmt.Fprintln(w, outputSeparator)
	render(w)
	fmt.Fprintln(w, outputSeparator)
	if color {
		fmt.Fprint(w, ansiReset)
	}
}

func colorize(enabled bool, tone outputTone, value string) string {
	if !enabled {
		return value
	}
	color := ansiNeutral
	switch tone {
	case toneGood:
		color = ansiGood
	case toneBad:
		color = ansiBad
	}
	return color + value + ansiNeutral
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

func promptFieldRequirements(w io.Writer, reader *bufio.Reader, fields []core.FieldRequirement, inputs map[string]interface{}) error {
	for _, field := range fields {
		if len(field.Values) == 0 {
			prompt := strings.TrimSpace(field.Prompt)
			if prompt == "" {
				prompt = "Enter " + field.Name + ":"
			}
			for {
				fmt.Fprintf(w, "%s ", prompt)
				line, err := reader.ReadString('\n')
				if err != nil {
					return err
				}
				line = strings.TrimSpace(line)
				if line == "" {
					fmt.Fprintln(w, "A value is required.")
					continue
				}
				inputs[field.Name] = line
				break
			}
			continue
		}

		heading := strings.TrimSpace(field.Prompt)
		if heading == "" {
			heading = "Available options:"
		}
		fmt.Fprintln(w, heading)
		for index, value := range field.Values {
			fmt.Fprintf(w, "%d. %s\n", index+1, value)
		}
		for {
			fmt.Fprintf(w, "Choose an option (1-%d): ", len(field.Values))
			line, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			line = strings.TrimSpace(line)
			if number, err := strconv.Atoi(line); err == nil && number >= 1 && number <= len(field.Values) {
				inputs[field.Name] = field.Values[number-1]
				break
			}
			matched := false
			for _, value := range field.Values {
				if line == value {
					inputs[field.Name] = value
					matched = true
					break
				}
			}
			if matched {
				break
			}
			fmt.Fprintln(w, "Choose a listed number or name.")
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

func executeCLI(ctx context.Context, registry *core.Registry, env core.Environment, scenario core.Scenario, req core.Request, interactive bool, color bool) core.Result {
	showProgress := interactive && !scenario.ReadOnly && !scenario.Interactive && !req.Test &&
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
			if color {
				fmt.Fprint(os.Stderr, ansiReset)
			}
			return result
		case <-ticker.C:
			renderProgress(os.Stderr, scenario.ID, frame, time.Since(started), color)
			frame++
		}
	}
}

func renderProgress(w io.Writer, action string, frame int, elapsed time.Duration, color bool) {
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
	prefix := ""
	suffix := ""
	if color {
		prefix = ansiNeutral
		suffix = ansiReset
	}
	fmt.Fprintf(w, "\r\033[2K%s[%s] %s %s%s", prefix, bar, action, elapsed.Truncate(time.Second), suffix)
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
		if len(item.CLIAliases) > 0 {
			fmt.Fprintf(w, "    aliases: %s\n", strings.Join(formatCLIPaths(item.CLIAliases), ", "))
		}
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
		if len(item.CLIAliases) > 0 {
			fmt.Fprintf(w, "Aliases: %s\n", strings.Join(formatCLIPaths(item.CLIAliases), ", "))
		}
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

func formatCLIPaths(paths [][]string) []string {
	formatted := make([]string, 0, len(paths))
	for _, path := range paths {
		if len(path) > 0 {
			formatted = append(formatted, "sindri "+strings.Join(path, " "))
		}
	}
	return formatted
}

func printResult(w io.Writer, result core.Result) {
	printResultWithColor(w, result, false)
}

func printResultWithColor(w io.Writer, result core.Result, color bool) {
	if result.Action == "meta.version" && result.Status == core.StatusSuccess {
		fmt.Fprintln(w, colorize(color, toneGood, fmt.Sprintf("Sindri %s", result.Data["version"])))
		fmt.Fprintf(w, "Protocol version: %s\n", result.Data["protocol_version"])
		fmt.Fprintf(w, "Platform: %s\n", result.Data["platform"])
		fmt.Fprintf(w, "Build: %s\n", result.Data["build"])
		return
	}

	if result.Action == "meta.history" && result.Status == core.StatusSuccess {
		rows, _ := result.Data["entries"].([]core.HistoryEntry)
		fmt.Fprintln(w, "ID                         DATE                  ACTION                    RESULT")
		for _, row := range rows {
			fmt.Fprintf(w, "%-26s %-21s %-25s %s\n", row.ID, row.Time.Format("2006-01-02 15:04:05"), row.Action, colorize(color, toneForStatus(row.Status), string(row.Status)))
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
			for index, value := range field.Values {
				fmt.Fprintf(w, "    %d. %s\n", index+1, value)
			}
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
		fmt.Fprintln(w, colorize(color, toneForStatus(result.Status), result.Message))
	}
	if len(result.Data) > 0 && result.Action != "meta.version" && result.Action != "meta.history" {
		printHumanDataWithColor(w, result.Data, 0, color)
	}
	if len(result.Steps) > 0 {
		for _, step := range result.Steps {
			line := fmt.Sprintf("[%s] %s", step.Status, step.Name)
			fmt.Fprintln(w, colorize(color, toneForStep(step.Status), line))
		}
	}
	if result.Error != nil {
		message := fmt.Sprintf("Error: %s: %s", result.Error.Code, result.Error.Message)
		fmt.Fprintln(w, colorize(color, toneBad, message))
	}
	if result.LogReference != "" {
		fmt.Fprintf(w, "Log reference: %s\n", result.LogReference)
	}
	if result.DurationMS > 0 {
		fmt.Fprintf(w, "Duration: %s\n", time.Duration(result.DurationMS)*time.Millisecond)
	}
}

func printHumanData(w io.Writer, data map[string]interface{}, indent int) {
	printHumanDataWithColor(w, data, indent, false)
}

func printHumanDataWithColor(w io.Writer, data map[string]interface{}, indent int, color bool) {
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
		printHumanValue(w, humanLabel(key), normalized[key], indent, color)
	}
}

func printHumanValue(w io.Writer, label string, value interface{}, indent int, color bool) {
	padding := strings.Repeat(" ", indent)
	switch typed := value.(type) {
	case map[string]interface{}:
		fmt.Fprintf(w, "%s%s:\n", padding, label)
		printHumanDataWithColor(w, typed, indent+2, color)
	case []interface{}:
		if len(typed) == 0 {
			fmt.Fprintf(w, "%s%s: none\n", padding, label)
			return
		}
		fmt.Fprintf(w, "%s%s:\n", padding, label)
		for _, item := range typed {
			if nested, ok := item.(map[string]interface{}); ok {
				fmt.Fprintf(w, "%s-\n", strings.Repeat(" ", indent+2))
				printHumanDataWithColor(w, nested, indent+4, color)
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
				fmt.Fprintf(w, "%s%s\n", strings.Repeat(" ", indent+2), colorize(color, toneForValue(label, line), line))
			}
			return
		}
		fmt.Fprintf(w, "%s%s: %s\n", padding, label, colorize(color, toneForValue(label, typed), typed))
	default:
		valueText := humanScalar(typed)
		fmt.Fprintf(w, "%s%s: %s\n", padding, label, colorize(color, toneForValue(label, typed), valueText))
	}
}

func toneForStatus(status core.Status) outputTone {
	switch status {
	case core.StatusSuccess:
		return toneGood
	case core.StatusFailed, core.StatusPartial:
		return toneBad
	default:
		return toneNeutral
	}
}

func toneForStep(status string) outputTone {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed", "success", "ok", "passed":
		return toneGood
	case "failed", "error", "partial":
		return toneBad
	default:
		return toneNeutral
	}
}

func toneForValue(label string, value interface{}) outputTone {
	label = strings.ToLower(strings.TrimSpace(label))
	if boolean, ok := value.(bool); ok {
		switch label {
		case "active", "available", "enabled", "healthy", "installed", "supported", "valid":
			if boolean {
				return toneGood
			}
			return toneBad
		}
	}
	text := strings.ToLower(strings.TrimSpace(fmt.Sprint(value)))
	switch text {
	case "active", "completed", "enabled", "healthy", "ok", "passed", "ready", "running", "success":
		return toneGood
	case "disabled", "error", "failed", "failure", "inactive", "missing", "partial", "unhealthy":
		return toneBad
	}
	if strings.HasPrefix(text, "status: active") || strings.Contains(text, "active (running)") {
		return toneGood
	}
	if strings.HasPrefix(text, "status: inactive") || strings.Contains(text, "inactive (dead)") || strings.Contains(text, "failed") {
		return toneBad
	}
	return toneNeutral
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
