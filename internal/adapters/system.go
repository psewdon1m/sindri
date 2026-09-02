package adapters

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type CommandResult struct {
	Command  []string `json:"command"`
	Stdout   string   `json:"stdout"`
	Stderr   string   `json:"stderr"`
	ExitCode int      `json:"exit_code"`
	TimedOut bool     `json:"timed_out,omitempty"`
}

func Run(ctx context.Context, name string, args ...string) CommandResult {
	return run(ctx, "", nil, 0, name, args...)
}

func RunWithInput(ctx context.Context, input string, name string, args ...string) CommandResult {
	return run(ctx, input, nil, 0, name, args...)
}

func RunWithTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) CommandResult {
	return run(ctx, "", nil, timeout, name, args...)
}

func RunWithEnvTimeout(ctx context.Context, env map[string]string, timeout time.Duration, name string, args ...string) CommandResult {
	return run(ctx, "", env, timeout, name, args...)
}

func RunWithInputTimeout(ctx context.Context, input string, timeout time.Duration, name string, args ...string) CommandResult {
	return run(ctx, input, nil, timeout, name, args...)
}

// RunInteractive attaches a command directly to Sindri's terminal. It is
// intended for full-screen tools such as editors, where captured output and a
// progress renderer would corrupt the terminal session.
func RunInteractive(ctx context.Context, name string, args ...string) CommandResult {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	code := 0
	message := ""
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else {
			code = -1
		}
		message = err.Error()
	}
	return CommandResult{
		Command:  append([]string{name}, args...),
		Stderr:   message,
		ExitCode: code,
		TimedOut: errors.Is(ctx.Err(), context.DeadlineExceeded),
	}
}

func run(parent context.Context, input string, extraEnv map[string]string, timeout time.Duration, name string, args ...string) CommandResult {
	ctx := parent
	cancel := func() {}
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, timeout)
	}
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if len(extraEnv) > 0 {
		cmd.Env = make([]string, 0, len(os.Environ())+len(extraEnv))
		for _, item := range os.Environ() {
			key, _, _ := strings.Cut(item, "=")
			if _, replaced := extraEnv[key]; !replaced {
				cmd.Env = append(cmd.Env, item)
			}
		}
		for key, value := range extraEnv {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	err := cmd.Run()
	code := 0
	timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else {
			code = -1
			stderr.WriteString(err.Error())
		}
	}
	if timedOut {
		code = -1
		if stderr.Len() > 0 {
			stderr.WriteString(": ")
		}
		stderr.WriteString("command timed out")
	}
	return CommandResult{
		Command:  append([]string{name}, args...),
		Stdout:   strings.TrimSpace(stdout.String()),
		Stderr:   strings.TrimSpace(stderr.String()),
		ExitCode: code,
		TimedOut: timedOut,
	}
}

func CommandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

type OSInfo struct {
	GOOS       string `json:"goos"`
	GOARCH     string `json:"goarch"`
	ID         string `json:"id,omitempty"`
	VersionID  string `json:"version_id,omitempty"`
	PrettyName string `json:"pretty_name,omitempty"`
	Supported  bool   `json:"supported"`
}

func DetectOS() OSInfo {
	info := OSInfo{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	if runtime.GOOS != "linux" {
		return info
	}
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return info
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	values := map[string]string{}
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[key] = strings.Trim(value, `"`)
	}
	info.ID = values["ID"]
	info.VersionID = values["VERSION_ID"]
	info.PrettyName = values["PRETTY_NAME"]
	info.Supported = info.ID == "ubuntu" && (info.VersionID == "22.04" || info.VersionID == "24.04" || info.VersionID == "26.04") && runtime.GOARCH == "amd64"
	return info
}

func HostSummary(ctx context.Context) map[string]interface{} {
	timeout, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	data := map[string]interface{}{
		"os":         DetectOS(),
		"go_runtime": runtime.Version(),
	}
	if hostname, err := os.Hostname(); err == nil {
		data["hostname"] = hostname
	}
	if runtime.GOOS == "linux" {
		data["kernel"] = Run(timeout, "uname", "-r").Stdout
		data["uptime"] = Run(timeout, "uptime", "-p").Stdout
		data["load_average"] = readFirstLine("/proc/loadavg")
		data["memory"] = readMemInfo()
		data["disk"] = Run(timeout, "df", "-h", "/", "/var", "/tmp").Stdout
		data["ip_addresses"] = Run(timeout, "hostname", "-I").Stdout
	}
	return data
}

func readFirstLine(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		return scanner.Text()
	}
	return ""
}

func readMemInfo() map[string]string {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil
	}
	defer file.Close()
	keys := map[string]bool{"MemTotal": true, "MemAvailable": true, "SwapTotal": true, "SwapFree": true}
	out := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if ok && keys[key] {
			out[key] = strings.TrimSpace(value)
		}
	}
	return out
}
