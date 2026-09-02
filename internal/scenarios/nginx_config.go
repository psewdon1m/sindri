package scenarios

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"sindri/internal/adapters"
	"sindri/internal/core"
)

const nginxSitesAvailableDirectory = "/etc/nginx/sites-available"

var (
	nginxConfigEditor    = adapters.RunInteractive
	nginxConfigEditSteps = []core.StepSpec{
		{ID: "discover", Name: "Discover available Nginx site configurations"},
		{ID: "select", Name: "Select a configuration"},
		{ID: "edit", Name: "Open the configuration in nano"},
		{ID: "verify", Name: "Verify the edited file"},
	}
)

func nginxConfigEdit(ctx core.Context, req core.Request, inputs map[string]interface{}) core.Result {
	if req.Source == "machine" {
		return nginxConfigEditFailure("NGINX_CONFIG_EDITOR_CLI_ONLY", "the nano editor is available only through the interactive CLI", "discover", core.ExitPrecheckFailed)
	}
	if failure := requireLinuxRoot("NGINX_CONFIG_EDITOR_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	directory := hostPath(ctx.Env, nginxSitesAvailableDirectory)
	configs, err := discoverNginxConfigs(directory)
	if err != nil {
		return nginxConfigEditFailure("NGINX_CONFIG_DISCOVERY_FAILED", err.Error(), "discover", core.ExitPrecheckFailed)
	}
	if len(configs) == 0 {
		return nginxConfigEditFailure("NGINX_CONFIG_NOT_FOUND", "no regular configuration files were found in "+nginxSitesAvailableDirectory, "discover", core.ExitPrecheckFailed)
	}

	selected, _ := inputs["config"].(string)
	selected = strings.TrimSpace(selected)
	if selected == "" && len(configs) == 1 {
		selected = configs[0]
	}
	if selected == "" {
		return core.Result{
			Status:  core.StatusInputRequired,
			Message: "Choose an Nginx site configuration",
			Fields: []core.FieldRequirement{{
				Name: "config", Type: core.InputChoice, Required: true,
				Prompt: "Available Nginx configurations:", Values: configs,
			}},
			Data:     map[string]interface{}{"directory": nginxSitesAvailableDirectory, "configs": configs},
			Steps:    failedSteps(nginxConfigEditSteps, "select"),
			ExitCode: core.ExitInputRequired,
		}
	}
	if !containsString(configs, selected) {
		return nginxConfigEditFailure("NGINX_CONFIG_NOT_FOUND", fmt.Sprintf("%q is not a regular file in %s", selected, nginxSitesAvailableDirectory), "select", core.ExitInvalidCommand)
	}
	if !adapters.CommandExists("nano") {
		return nginxConfigEditFailure("NANO_NOT_FOUND", "nano is not installed; run sindri mir or install nano", "edit", core.ExitPrecheckFailed)
	}

	path := filepath.Join(directory, selected)
	before, err := nginxConfigFileSHA256(path)
	if err != nil {
		return nginxConfigEditFailure("NGINX_CONFIG_READ_FAILED", err.Error(), "edit", core.ExitPrecheckFailed)
	}
	run := nginxConfigEditor(ctx, "nano", path)
	if run.ExitCode != 0 {
		failure := commandFailed("NGINX_CONFIG_EDITOR_FAILED", "nano", run)
		failure.Message = "Nginx configuration editor failed"
		failure.Steps = failedSteps(nginxConfigEditSteps, "edit")
		return failure
	}
	after, err := nginxConfigFileSHA256(path)
	if err != nil {
		return nginxConfigEditFailure("NGINX_CONFIG_VERIFY_FAILED", err.Error(), "verify", core.ExitVerificationFailed)
	}
	logicalPath := nginxSitesAvailableDirectory + "/" + selected
	changed := before != after
	message := "Nginx configuration editor closed"
	if changed {
		message = "Nginx configuration updated"
	}
	return success(message, changed, map[string]interface{}{
		"config": selected, "path": logicalPath, "changed": changed,
	})
}

func discoverNginxConfigs(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	configs := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || strings.HasSuffix(name, "~") || strings.HasSuffix(name, ".swp") || strings.HasSuffix(name, ".tmp") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if entry.Type()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			continue
		}
		configs = append(configs, name)
	}
	sort.Strings(configs)
	return configs, nil
}

func nginxConfigFileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("selected configuration is no longer a regular file")
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func nginxConfigEditFailure(code, message, step string, exitCode int) core.Result {
	return core.Result{
		Status: core.StatusFailed, Message: "Nginx configuration editor failed",
		Error: &core.ErrorInfo{Code: code, Message: message}, Steps: failedSteps(nginxConfigEditSteps, step), ExitCode: exitCode,
	}
}
