package scenarios

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"sindri/internal/adapters"
	"sindri/internal/core"
	"sindri/internal/releases"
)

func NewRegistry(version string, protocolVersion string, buildID string) *core.Registry {
	r := core.NewRegistry()
	addMeta(r, version, protocolVersion, buildID)
	addSystem(r)
	addFirewall(r)
	addDocker(r)
	addNginx(r)
	addUsers(r)
	addCerts(r)
	addReleaseManagement(r)
	return r
}

func addNginx(r *core.Registry) {
	r.Add(hostScenario("nginx.install", []string{"nginx", "install"}, "sindri nginx install", "Install the shared host Nginx", core.RiskChange, []core.StepSpec{
		{ID: "packages", Name: "Install Nginx"},
		{ID: "default_site", Name: "Prepare the distribution default site"},
		{ID: "cloudflare", Name: "Configure trusted Cloudflare proxy addresses"},
		{ID: "renewal_hooks", Name: "Install shared Certbot renewal hooks"},
		{ID: "service", Name: "Enable Nginx without starting it"},
		{ID: "verify", Name: "Verify the Nginx binary"},
	}, nginxInstall))
	r.Add(core.Scenario{
		ID: "nginx.status", APIVersion: 1, CLIPath: []string{"nginx", "status"},
		Usage: "sindri nginx status", Title: "Show shared host Nginx status",
		Risk: core.RiskRead, ReadOnly: true,
		Handler: nginxStatus,
	})
	r.Add(hostScenario("nginx.start", []string{"nginx", "start"}, "sindri nginx start", "Validate and start the shared host Nginx", core.RiskChange, []core.StepSpec{
		{ID: "config_test", Name: "Validate the complete Nginx configuration"},
		{ID: "service", Name: "Enable and start Nginx"},
		{ID: "verify", Name: "Verify the active service"},
	}, nginxStart))
	r.Add(hostScenario("nginx.reload", []string{"nginx", "reload"}, "sindri nginx reload", "Validate and reload the shared host Nginx", core.RiskChange, []core.StepSpec{
		{ID: "config_test", Name: "Validate the complete Nginx configuration"},
		{ID: "reload", Name: "Reload Nginx without dropping active connections"},
		{ID: "verify", Name: "Verify the active service"},
	}, nginxReload))
	r.Add(hostScenario("nginx.stop", []string{"nginx", "stop"}, "sindri nginx stop", "Stop the shared host Nginx", core.RiskDangerous, []core.StepSpec{
		{ID: "service", Name: "Stop Nginx"},
		{ID: "verify", Name: "Verify the stopped service"},
	}, nginxStop))
}

func addReleaseManagement(r *core.Registry) {
	addManagedReleaseScenario(r, "meta.update", []string{"update"}, "sindri update", "Update Sindri to the latest release", "sindri", "update", core.RiskChange)
}

func addManagedReleaseScenario(r *core.Registry, id string, cli []string, usage, title, product, action string, risk core.Risk) {
	steps := []core.StepSpec{
		{ID: "manifest", Name: "Fetch release manifest"},
		{ID: "verify", Name: "Verify installer checksum"},
		{ID: "install", Name: title},
	}
	r.Add(core.Scenario{
		ID: id, APIVersion: 1, CLIPath: cli, Usage: usage, Title: title,
		Description: "Uses the configured HTTPS release manifest and verifies SHA-256 before execution.",
		Risk:        risk, ReadOnly: false, Steps: steps,
		Handler: func(ctx core.Context, req core.Request, inputs map[string]interface{}) core.Result {
			if req.Test {
				return planned(title, steps, map[string]interface{}{"manifest_url": releases.ManifestURL(product)})
			}
			manifest, output, err := releases.NewManager().Execute(ctx, product, action)
			if err != nil {
				details := err.Error()
				if output = strings.TrimSpace(output); output != "" {
					if len(output) > 4096 {
						output = output[len(output)-4096:]
					}
					details += ": " + output
				}
				return core.Result{Status: core.StatusFailed, Message: title + " failed", Error: &core.ErrorInfo{Code: "RELEASE_OPERATION_FAILED", Message: details}, ExitCode: core.ExitVerificationFailed}
			}
			return success(title+" completed", true, map[string]interface{}{"product": product, "version": manifest.Version, "installer_output": output})
		},
	})
}

func addMeta(r *core.Registry, version string, protocolVersion string, buildID string) {
	r.Add(core.Scenario{
		ID:         "meta.help",
		APIVersion: 1,
		Usage:      "sindri help [command]",
		Title:      "Show Sindri help",
		Risk:       core.RiskRead,
		ReadOnly:   true,
		Handler: func(ctx core.Context, req core.Request, inputs map[string]interface{}) core.Result {
			commands := make([]map[string]interface{}, 0)
			for _, scenario := range r.All() {
				if scenario.ID == "meta.help" || len(scenario.CLIPath) == 0 {
					continue
				}
				group, _, _ := strings.Cut(scenario.ID, ".")
				commands = append(commands, map[string]interface{}{
					"action":      scenario.ID,
					"title":       scenario.Title,
					"description": scenario.Description,
					"group":       strings.ToUpper(group[:1]) + group[1:],
					"risk":        scenario.Risk,
					"inputs":      scenario.Inputs,
					"available":   true,
				})
			}
			return success("Help metadata collected", false, map[string]interface{}{
				"commands":         commands,
				"version":          version,
				"protocol_version": protocolVersion,
			})
		},
	})
	r.Add(core.Scenario{
		ID:         "meta.version",
		APIVersion: 1,
		CLIPath:    []string{"version"},
		Usage:      "sindri version",
		Title:      "Show Sindri version",
		Risk:       core.RiskRead,
		ReadOnly:   true,
		Handler: func(ctx core.Context, req core.Request, inputs map[string]interface{}) core.Result {
			return success("Version information", false, map[string]interface{}{
				"version":          version,
				"protocol_version": protocolVersion,
				"platform":         runtime.GOOS + "/" + runtime.GOARCH,
				"build":            buildID,
			})
		},
	})
	r.Add(core.Scenario{
		ID:         "meta.history",
		APIVersion: 1,
		CLIPath:    []string{"history"},
		Usage:      "sindri history",
		Title:      "Show recent operation history",
		Risk:       core.RiskRead,
		ReadOnly:   true,
		Handler: func(ctx core.Context, req core.Request, inputs map[string]interface{}) core.Result {
			entries, _ := core.ReadHistory(ctx.Env, 10)
			return success("Recent operations", false, map[string]interface{}{"entries": entries})
		},
	})
}

func addSystem(r *core.Registry) {
	r.Add(core.Scenario{
		ID:         "system.init",
		APIVersion: 1,
		CLIPath:    []string{"init"},
		Usage:      "sindri init",
		Title:      "Initialize Sindri runtime directories",
		Risk:       core.RiskChange,
		Steps: []core.StepSpec{
			{ID: "directories", Name: "Create runtime directories"},
			{ID: "verify", Name: "Verify runtime directories"},
		},
		Handler: func(ctx core.Context, req core.Request, inputs map[string]interface{}) core.Result {
			if req.Test {
				return planned("Sindri runtime directories would be initialized", []core.StepSpec{{ID: "directories", Name: "Create runtime directories"}, {ID: "verify", Name: "Verify runtime directories"}}, inputs)
			}
			if err := core.EnsureRuntimeDirs(ctx.Env); err != nil {
				return core.Result{Status: core.StatusFailed, Message: "Failed to initialize Sindri directories", Error: &core.ErrorInfo{Code: "INIT_FAILED", Message: err.Error()}, ExitCode: core.ExitGeneralFailure}
			}
			return success("Sindri runtime directories initialized", true, map[string]interface{}{
				"data_dir":   ctx.Env.DataDir,
				"log_dir":    ctx.Env.LogDir,
				"config_dir": ctx.Env.ConfigDir,
			})
		},
	})
	r.Add(core.Scenario{
		ID:         "system.info",
		APIVersion: 1,
		CLIPath:    []string{"info"},
		Usage:      "sindri info",
		Title:      "Show system information",
		Risk:       core.RiskRead,
		ReadOnly:   true,
		Handler: func(ctx core.Context, req core.Request, inputs map[string]interface{}) core.Result {
			data := adapters.HostSummary(ctx)
			return success("System information collected", false, data)
		},
	})
	r.Add(core.Scenario{
		ID:         "system.doctor",
		APIVersion: 1,
		CLIPath:    []string{"doctor"},
		Usage:      "sindri doctor",
		Title:      "Run emergency server diagnostics",
		Risk:       core.RiskRead,
		ReadOnly:   true,
		Handler: func(ctx core.Context, req core.Request, inputs map[string]interface{}) core.Result {
			data := adapters.HostSummary(ctx)
			osInfo := adapters.DetectOS()
			status := "HEALTHY"
			checks := make([]map[string]interface{}, 0, 6)
			addCheck := func(name string, ok bool, message string) {
				checkStatus := "ok"
				if !ok {
					checkStatus = "failed"
					status = "PARTIAL"
				}
				checks = append(checks, map[string]interface{}{"name": name, "status": checkStatus, "message": message})
			}
			addCheck("os", osInfo.Supported, osInfo.PrettyName)
			addCheck("service_manager", adapters.CommandExists("systemctl"), "systemctl must be available for service operations")
			addCheck("package_manager", adapters.CommandExists("apt-get"), "apt-get must be available for package operations")
			free, diskErr := diskFreeBytes(hostPath(ctx.Env, "/"))
			addCheck("disk", diskErr == nil && free >= 512*1024*1024, "at least 512 MB must be available")
			addresses, _ := data["ip_addresses"].(string)
			addCheck("network", strings.TrimSpace(addresses) != "", "at least one IP address must be detected")
			dnsContext, cancelDNS := context.WithTimeout(ctx, 3*time.Second)
			dnsErr := resolveWithRetry(dnsContext, net.DefaultResolver.LookupHost, "acme-v02.api.letsencrypt.org", 1, 0)
			cancelDNS()
			addCheck("dns", dnsErr == nil, "resolve acme-v02.api.letsencrypt.org: "+errorText(dnsErr))
			data["status"] = status
			data["checks"] = checks
			return success("Doctor finished with status "+status, false, data)
		},
	})
	r.Add(hostScenario("system.make_ready", []string{"make_it_ready"}, "sindri make_it_ready", "Prepare base Ubuntu server packages", core.RiskChange, []core.StepSpec{
		{ID: "check_os", Name: "Check supported Ubuntu release"},
		{ID: "apt_update", Name: "Update package index"},
		{ID: "apt_upgrade", Name: "Upgrade packages"},
		{ID: "install_tools", Name: "Install git, curl and gnupg"},
		{ID: "journal_limits", Name: "Configure system journal limits"},
	}, makeReady))
	r.Add(hostScenario("system.reboot", []string{"reboot"}, "sindri reboot", "Reboot the server", core.RiskDangerous, []core.StepSpec{
		{ID: "sync", Name: "Flush filesystem buffers"},
		{ID: "reboot", Name: "Request system reboot"},
	}, rebootHost))
	r.Add(hostScenario("system.shutdown", []string{"shutdown"}, "sindri shutdown", "Enter reversible network lockdown mode", core.RiskDangerous, []core.StepSpec{
		{ID: "bundle", Name: "Create recovery bundle"},
		{ID: "ports", Name: "Preserve SSH access"},
		{ID: "services", Name: "Stop application services"},
		{ID: "firewall", Name: "Reduce exposed network surface"},
	}, shutdownHost))
	r.Add(hostScenario("system.recovery", []string{"recovery"}, "sindri recovery", "Restore previous network and service state", core.RiskChange, []core.StepSpec{
		{ID: "load_bundle", Name: "Load recovery bundle"},
		{ID: "restore_firewall", Name: "Restore firewall rules"},
		{ID: "restore_services", Name: "Restore services and containers"},
	}, recoverHost))
	r.Add(hostScenario("system.exterminatus", []string{"exterminatus"}, "sindri exterminatus", "Perform maximum best-effort decommission cleanup", core.RiskDangerous, []core.StepSpec{
		{ID: "inventory", Name: "Build immutable inventory"},
		{ID: "plan", Name: "Confirm cleanup scope"},
		{ID: "cleanup", Name: "Delete managed resources"},
		{ID: "lockdown", Name: "Enter final lockdown"},
	}, exterminatusHost))
}

func errorText(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

func addFirewall(r *core.Registry) {
	portInput := core.InputSpec{Name: "port", Position: 1, Type: core.InputInteger, Minimum: 1, Maximum: 65535, Required: true, Prompt: "Which port should be opened?"}
	protocolInput := core.InputSpec{Name: "protocol", Position: 2, Type: core.InputChoice, Values: []string{"tcp", "udp"}, Default: "tcp"}
	r.Add(core.Scenario{
		ID:         "firewall.status",
		APIVersion: 1,
		CLIPath:    []string{"firewall", "status"},
		Usage:      "sindri firewall status",
		Title:      "Show firewall status",
		Risk:       core.RiskRead,
		ReadOnly:   true,
		Handler: func(ctx core.Context, req core.Request, inputs map[string]interface{}) core.Result {
			if !adapters.CommandExists("ufw") {
				return success("UFW is not installed", false, map[string]interface{}{"installed": false})
			}
			run := adapters.Run(ctx, "ufw", "status", "verbose")
			return success("Firewall status collected", false, map[string]interface{}{"installed": true, "ufw": run.Stdout, "stderr": run.Stderr})
		},
	})
	r.Add(hostScenario("firewall.enable", []string{"firewall", "on"}, "sindri firewall on", "Enable UFW while preserving SSH access", core.RiskChange, []core.StepSpec{
		{ID: "check_ufw", Name: "Check UFW installation"},
		{ID: "allow_ssh", Name: "Allow SSH ports"},
		{ID: "enable", Name: "Enable UFW"},
		{ID: "verify", Name: "Verify firewall status"},
	}, firewallEnable))
	r.Add(hostScenario("firewall.disable", []string{"firewall", "off"}, "sindri firewall off", "Disable UFW", core.RiskDangerous, []core.StepSpec{
		{ID: "disable", Name: "Disable UFW"},
		{ID: "verify", Name: "Verify firewall status"},
	}, firewallDisable))
	r.Add(core.Scenario{
		ID:          "firewall.open",
		APIVersion:  1,
		CLIPath:     []string{"firewall", "open"},
		Usage:       "sindri firewall open [port] [protocol]",
		Title:       "Open firewall port",
		Description: "Add an allow rule to UFW.",
		Risk:        core.RiskChange,
		Inputs:      []core.InputSpec{portInput, protocolInput},
		Steps: []core.StepSpec{
			{ID: "inspect_rule", Name: "Check existing rule"},
			{ID: "add_rule", Name: "Add firewall rule"},
			{ID: "verify_rule", Name: "Verify firewall rule"},
		},
		Handler: firewallOpen,
	})
	r.Add(hostScenario("firewall.close", []string{"firewall", "close"}, "sindri firewall close [port] [protocol]", "Close firewall port", core.RiskDangerous, []core.StepSpec{
		{ID: "inspect_rule", Name: "Check existing rule"},
		{ID: "delete_rule", Name: "Delete firewall rule"},
		{ID: "verify_rule", Name: "Verify firewall rule"},
	}, firewallClose, portInput, protocolInput))
}

func addDocker(r *core.Registry) {
	r.Add(hostScenario("docker.install", []string{"docker", "install"}, "sindri docker install", "Install Docker Engine from official repository", core.RiskChange, nil, dockerInstall))
	r.Add(hostScenario("docker.uninstall", []string{"docker", "uninstall"}, "sindri docker uninstall", "Uninstall Docker packages and repository", core.RiskDangerous, nil, dockerUninstall))
	r.Add(core.Scenario{
		ID:         "docker.info",
		APIVersion: 1,
		CLIPath:    []string{"docker", "info"},
		Usage:      "sindri docker info",
		Title:      "Show Docker information",
		Risk:       core.RiskRead,
		ReadOnly:   true,
		Handler: func(ctx core.Context, req core.Request, inputs map[string]interface{}) core.Result {
			if !adapters.CommandExists("docker") {
				return success("Docker is not installed", false, map[string]interface{}{"installed": false})
			}
			run := adapters.Run(ctx, "docker", "info")
			return success("Docker information collected", false, map[string]interface{}{"installed": true, "docker": run.Stdout, "stderr": run.Stderr})
		},
	})
	r.Add(hostScenario("docker.logs", []string{"docker", "logs"}, "sindri docker logs [lines]", "Show Docker container logs", core.RiskRead, nil, dockerLogs, core.InputSpec{Name: "lines", Position: 1, Type: core.InputInteger, Minimum: 1, Maximum: 10000, Default: 500}))
	r.Add(hostScenario("docker.clean", []string{"docker", "clean"}, "sindri docker clean", "Remove Docker containers, images, volumes and build cache", core.RiskDangerous, nil, dockerClean))
	r.Add(hostScenario("docker.up", []string{"docker", "up"}, "sindri docker up [path]", "Start Docker Compose project or stopped containers", core.RiskChange, nil, dockerUp, core.InputSpec{Name: "path", Position: 1, Type: core.InputPath, Default: "."}))
	r.Add(hostScenario("docker.down", []string{"docker", "down"}, "sindri docker down [path]", "Stop Docker Compose project or running containers", core.RiskDangerous, nil, dockerDown, core.InputSpec{Name: "path", Position: 1, Type: core.InputPath, Default: "."}))
}

func addUsers(r *core.Registry) {
	username := core.InputSpec{Name: "username", Position: 1, Type: core.InputString, Required: true, Prompt: "Which username should be used?"}
	password := core.InputSpec{Name: "password", Position: 2, Type: core.InputSecret, Required: true, Secret: true, Prompt: "Enter the password securely"}
	r.Add(hostScenario("user.add", []string{"user", "add"}, "sindri user add [username]", "Create a local user", core.RiskChange, nil, userAdd, username, password, core.InputSpec{Name: "sudo", Position: 3, Type: core.InputBoolean, Default: false}))
	r.Add(hostScenario("user.delete", []string{"user", "delete"}, "sindri user delete [username]", "Delete a local user", core.RiskDangerous, nil, userDelete, username, core.InputSpec{Name: "remove_home", Position: 2, Type: core.InputBoolean, Default: false}))
	r.Add(hostScenario("user.password_change", []string{"password_change"}, "sindri password_change [username]", "Change a local user password", core.RiskChange, nil, userPasswordChange, username, password))
}

func addCerts(r *core.Registry) {
	r.Add(core.Scenario{
		ID: "cert.new", APIVersion: 1, CLIPath: []string{"cert", "new"},
		Usage: "sindri cert new [domain]", Title: "Issue a certificate with Certbot standalone",
		Risk: core.RiskChange, ReadOnly: false,
		Inputs:  []core.InputSpec{{Name: "domain", Position: 1, Type: core.InputString, Required: true, Prompt: "Enter a domain name:"}},
		Steps:   certificateIssueSteps(),
		Handler: certificateNew,
	})
	r.Add(core.Scenario{
		ID: "cert.copy", APIVersion: 1, CLIPath: []string{"cert", "cp"},
		Usage: "sindri cert cp [certificate-name] [destination]", Title: "Copy certificate files to a destination",
		Risk: core.RiskChange, ReadOnly: false,
		Inputs: []core.InputSpec{
			{Name: "certificate", Position: 1, Type: core.InputString, Required: true},
			{Name: "destination", Position: 2, Type: core.InputPath, Required: true},
		},
		Steps:   []core.StepSpec{{ID: "precheck", Name: "Validate certificate source"}, {ID: "copy", Name: "Copy certificate files"}, {ID: "verify", Name: "Verify copied files"}},
		Handler: certificateCopy,
	})
	r.Add(hostScenario("cert.delete", []string{"cert", "delete"}, "sindri cert delete [certificate-name]", "Delete Certbot-managed certificates", core.RiskDangerous, nil, certificateDelete, core.InputSpec{Name: "certificate", Position: 1, Type: core.InputString, Required: true}))
}

var certificateName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

func certificateNew(ctx core.Context, req core.Request, inputs map[string]interface{}) core.Result {
	domain := strings.TrimSpace(inputs["domain"].(string))
	steps := certificateIssueSteps()
	if !certificateName.MatchString(domain) || !strings.Contains(domain, ".") {
		return core.Result{Status: core.StatusFailed, Error: &core.ErrorInfo{Code: "DOMAIN_INVALID", Message: "A valid DNS domain is required"}, Steps: failedSteps(steps, "precheck"), ExitCode: core.ExitInvalidCommand}
	}
	if req.Test {
		return planned("Certificate would be issued", steps, inputs)
	}
	if failure := requireUbuntuRoot(ctx, "CERTIFICATE_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	if adapters.CommandExists("nginx") && runSystemctl(ctx, "is-active", "--quiet", "nginx").ExitCode == 0 {
		return core.Result{Status: core.StatusFailed, Error: &core.ErrorInfo{Code: "NGINX_ACTIVE", Message: "Standalone certificate issuance requires port 80; run sindri nginx stop first"}, Steps: failedSteps(steps, "precheck"), ExitCode: core.ExitPrecheckFailed}
	}
	if code, err := acmeConnectivityCheck(ctx, domain); err != nil {
		return core.Result{Status: core.StatusFailed, Error: &core.ErrorInfo{Code: code, Message: err.Error()}, Steps: failedSteps(steps, "connectivity"), ExitCode: core.ExitPrecheckFailed}
	}
	if !adapters.CommandExists("certbot") {
		if run := runApt(ctx, "update"); run.ExitCode != 0 {
			result := commandFailed("CERTBOT_INSTALL_FAILED", "install_certbot", run)
			result.Steps = failedSteps(steps, "install_certbot")
			return result
		}
		if run := runApt(ctx, "install", "-y", "certbot"); run.ExitCode != 0 {
			result := commandFailed("CERTBOT_INSTALL_FAILED", "install_certbot", run)
			result.Steps = failedSteps(steps, "install_certbot")
			return result
		}
		if !adapters.CommandExists("certbot") {
			return core.Result{Status: core.StatusFailed, Error: &core.ErrorInfo{Code: "CERTBOT_INSTALL_VERIFY_FAILED", Message: "Certbot is missing after package installation"}, Steps: failedSteps(steps, "install_certbot"), ExitCode: core.ExitVerificationFailed}
		}
		resources := loadManaged(ctx.Env)
		resources.Packages = mergeUnique(resources.Packages, "certbot")
		if err := saveManaged(ctx.Env, resources); err != nil {
			return managedStateFailure(err)
		}
	}
	run := runCertbot(ctx, "certonly", "--standalone", "--non-interactive", "--agree-tos", "--register-unsafely-without-email", "-d", domain)
	if run.ExitCode != 0 {
		return core.Result{Status: core.StatusFailed, Error: &core.ErrorInfo{Code: "CERTBOT_FAILED", Message: strings.TrimSpace(run.Stderr)}, Steps: failedSteps(steps, "issue"), ExitCode: core.ExitGeneralFailure}
	}
	for _, name := range []string{"fullchain.pem", "privkey.pem"} {
		if _, err := os.Stat(hostPath(ctx.Env, filepath.Join("/etc/letsencrypt/live", domain, name))); err != nil {
			return core.Result{Status: core.StatusFailed, Error: &core.ErrorInfo{Code: "CERTIFICATE_VERIFY_FAILED", Message: err.Error()}, Steps: failedSteps(steps, "verify"), ExitCode: core.ExitVerificationFailed}
		}
	}
	return success("Certificate issued", true, map[string]interface{}{"certificate": domain})
}

func certificateIssueSteps() []core.StepSpec {
	return []core.StepSpec{
		{ID: "precheck", Name: "Validate the domain and port availability"},
		{ID: "connectivity", Name: "Verify DNS and Let's Encrypt connectivity"},
		{ID: "install_certbot", Name: "Install Certbot when required"},
		{ID: "issue", Name: "Issue certificate"},
		{ID: "verify", Name: "Verify certificate files"},
	}
}

func certificateCopy(ctx core.Context, req core.Request, inputs map[string]interface{}) core.Result {
	name := strings.TrimSpace(inputs["certificate"].(string))
	destination := filepath.Clean(inputs["destination"].(string))
	steps := []core.StepSpec{{ID: "precheck", Name: "Validate certificate source"}, {ID: "copy", Name: "Copy certificate files"}, {ID: "verify", Name: "Verify copied files"}}
	if !certificateName.MatchString(name) || !filepath.IsAbs(destination) {
		return core.Result{Status: core.StatusFailed, Error: &core.ErrorInfo{Code: "CERTIFICATE_INPUT_INVALID", Message: "Certificate name and absolute destination are required"}, Steps: failedSteps(steps, "precheck"), ExitCode: core.ExitInvalidCommand}
	}
	if req.Test {
		return planned("Certificate files would be copied", steps, inputs)
	}
	if failure := requireLinuxRoot("CERTIFICATE_COPY_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	source := hostPath(ctx.Env, filepath.Join("/etc/letsencrypt/live", name))
	targetDirectory := hostPath(ctx.Env, destination)
	files := []string{"fullchain.pem", "privkey.pem", "cert.pem", "chain.pem"}
	if err := os.MkdirAll(targetDirectory, 0750); err != nil {
		return core.Result{Status: core.StatusFailed, Error: &core.ErrorInfo{Code: "CERTIFICATE_COPY_FAILED", Message: err.Error()}, Steps: failedSteps(steps, "copy"), ExitCode: core.ExitGeneralFailure}
	}
	managedFiles := make([]string, 0, len(files))
	for _, filename := range files {
		body, err := os.ReadFile(filepath.Join(source, filename))
		if err != nil {
			return core.Result{Status: core.StatusFailed, Error: &core.ErrorInfo{Code: "CERTIFICATE_NOT_FOUND", Message: err.Error()}, Steps: failedSteps(steps, "precheck"), ExitCode: core.ExitPrecheckFailed}
		}
		target := filepath.Join(targetDirectory, filename)
		mode := os.FileMode(0644)
		if filename == "privkey.pem" {
			mode = 0600
		}
		if err := atomicWrite(target, body, mode); err != nil {
			return core.Result{Status: core.StatusFailed, Error: &core.ErrorInfo{Code: "CERTIFICATE_COPY_FAILED", Message: err.Error()}, Steps: failedSteps(steps, "copy"), ExitCode: core.ExitGeneralFailure}
		}
		managedFiles = append(managedFiles, target)
	}
	resources := loadManaged(ctx.Env)
	resources.Files = mergeUnique(resources.Files, managedFiles...)
	if err := saveManaged(ctx.Env, resources); err != nil {
		return managedStateFailure(err)
	}
	return success("Certificate files copied", true, map[string]interface{}{"certificate": name, "destination": destination})
}

func hostScenario(id string, cli []string, usage string, title string, risk core.Risk, steps []core.StepSpec, handler core.Handler, inputs ...core.InputSpec) core.Scenario {
	if steps == nil {
		steps = []core.StepSpec{{ID: "plan", Name: "Build execution plan"}, {ID: "execute", Name: "Execute scenario"}, {ID: "verify", Name: "Verify result"}}
	}
	return core.Scenario{
		ID:         id,
		APIVersion: 1,
		CLIPath:    cli,
		Usage:      usage,
		Title:      title,
		Risk:       risk,
		ReadOnly:   risk == core.RiskRead,
		Inputs:     inputs,
		Steps:      steps,
		Handler: func(ctx core.Context, req core.Request, values map[string]interface{}) core.Result {
			if req.Test {
				safeValues := make(map[string]interface{}, len(values))
				for key, value := range values {
					safeValues[key] = value
				}
				for _, input := range inputs {
					if input.Secret {
						safeValues[input.Name] = "[redacted]"
					}
				}
				return planned(title, steps, safeValues)
			}
			return handler(ctx, req, values)
		},
	}
}

func firewallOpen(ctx core.Context, req core.Request, inputs map[string]interface{}) core.Result {
	port := inputs["port"].(int)
	protocol := inputs["protocol"].(string)
	steps := []core.StepSpec{{ID: "inspect_rule", Name: "Check existing rule"}, {ID: "add_rule", Name: "Add firewall rule"}, {ID: "verify_rule", Name: "Verify firewall rule"}}
	if req.Test {
		return planned(fmt.Sprintf("Port %d/%s would be opened", port, protocol), steps, inputs)
	}
	if failure := requireLinuxRoot("FIREWALL_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	if !adapters.CommandExists("ufw") {
		return core.Result{
			Status:   core.StatusFailed,
			Message:  "UFW is not installed",
			Error:    &core.ErrorInfo{Code: "UFW_NOT_FOUND", Message: "Install or enable UFW before opening ports"},
			Steps:    plannedSteps(steps),
			ExitCode: core.ExitPrecheckFailed,
		}
	}
	rule := fmt.Sprintf("%d/%s", port, protocol)
	before := adapters.Run(ctx, "ufw", "status")
	if before.ExitCode != 0 {
		return commandFailed("UFW_COMMAND_FAILED", "inspect_rule", before)
	}
	if ufwRulePresent(before.Stdout, rule) {
		return success(fmt.Sprintf("Port %d/%s is already open", port, protocol), false, map[string]interface{}{"rule": rule})
	}
	add := adapters.Run(ctx, "ufw", "allow", rule)
	if add.ExitCode != 0 {
		return core.Result{
			Status:   core.StatusFailed,
			Message:  "Failed to add firewall rule",
			Error:    &core.ErrorInfo{Code: "UFW_COMMAND_FAILED", Message: strings.TrimSpace(add.Stderr)},
			Steps:    failedSteps(steps, "add_rule"),
			ExitCode: core.ExitGeneralFailure,
		}
	}
	verify := adapters.Run(ctx, "ufw", "status")
	if verify.ExitCode != 0 || !ufwRulePresent(verify.Stdout, rule) {
		return core.Result{
			Status:   core.StatusFailed,
			Message:  "Firewall rule verification failed",
			Error:    &core.ErrorInfo{Code: "VERIFICATION_FAILED", Message: "Rule was not found in UFW status"},
			Steps:    failedSteps(steps, "verify_rule"),
			ExitCode: core.ExitVerificationFailed,
		}
	}
	return success(fmt.Sprintf("Port %d/%s is open", port, protocol), true, map[string]interface{}{"rule": rule})
}

func success(message string, changed bool, data map[string]interface{}) core.Result {
	return core.Result{Status: core.StatusSuccess, Changed: changed, Message: message, Data: data, ExitCode: core.ExitSuccess}
}

func planned(message string, steps []core.StepSpec, inputs map[string]interface{}) core.Result {
	return core.Result{
		Status:   core.StatusSuccess,
		Changed:  false,
		Message:  message,
		Data:     map[string]interface{}{"test_mode": true, "inputs": inputs},
		Steps:    plannedSteps(steps),
		ExitCode: core.ExitSuccess,
	}
}

func plannedSteps(steps []core.StepSpec) []core.StepResult {
	out := make([]core.StepResult, 0, len(steps))
	for _, step := range steps {
		out = append(out, core.StepResult{ID: step.ID, Name: step.Name, Status: "planned"})
	}
	return out
}

func failedSteps(steps []core.StepSpec, failedID string) []core.StepResult {
	out := make([]core.StepResult, 0, len(steps))
	failureReached := false
	for _, step := range steps {
		status := "skipped"
		if step.ID == failedID {
			status = "failed"
			failureReached = true
		} else if !failureReached {
			status = "completed"
		}
		out = append(out, core.StepResult{ID: step.ID, Name: step.Name, Status: status})
	}
	return out
}
