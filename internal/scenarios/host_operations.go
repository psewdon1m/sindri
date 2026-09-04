package scenarios

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sindri/internal/adapters"
	"sindri/internal/core"
)

type managedResources struct {
	Users    []string `json:"users"`
	Packages []string `json:"packages"`
	Services []string `json:"services"`
	Files    []string `json:"files"`
	Projects []string `json:"projects"`
}

type recoveryBundle struct {
	Schema            string   `json:"schema"`
	CreatedAt         string   `json:"created_at"`
	Hostname          string   `json:"hostname"`
	UFWInstalled      bool     `json:"ufw_installed"`
	UFWActive         bool     `json:"ufw_active"`
	UFWRules          []string `json:"ufw_rules"`
	SSHPorts          []int    `json:"ssh_ports"`
	RunningContainers []string `json:"running_containers"`
	RunningServices   []string `json:"running_services"`
	IPv4ICMPIgnore    string   `json:"ipv4_icmp_ignore"`
	IPv6ICMPIgnore    string   `json:"ipv6_icmp_ignore"`
}

type recoveryPointer struct {
	BundlePath string `json:"bundle_path"`
	Checksum   string `json:"checksum"`
	Status     string `json:"status"`
}

var localUsername = regexpUsername()

const (
	aptCommandTimeout     = 15 * time.Minute
	serviceCommandTimeout = 45 * time.Second
	certbotCommandTimeout = 15 * time.Minute
	fail2banJailPath      = "/etc/fail2ban/jail.d/90-sindri-sshd.local"
	fail2banReadyAttempts = 20
	fail2banReadyInterval = 500 * time.Millisecond
)

var aptEnvironment = map[string]string{
	"DEBIAN_FRONTEND":          "noninteractive",
	"APT_LISTCHANGES_FRONTEND": "none",
	"NEEDRESTART_MODE":         "a",
	"RES_OPTIONS":              "attempts:5 timeout:2",
}

var resolverRetryEnvironment = map[string]string{"RES_OPTIONS": "attempts:5 timeout:2"}

func runApt(ctx core.Context, args ...string) adapters.CommandResult {
	args = append([]string{"-o", "DPkg::Lock::Timeout=120"}, args...)
	return adapters.RunWithEnvTimeout(ctx, aptEnvironment, aptCommandTimeout, "apt-get", args...)
}

func runSystemctl(ctx core.Context, args ...string) adapters.CommandResult {
	return adapters.RunWithTimeout(ctx, serviceCommandTimeout, "systemctl", args...)
}

func runCertbot(ctx core.Context, args ...string) adapters.CommandResult {
	return adapters.RunWithEnvTimeout(ctx, resolverRetryEnvironment, certbotCommandTimeout, "certbot", args...)
}

func runFail2ban(ctx core.Context, args ...string) adapters.CommandResult {
	return adapters.RunWithTimeout(ctx, serviceCommandTimeout, "fail2ban-client", args...)
}

func regexpUsername() func(string) bool {
	return func(value string) bool {
		if len(value) < 1 || len(value) > 32 {
			return false
		}
		for index, ch := range value {
			if (ch >= 'a' && ch <= 'z') || (index > 0 && ch >= '0' && ch <= '9') || (index > 0 && (ch == '-' || ch == '_')) {
				continue
			}
			return false
		}
		return true
	}
}

func makeReady(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	if failure := requireUbuntuRoot(ctx, "MAKE_READY_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	if free, err := diskFreeBytes(hostPath(ctx.Env, "/var")); err != nil || free < 512*1024*1024 {
		return failed("MAKE_READY_PRECHECK_FAILED", "At least 512 MB must be free under /var", core.ExitPrecheckFailed)
	}
	commands := []struct {
		step string
		args []string
	}{
		{"apt_update", []string{"update"}},
		{"apt_upgrade", []string{"-y", "upgrade"}},
		{"install_tools", []string{"install", "-y", "git", "curl", "gnupg", "nano"}},
		{"install_fail2ban", []string{"install", "-y", "fail2ban"}},
		{"autoremove", []string{"autoremove", "-y"}},
		{"autoclean", []string{"autoclean"}},
	}
	for _, command := range commands {
		run := runApt(ctx, command.args...)
		if run.ExitCode != 0 {
			return commandFailed("MAKE_READY_FAILED", command.step, run)
		}
	}
	journalPath := hostPath(ctx.Env, "/etc/systemd/journald.conf.d/90-sindri-limits.conf")
	if err := atomicWrite(journalPath, []byte("[Journal]\nSystemMaxUse=256M\nRuntimeMaxUse=64M\n"), 0644); err != nil {
		return failed("JOURNAL_CONFIGURATION_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	if run := runSystemctl(ctx, "restart", "systemd-journald"); run.ExitCode != 0 {
		return commandFailed("JOURNAL_RESTART_FAILED", "journal_limits", run)
	}
	fail2banPath := hostPath(ctx.Env, fail2banJailPath)
	ports := sshPorts(ctx.Env)
	if err := atomicWrite(fail2banPath, fail2banSSHDJail(ports), 0644); err != nil {
		return failed("FAIL2BAN_CONFIGURATION_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	if run := runFail2ban(ctx, "-t"); run.ExitCode != 0 {
		return commandFailed("FAIL2BAN_CONFIGURATION_INVALID", "validate_fail2ban", run)
	}
	if run := runSystemctl(ctx, "enable", "fail2ban"); run.ExitCode != 0 {
		return commandFailed("FAIL2BAN_SERVICE_FAILED", "enable_fail2ban", run)
	}
	if run := runSystemctl(ctx, "restart", "fail2ban"); run.ExitCode != 0 {
		return commandFailed("FAIL2BAN_SERVICE_FAILED", "restart_fail2ban", run)
	}
	fail2banService, fail2banStatus, ready := waitForFail2banSSHDJail(ctx, fail2banReadyAttempts, fail2banReadyInterval)
	if !ready {
		if fail2banService.ExitCode != 0 {
			return commandFailed("FAIL2BAN_VERIFICATION_FAILED", "verify_fail2ban_service", fail2banService)
		}
		return commandFailed("FAIL2BAN_VERIFICATION_FAILED", "verify_sshd_jail", fail2banStatus)
	}
	tools := map[string]string{}
	for label, command := range map[string]string{"git": "git", "curl": "curl", "gpg": "gpg", "nano": "nano"} {
		run := adapters.Run(ctx, command, "--version")
		if run.ExitCode != 0 {
			return commandFailed("TOOL_VERIFICATION_FAILED", label, run)
		}
		tools[label] = firstLine(run.Stdout)
	}
	if run := runFail2ban(ctx, "--version"); run.ExitCode != 0 {
		return commandFailed("TOOL_VERIFICATION_FAILED", "fail2ban", run)
	} else {
		tools["fail2ban"] = firstLine(run.Stdout)
	}
	resources := loadManaged(ctx.Env)
	resources.Packages = mergeUnique(resources.Packages, "git", "curl", "gnupg", "nano", "fail2ban")
	resources.Services = mergeUnique(resources.Services, "fail2ban.service")
	resources.Files = mergeUnique(resources.Files, journalPath, fail2banPath)
	if err := saveManaged(ctx.Env, resources); err != nil {
		return managedStateFailure(err)
	}
	return success("Base Ubuntu server packages and SSH protection are ready", true, map[string]interface{}{
		"tools": tools,
		"fail2ban": map[string]interface{}{
			"jail":   "sshd",
			"ports":  ports,
			"status": firstLine(fail2banStatus.Stdout),
		},
	})
}

func waitForFail2banSSHDJail(ctx core.Context, attempts int, interval time.Duration) (adapters.CommandResult, adapters.CommandResult, bool) {
	if attempts < 1 {
		attempts = 1
	}
	var service adapters.CommandResult
	var jail adapters.CommandResult
	for attempt := 1; attempt <= attempts; attempt++ {
		service = runSystemctl(ctx, "is-active", "--quiet", "fail2ban")
		if service.ExitCode == 0 {
			jail = runFail2ban(ctx, "status", "sshd")
			if jail.ExitCode == 0 {
				return service, jail, true
			}
		}
		if ctx.Log != nil {
			ctx.Log.Write("fail2ban_readiness attempt=%d/%d service_exit=%d jail_exit=%d", attempt, attempts, service.ExitCode, jail.ExitCode)
		}
		if service.TimedOut || jail.TimedOut || attempt == attempts {
			break
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return service, jail, false
		case <-timer.C:
		}
	}
	return service, jail, false
}

func fail2banSSHDJail(ports []int) []byte {
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, strconv.Itoa(port))
	}
	return []byte(fmt.Sprintf(`[sshd]
enabled = true
backend = systemd
port = %s
findtime = 10m
maxretry = 5
bantime = 1h
`, strings.Join(values, ",")))
}

func rebootHost(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("REBOOT_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	if run := adapters.Run(ctx, "sync"); run.ExitCode != 0 {
		return commandFailed("SYNC_FAILED", "sync", run)
	}
	run := runSystemctl(ctx, "reboot", "--no-block")
	if run.ExitCode != 0 {
		return commandFailed("REBOOT_REQUEST_FAILED", "reboot", run)
	}
	return success("System reboot requested", true, nil)
}

func firewallEnable(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("FIREWALL_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	if !adapters.CommandExists("ufw") {
		if run := runApt(ctx, "update"); run.ExitCode != 0 {
			return commandFailed("UFW_INSTALL_FAILED", "apt_update", run)
		}
		if run := runApt(ctx, "install", "-y", "ufw"); run.ExitCode != 0 {
			return commandFailed("UFW_INSTALL_FAILED", "install", run)
		}
	}
	ports := sshPorts(ctx.Env)
	if len(ports) == 0 {
		return failed("SSH_PORT_UNKNOWN", "No SSH port could be identified", core.ExitPrecheckFailed)
	}
	for _, port := range ports {
		if run := adapters.Run(ctx, "ufw", "allow", fmt.Sprintf("%d/tcp", port)); run.ExitCode != 0 {
			return commandFailed("UFW_COMMAND_FAILED", "allow_ssh", run)
		}
	}
	if run := adapters.Run(ctx, "ufw", "--force", "enable"); run.ExitCode != 0 {
		return commandFailed("UFW_COMMAND_FAILED", "enable", run)
	}
	status := adapters.Run(ctx, "ufw", "status")
	if status.ExitCode != 0 || !strings.Contains(strings.ToLower(status.Stdout), "status: active") {
		return failed("FIREWALL_VERIFY_FAILED", "UFW did not report active status", core.ExitVerificationFailed)
	}
	return success("Firewall enabled with SSH access preserved", true, map[string]interface{}{"ssh_ports": ports})
}

func firewallDisable(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("FIREWALL_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	if !adapters.CommandExists("ufw") {
		return success("UFW is not installed", false, map[string]interface{}{"installed": false})
	}
	if run := adapters.Run(ctx, "ufw", "--force", "disable"); run.ExitCode != 0 {
		return commandFailed("UFW_COMMAND_FAILED", "disable", run)
	}
	status := adapters.Run(ctx, "ufw", "status")
	if status.ExitCode != 0 || !strings.Contains(strings.ToLower(status.Stdout), "status: inactive") {
		return failed("FIREWALL_VERIFY_FAILED", "UFW did not report inactive status", core.ExitVerificationFailed)
	}
	return success("Firewall disabled", true, nil)
}

func firewallClose(ctx core.Context, _ core.Request, inputs map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("FIREWALL_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	if !adapters.CommandExists("ufw") {
		return failed("UFW_NOT_FOUND", "UFW is not installed", core.ExitPrecheckFailed)
	}
	port := inputs["port"].(int)
	protocol := inputs["protocol"].(string)
	rule := fmt.Sprintf("%d/%s", port, protocol)
	before := adapters.Run(ctx, "ufw", "status")
	if before.ExitCode != 0 {
		return commandFailed("FIREWALL_VERIFY_FAILED", "inspect_rule", before)
	}
	if !ufwRulePresent(before.Stdout, rule) {
		return success("Firewall rule is already absent", false, map[string]interface{}{"rule": rule, "ssh_port": containsInt(sshPorts(ctx.Env), port)})
	}
	run := adapters.Run(ctx, "ufw", "--force", "delete", "allow", rule)
	if run.ExitCode != 0 {
		return commandFailed("UFW_COMMAND_FAILED", "delete_rule", run)
	}
	status := adapters.Run(ctx, "ufw", "status")
	if status.ExitCode != 0 {
		return commandFailed("FIREWALL_VERIFY_FAILED", "verify_rule", status)
	}
	if ufwRulePresent(status.Stdout, rule) {
		return failed("FIREWALL_VERIFY_FAILED", "Firewall rule is still present after deletion", core.ExitVerificationFailed)
	}
	return success("Firewall rule removed", true, map[string]interface{}{
		"rule":     rule,
		"ssh_port": containsInt(sshPorts(ctx.Env), port),
	})
}

func ufwRulePresent(status, rule string) bool {
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == rule {
			return true
		}
	}
	return false
}

func dockerInstall(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	if failure := requireUbuntuRoot(ctx, "DOCKER_INSTALL_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	conflicts := []string{"docker.io", "docker-compose", "docker-compose-v2", "docker-doc", "podman-docker", "containerd", "runc"}
	removeArgs := append([]string{"remove", "-y"}, conflicts...)
	_ = runApt(ctx, removeArgs...)
	if run := runApt(ctx, "update"); run.ExitCode != 0 {
		return commandFailed("DOCKER_INSTALL_FAILED", "apt_update", run)
	}
	if run := runApt(ctx, "install", "-y", "ca-certificates", "curl", "gnupg"); run.ExitCode != 0 {
		return commandFailed("DOCKER_INSTALL_FAILED", "prerequisites", run)
	}
	keyring := hostPath(ctx.Env, "/etc/apt/keyrings/docker.asc")
	if err := os.MkdirAll(filepath.Dir(keyring), 0755); err != nil {
		return failed("DOCKER_REPOSITORY_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	if run := adapters.Run(ctx, "curl", "-fsSL", "https://download.docker.com/linux/ubuntu/gpg", "-o", keyring); run.ExitCode != 0 {
		return commandFailed("DOCKER_REPOSITORY_FAILED", "keyring", run)
	}
	_ = os.Chmod(keyring, 0644)
	codename := osReleaseValue(hostPath(ctx.Env, "/etc/os-release"), "VERSION_CODENAME")
	if codename == "" {
		return failed("DOCKER_REPOSITORY_FAILED", "Ubuntu VERSION_CODENAME is missing", core.ExitPrecheckFailed)
	}
	arch := "amd64"
	if runtime.GOARCH == "arm64" {
		arch = "arm64"
	}
	repository := fmt.Sprintf("deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n", arch, codename)
	repoPath := hostPath(ctx.Env, "/etc/apt/sources.list.d/docker.list")
	if err := atomicWrite(repoPath, []byte(repository), 0644); err != nil {
		return failed("DOCKER_REPOSITORY_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	if run := runApt(ctx, "update"); run.ExitCode != 0 {
		return commandFailed("DOCKER_INSTALL_FAILED", "apt_update_docker", run)
	}
	packages := []string{"docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"}
	if run := runApt(ctx, append([]string{"install", "-y"}, packages...)...); run.ExitCode != 0 {
		return commandFailed("DOCKER_INSTALL_FAILED", "packages", run)
	}
	daemonPath := hostPath(ctx.Env, "/etc/docker/daemon.json")
	daemon := map[string]interface{}{}
	if body, err := os.ReadFile(daemonPath); err == nil && len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &daemon); err != nil {
			return failed("DOCKER_CONFIGURATION_INVALID", err.Error(), core.ExitPrecheckFailed)
		}
		_ = os.WriteFile(daemonPath+".sindri.bak", body, 0600)
	}
	daemon["log-driver"] = "local"
	daemon["log-opts"] = map[string]interface{}{"max-size": "10m", "max-file": "5"}
	body, _ := json.MarshalIndent(daemon, "", "  ")
	if err := atomicWrite(daemonPath, append(body, '\n'), 0644); err != nil {
		return failed("DOCKER_CONFIGURATION_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	if run := runSystemctl(ctx, "enable", "--now", "docker"); run.ExitCode != 0 {
		return commandFailed("DOCKER_SERVICE_FAILED", "service", run)
	}
	checks := map[string]interface{}{}
	for name, args := range map[string][]string{
		"engine":     {"docker", "--version"},
		"compose":    {"docker", "compose", "version"},
		"buildx":     {"docker", "buildx", "version"},
		"containerd": {"containerd", "--version"},
	} {
		run := adapters.Run(ctx, args[0], args[1:]...)
		if run.ExitCode != 0 {
			return commandFailed("DOCKER_VERIFY_FAILED", name, run)
		}
		checks[name] = firstLine(run.Stdout)
	}
	if run := adapters.Run(ctx, "docker", "run", "--rm", "hello-world"); run.ExitCode != 0 {
		return commandFailed("DOCKER_VERIFY_FAILED", "hello_world", run)
	}
	resources := loadManaged(ctx.Env)
	resources.Packages = mergeUnique(resources.Packages, packages...)
	resources.Services = mergeUnique(resources.Services, "docker.service", "containerd.service")
	resources.Files = mergeUnique(resources.Files, keyring, repoPath, daemonPath)
	if err := saveManaged(ctx.Env, resources); err != nil {
		return managedStateFailure(err)
	}
	return success("Docker Engine installed and verified", true, checks)
}

func dockerUninstall(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("DOCKER_UNINSTALL_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	packages := []string{"docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin", "docker-ce-rootless-extras"}
	run := runApt(ctx, append([]string{"purge", "-y"}, packages...)...)
	if run.ExitCode != 0 {
		return commandFailed("DOCKER_UNINSTALL_FAILED", "packages", run)
	}
	for _, path := range []string{
		hostPath(ctx.Env, "/etc/apt/sources.list.d/docker.list"),
		hostPath(ctx.Env, "/etc/apt/keyrings/docker.asc"),
	} {
		_ = os.Remove(path)
	}
	_ = runApt(ctx, "update")
	if adapters.CommandExists("docker") {
		return failed("DOCKER_UNINSTALL_VERIFY_FAILED", "docker remains available in PATH", core.ExitVerificationFailed)
	}
	resources := loadManaged(ctx.Env)
	for _, item := range packages {
		resources.Packages = removeString(resources.Packages, item)
	}
	resources.Services = removeString(removeString(resources.Services, "docker.service"), "containerd.service")
	for _, path := range []string{
		hostPath(ctx.Env, "/etc/apt/sources.list.d/docker.list"),
		hostPath(ctx.Env, "/etc/apt/keyrings/docker.asc"),
		hostPath(ctx.Env, "/etc/docker/daemon.json"),
	} {
		resources.Files = removeString(resources.Files, path)
	}
	if err := saveManaged(ctx.Env, resources); err != nil {
		return managedStateFailure(err)
	}
	return success("Docker packages and repository removed; data directories were preserved", true, nil)
}

const (
	nginxSiteAvailable = "/etc/nginx/sites-available/default"
	nginxSiteEnabled   = "/etc/nginx/sites-enabled/default"
	nginxCloudflareIP  = "/etc/nginx/conf.d/sindri-cloudflare-real-ip.conf"
	nginxCertbotPre    = "/etc/letsencrypt/renewal-hooks/pre/sindri-nginx"
	nginxCertbotPost   = "/etc/letsencrypt/renewal-hooks/post/sindri-nginx"
)

func nginxInstall(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	if failure := requireUbuntuRoot(ctx, "NGINX_INSTALL_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	wasActive := false
	nginxWasInstalled := adapters.CommandExists("nginx")
	if nginxWasInstalled {
		wasActive = runSystemctl(ctx, "is-active", "--quiet", "nginx").ExitCode == 0
	}
	if !nginxWasInstalled {
		if run := runApt(ctx, "update"); run.ExitCode != 0 {
			return commandFailed("NGINX_INSTALL_FAILED", "packages", run)
		}
		if run := runApt(ctx, "install", "-y", "nginx"); run.ExitCode != 0 {
			return commandFailed("NGINX_INSTALL_FAILED", "packages", run)
		}
	}
	if !adapters.CommandExists("nginx") {
		return failed("NGINX_INSTALL_VERIFY_FAILED", "Nginx is missing after package installation", core.ExitVerificationFailed)
	}

	for _, directory := range []string{
		hostPath(ctx.Env, "/etc/nginx/sites-available"),
		hostPath(ctx.Env, "/etc/nginx/sites-enabled"),
		hostPath(ctx.Env, "/etc/nginx/conf.d"),
		filepath.Dir(hostPath(ctx.Env, nginxCertbotPre)),
		filepath.Dir(hostPath(ctx.Env, nginxCertbotPost)),
	} {
		if err := os.MkdirAll(directory, 0755); err != nil {
			return failed("NGINX_DIRECTORY_CREATE_FAILED", err.Error(), core.ExitGeneralFailure)
		}
	}
	availablePath := hostPath(ctx.Env, nginxSiteAvailable)
	if _, err := os.Stat(availablePath); os.IsNotExist(err) {
		defaultConfig := "server {\n    listen 80 default_server;\n    listen [::]:80 default_server;\n    server_name _;\n    root /var/www/html;\n    index index.html;\n}\n"
		if err := atomicWrite(availablePath, []byte(defaultConfig), 0644); err != nil {
			return failed("NGINX_DEFAULT_SITE_CREATE_FAILED", err.Error(), core.ExitGeneralFailure)
		}
	} else if err != nil {
		return failed("NGINX_DEFAULT_SITE_INSPECT_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	enabledPath := hostPath(ctx.Env, nginxSiteEnabled)
	if info, err := os.Lstat(enabledPath); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return failed("NGINX_DEFAULT_SITE_UNMANAGED", nginxSiteEnabled+" must be a symlink", core.ExitPrecheckFailed)
		}
	} else if os.IsNotExist(err) {
		if err := os.Symlink("../sites-available/default", enabledPath); err != nil {
			return failed("NGINX_DEFAULT_SITE_ENABLE_FAILED", err.Error(), core.ExitGeneralFailure)
		}
	} else {
		return failed("NGINX_DEFAULT_SITE_INSPECT_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	resolvedSite, err := filepath.EvalSymlinks(enabledPath)
	if err != nil || filepath.Clean(resolvedSite) != filepath.Clean(availablePath) {
		return failed("NGINX_DEFAULT_SITE_UNMANAGED", nginxSiteEnabled+" must resolve to "+nginxSiteAvailable, core.ExitPrecheckFailed)
	}

	cloudflareRanges, cloudflareSource, cloudflareWarning := cloudflareRangeLoader(ctx)
	if cloudflareWarning != nil {
		ctx.Log.Write("cloudflare_ranges source=embedded warning=%s", cloudflareWarning)
	}
	cloudflarePath := hostPath(ctx.Env, nginxCloudflareIP)
	previousCloudflare, previousCloudflareErr := os.ReadFile(cloudflarePath)
	cloudflareExisted := previousCloudflareErr == nil
	if previousCloudflareErr != nil && !os.IsNotExist(previousCloudflareErr) {
		return failed("NGINX_CLOUDFLARE_CONFIG_FAILED", previousCloudflareErr.Error(), core.ExitGeneralFailure)
	}
	if err := atomicWrite(cloudflarePath, cloudflareRealIPConfig(cloudflareRanges, cloudflareSource), 0644); err != nil {
		return failed("NGINX_CLOUDFLARE_CONFIG_FAILED", err.Error(), core.ExitGeneralFailure)
	}

	preHook := `#!/bin/sh
set -eu
marker=/run/sindri-nginx-certbot-was-running
if systemctl is-active --quiet nginx; then
  : >"$marker"
  timeout 45s systemctl stop nginx
fi
`
	postHook := `#!/bin/sh
set -eu
marker=/run/sindri-nginx-certbot-was-running
if [ -f "$marker" ]; then
  rm -f "$marker"
  timeout 45s systemctl start nginx
fi
`
	prePath := hostPath(ctx.Env, nginxCertbotPre)
	postPath := hostPath(ctx.Env, nginxCertbotPost)
	if err := atomicWrite(prePath, []byte(preHook), 0755); err != nil {
		return failed("NGINX_CERTBOT_HOOK_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	if err := atomicWrite(postPath, []byte(postHook), 0755); err != nil {
		return failed("NGINX_CERTBOT_HOOK_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	if configTest := adapters.RunWithTimeout(ctx, serviceCommandTimeout, "nginx", "-t"); configTest.ExitCode != 0 {
		if cloudflareExisted {
			_ = atomicWrite(cloudflarePath, previousCloudflare, 0644)
		} else {
			_ = os.Remove(cloudflarePath)
		}
		return commandFailed("NGINX_CONFIG_INVALID", "cloudflare_real_ip", configTest)
	}
	configDump := adapters.RunWithTimeout(ctx, serviceCommandTimeout, "nginx", "-T")
	configText := configDump.Stdout + "\n" + configDump.Stderr
	if configDump.ExitCode != 0 || !strings.Contains(configText, nginxCloudflareIP) || !strings.Contains(configText, "real_ip_header CF-Connecting-IP;") {
		if cloudflareExisted {
			_ = atomicWrite(cloudflarePath, previousCloudflare, 0644)
		} else {
			_ = os.Remove(cloudflarePath)
		}
		if configDump.ExitCode != 0 {
			return commandFailed("NGINX_CONFIG_INVALID", "cloudflare_real_ip_include", configDump)
		}
		return failed("NGINX_CLOUDFLARE_CONFIG_NOT_INCLUDED", nginxCloudflareIP+" is not included by nginx.conf", core.ExitVerificationFailed)
	}

	// Ubuntu can start Nginx automatically after a fresh apt installation. Keep
	// that new service stopped until the operator has issued certificates and
	// created the shared site. Apply refreshed proxy ranges to an existing
	// service with a zero-downtime reload.
	if wasActive {
		if run := runSystemctl(ctx, "reload", "nginx"); run.ExitCode != 0 {
			return commandFailed("NGINX_RELOAD_FAILED", "cloudflare_real_ip", run)
		}
	} else {
		if run := runSystemctl(ctx, "stop", "nginx"); run.ExitCode != 0 {
			return commandFailed("NGINX_SERVICE_FAILED", "service", run)
		}
	}
	if run := runSystemctl(ctx, "enable", "nginx"); run.ExitCode != 0 {
		return commandFailed("NGINX_SERVICE_FAILED", "service", run)
	}
	version := adapters.Run(ctx, "nginx", "-v")
	if version.ExitCode != 0 {
		return commandFailed("NGINX_INSTALL_VERIFY_FAILED", "verify", version)
	}
	versionText := firstLine(version.Stderr)
	if versionText == "" {
		versionText = firstLine(version.Stdout)
	}

	resources := loadManaged(ctx.Env)
	resources.Packages = mergeUnique(resources.Packages, "nginx")
	resources.Services = mergeUnique(resources.Services, "nginx.service")
	resources.Files = mergeUnique(resources.Files, cloudflarePath, prePath, postPath)
	if err := saveManaged(ctx.Env, resources); err != nil {
		return managedStateFailure(err)
	}
	message := "Shared host Nginx installed with the default site and left stopped"
	if wasActive {
		message = "Shared host Nginx updated and reloaded without interrupting the active service"
	}
	next := "Run sindri nginx conf, issue certificates if needed, then run sindri nginx start"
	if wasActive {
		next = "Cloudflare proxy ranges are active; use sindri nginx conf and then sindri nginx reload for future site changes"
	}
	return success(message, true, map[string]interface{}{
		"version":           versionText,
		"active":            wasActive,
		"site_available":    nginxSiteAvailable,
		"site_enabled_path": nginxSiteEnabled,
		"cloudflare_real_ip": map[string]interface{}{
			"config": nginxCloudflareIP, "ranges": len(cloudflareRanges), "source": cloudflareSource,
		},
		"next": next,
	})
}

func nginxStatus(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("NGINX_STATUS_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	if !adapters.CommandExists("nginx") {
		return success("Nginx is not installed", false, map[string]interface{}{"installed": false})
	}
	version := adapters.Run(ctx, "nginx", "-v")
	versionText := firstLine(version.Stderr)
	if versionText == "" {
		versionText = firstLine(version.Stdout)
	}
	configTest := adapters.Run(ctx, "nginx", "-t")
	configError := ""
	if configTest.ExitCode != 0 {
		configError = strings.TrimSpace(configTest.Stderr)
	}
	active := runSystemctl(ctx, "is-active", "--quiet", "nginx").ExitCode == 0
	_, siteError := os.Stat(hostPath(ctx.Env, nginxSiteEnabled))
	_, cloudflareError := os.Stat(hostPath(ctx.Env, nginxCloudflareIP))
	return success("Shared host Nginx status collected", false, map[string]interface{}{
		"installed":                     true,
		"active":                        active,
		"config_valid":                  configTest.ExitCode == 0,
		"config_error":                  configError,
		"version":                       versionText,
		"site_enabled":                  siteError == nil,
		"site_available":                nginxSiteAvailable,
		"site_enabled_path":             nginxSiteEnabled,
		"cloudflare_real_ip_configured": cloudflareError == nil,
	})
}

func nginxStart(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("NGINX_START_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	if !adapters.CommandExists("nginx") {
		return failed("NGINX_NOT_FOUND", "Run sindri nginx install first", core.ExitPrecheckFailed)
	}
	if failure := requireNginxSite(ctx, "NGINX_SITE_NOT_ENABLED"); failure != nil {
		return *failure
	}
	if run := adapters.Run(ctx, "nginx", "-t"); run.ExitCode != 0 {
		return commandFailed("NGINX_CONFIG_INVALID", "config_test", run)
	}
	if run := runSystemctl(ctx, "enable", "--now", "nginx"); run.ExitCode != 0 {
		return commandFailed("NGINX_START_FAILED", "service", run)
	}
	if run := runSystemctl(ctx, "is-active", "--quiet", "nginx"); run.ExitCode != 0 {
		return commandFailed("NGINX_START_VERIFY_FAILED", "verify", run)
	}
	return success("Shared host Nginx is running", true, map[string]interface{}{"config": nginxSiteAvailable})
}

func nginxReload(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("NGINX_RELOAD_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	if !adapters.CommandExists("nginx") {
		return failed("NGINX_NOT_FOUND", "Run sindri nginx install first", core.ExitPrecheckFailed)
	}
	if failure := requireNginxSite(ctx, "NGINX_SITE_NOT_ENABLED"); failure != nil {
		return *failure
	}
	if run := adapters.Run(ctx, "nginx", "-t"); run.ExitCode != 0 {
		return commandFailed("NGINX_CONFIG_INVALID", "config_test", run)
	}
	if run := runSystemctl(ctx, "reload", "nginx"); run.ExitCode != 0 {
		return commandFailed("NGINX_RELOAD_FAILED", "reload", run)
	}
	if run := runSystemctl(ctx, "is-active", "--quiet", "nginx"); run.ExitCode != 0 {
		return commandFailed("NGINX_RELOAD_VERIFY_FAILED", "verify", run)
	}
	return success("Shared host Nginx reloaded", true, nil)
}

func nginxStop(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("NGINX_STOP_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	if !adapters.CommandExists("nginx") {
		return success("Nginx is not installed", false, map[string]interface{}{"installed": false})
	}
	if run := runSystemctl(ctx, "stop", "nginx"); run.ExitCode != 0 {
		return commandFailed("NGINX_STOP_FAILED", "service", run)
	}
	if runSystemctl(ctx, "is-active", "--quiet", "nginx").ExitCode == 0 {
		return failed("NGINX_STOP_VERIFY_FAILED", "Nginx still reports an active state", core.ExitVerificationFailed)
	}
	return success("Shared host Nginx stopped", true, nil)
}

func nginxUninstall(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	if failure := requireUbuntuRoot(ctx, "NGINX_UNINSTALL_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	packages := installedNginxPackages(ctx)
	commandInstalled := adapters.CommandExists("nginx")
	if commandInstalled && len(packages) == 0 {
		return failed("NGINX_UNMANAGED_INSTALLATION", "nginx is not owned by an installed Ubuntu package; refusing to remove unknown files", core.ExitManagedScopeViolation)
	}
	installed := commandInstalled || len(packages) > 0
	paths := []string{
		"/etc/nginx",
		"/var/log/nginx",
		"/var/cache/nginx",
		"/var/lib/nginx",
	}
	filesPresent := false
	for _, item := range paths {
		if fileExists(hostPath(ctx.Env, item)) {
			filesPresent = true
			break
		}
	}
	for _, item := range []string{nginxCertbotPre, nginxCertbotPost, "/run/sindri-nginx-certbot-was-running"} {
		if fileExists(hostPath(ctx.Env, item)) {
			filesPresent = true
		}
	}
	if !installed && !filesPresent {
		return success("Nginx is not installed", false, map[string]interface{}{"installed": false})
	}
	if installed {
		if run := runSystemctl(ctx, "stop", "nginx"); run.ExitCode != 0 {
			return commandFailed("NGINX_UNINSTALL_FAILED", "stop", run)
		}
		if run := runSystemctl(ctx, "disable", "nginx"); run.ExitCode != 0 {
			return commandFailed("NGINX_UNINSTALL_FAILED", "disable", run)
		}
	}
	if len(packages) > 0 {
		if run := runApt(ctx, append([]string{"purge", "-y"}, packages...)...); run.ExitCode != 0 {
			return commandFailed("NGINX_UNINSTALL_FAILED", "packages", run)
		}
	}
	for _, item := range paths {
		if _, err := safeRemoveManaged(hostPath(ctx.Env, item)); err != nil {
			return failed("NGINX_UNINSTALL_FAILED", item+": "+err.Error(), core.ExitGeneralFailure)
		}
	}
	for _, item := range []string{nginxCertbotPre, nginxCertbotPost, "/run/sindri-nginx-certbot-was-running"} {
		if err := os.Remove(hostPath(ctx.Env, item)); err != nil && !os.IsNotExist(err) {
			return failed("NGINX_UNINSTALL_FAILED", item+": "+err.Error(), core.ExitGeneralFailure)
		}
	}
	if adapters.CommandExists("nginx") {
		return failed("NGINX_UNINSTALL_VERIFY_FAILED", "nginx remains available in PATH", core.ExitVerificationFailed)
	}
	resources := loadManaged(ctx.Env)
	for _, item := range packages {
		resources.Packages = removeString(resources.Packages, item)
	}
	resources.Services = removeString(resources.Services, "nginx.service")
	filteredFiles := resources.Files[:0]
	for _, managed := range resources.Files {
		remove := managed == hostPath(ctx.Env, nginxCertbotPre) || managed == hostPath(ctx.Env, nginxCertbotPost)
		for _, directory := range paths {
			root := filepath.Clean(hostPath(ctx.Env, directory))
			candidate := filepath.Clean(managed)
			if candidate == root || strings.HasPrefix(candidate, root+string(filepath.Separator)) {
				remove = true
			}
		}
		if !remove {
			filteredFiles = append(filteredFiles, managed)
		}
	}
	resources.Files = filteredFiles
	if err := saveManaged(ctx.Env, resources); err != nil {
		return managedStateFailure(err)
	}
	return success("Nginx packages, configuration, cache and logs removed; certificates were preserved", true, map[string]interface{}{
		"certificates_preserved": true,
	})
}

func installedNginxPackages(ctx core.Context) []string {
	if !adapters.CommandExists("dpkg-query") {
		if adapters.CommandExists("nginx") {
			return []string{"nginx"}
		}
		return nil
	}
	packages := []string{}
	run := adapters.Run(ctx, "dpkg-query", "-W", "-f=${binary:Package}\\t${db:Status-Abbrev}\\n", "nginx*", "libnginx-mod-*")
	for _, line := range strings.Split(run.Stdout, "\n") {
		fields := strings.SplitN(line, "\t", 2)
		if len(fields) == 2 && strings.HasPrefix(fields[1], "ii") {
			packages = mergeUnique(packages, strings.TrimSpace(fields[0]))
		}
	}
	return packages
}

func requireNginxSite(ctx core.Context, code string) *core.Result {
	available := hostPath(ctx.Env, nginxSiteAvailable)
	enabled := hostPath(ctx.Env, nginxSiteEnabled)
	info, err := os.Lstat(enabled)
	if err != nil {
		result := failed(code, nginxSiteEnabled+" must be a symlink to "+nginxSiteAvailable, core.ExitPrecheckFailed)
		return &result
	}
	if info.Mode()&os.ModeSymlink == 0 {
		result := failed(code, nginxSiteEnabled+" exists but is not a symbolic link", core.ExitPrecheckFailed)
		return &result
	}
	resolved, err := filepath.EvalSymlinks(enabled)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(available) {
		result := failed(code, nginxSiteEnabled+" must resolve to "+nginxSiteAvailable, core.ExitPrecheckFailed)
		return &result
	}
	return nil
}

func dockerLogs(ctx core.Context, _ core.Request, inputs map[string]interface{}) core.Result {
	if !adapters.CommandExists("docker") {
		return failed("DOCKER_NOT_FOUND", "Docker is not installed", core.ExitPrecheckFailed)
	}
	lines := inputs["lines"].(int)
	list := adapters.Run(ctx, "docker", "ps", "-aq")
	if list.ExitCode != 0 {
		return commandFailed("DOCKER_LOGS_FAILED", "list", list)
	}
	const maxOutput = 2 * 1024 * 1024
	output := map[string]string{}
	total := 0
	truncated := false
	for _, id := range strings.Fields(list.Stdout) {
		nameResult := adapters.Run(ctx, "docker", "inspect", "--format", "{{.Name}}", id)
		name := strings.TrimPrefix(strings.TrimSpace(nameResult.Stdout), "/")
		if name == "" {
			name = id
		}
		logs := adapters.Run(ctx, "docker", "logs", "--timestamps", "--tail", strconv.Itoa(lines), id)
		value := strings.TrimSpace(strings.Join([]string{logs.Stdout, logs.Stderr}, "\n"))
		if total+len(value) > maxOutput {
			remaining := maxOutput - total
			if remaining > 0 {
				value = value[:remaining]
			} else {
				value = ""
			}
			truncated = true
		}
		output[name] = value
		total += len(value)
		if truncated {
			break
		}
	}
	return success("Docker logs collected", false, map[string]interface{}{"containers": output, "truncated": truncated})
}

func dockerClean(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("DOCKER_CLEAN_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	if !adapters.CommandExists("docker") {
		return success("Docker is not installed", false, map[string]interface{}{"installed": false})
	}
	removed := map[string]int{}
	for category, listArgs := range map[string][]string{
		"containers": {"ps", "-aq"},
		"images":     {"images", "-aq"},
		"volumes":    {"volume", "ls", "-q"},
		"networks":   {"network", "ls", "--filter", "type=custom", "-q"},
	} {
		list := adapters.Run(ctx, "docker", listArgs...)
		if list.ExitCode != 0 {
			return commandFailed("DOCKER_CLEAN_FAILED", "list_"+category, list)
		}
		ids := strings.Fields(list.Stdout)
		if len(ids) == 0 {
			continue
		}
		args := []string{}
		switch category {
		case "containers":
			args = append([]string{"rm", "-f"}, ids...)
		case "images":
			args = append([]string{"image", "rm", "-f"}, ids...)
		case "volumes":
			args = append([]string{"volume", "rm", "-f"}, ids...)
		case "networks":
			args = append([]string{"network", "rm"}, ids...)
		}
		if run := adapters.Run(ctx, "docker", args...); run.ExitCode != 0 {
			return commandFailed("DOCKER_CLEAN_FAILED", category, run)
		}
		removed[category] = len(ids)
	}
	if run := adapters.Run(ctx, "docker", "builder", "prune", "-af"); run.ExitCode != 0 {
		return commandFailed("DOCKER_CLEAN_FAILED", "build_cache", run)
	}
	return success("Docker data removed", true, map[string]interface{}{"removed": removed})
}

func dockerUp(ctx core.Context, _ core.Request, inputs map[string]interface{}) core.Result {
	return dockerComposeAction(ctx, filepath.Clean(inputs["path"].(string)), true)
}

func dockerDown(ctx core.Context, _ core.Request, inputs map[string]interface{}) core.Result {
	return dockerComposeAction(ctx, filepath.Clean(inputs["path"].(string)), false)
}

func dockerComposeAction(ctx core.Context, path string, up bool) core.Result {
	if !adapters.CommandExists("docker") {
		return failed("DOCKER_NOT_FOUND", "Docker is not installed", core.ExitPrecheckFailed)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return failed("DOCKER_PATH_INVALID", err.Error(), core.ExitInvalidCommand)
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.IsDir() {
		return failed("DOCKER_PATH_INVALID", "Compose path must be an existing directory", core.ExitPrecheckFailed)
	}
	compose := ""
	for _, name := range []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"} {
		candidate := filepath.Join(absolute, name)
		if item, statErr := os.Stat(candidate); statErr == nil && !item.IsDir() {
			compose = candidate
			break
		}
	}
	if compose != "" {
		args := []string{"compose", "-f", compose}
		if up {
			args = append(args, "up", "-d", "--build")
		} else {
			args = append(args, "down")
		}
		run := adapters.Run(ctx, "docker", args...)
		if run.ExitCode != 0 {
			return commandFailed("DOCKER_COMPOSE_FAILED", "compose", run)
		}
		if up {
			resources := loadManaged(ctx.Env)
			resources.Projects = mergeUnique(resources.Projects, absolute)
			if err := saveManaged(ctx.Env, resources); err != nil {
				return managedStateFailure(err)
			}
		}
		return success("Docker Compose project updated", true, map[string]interface{}{"compose_file": compose, "operation": map[bool]string{true: "up", false: "down"}[up]})
	}
	filter := "-qf"
	state := "status=exited"
	command := "start"
	if !up {
		state = "status=running"
		command = "stop"
	}
	list := adapters.Run(ctx, "docker", "ps", filter, state)
	if list.ExitCode != 0 {
		return commandFailed("DOCKER_COMMAND_FAILED", "list", list)
	}
	ids := strings.Fields(list.Stdout)
	if len(ids) == 0 {
		return success("No matching containers found", false, map[string]interface{}{"operation": command})
	}
	run := adapters.Run(ctx, "docker", append([]string{command}, ids...)...)
	if run.ExitCode != 0 {
		return commandFailed("DOCKER_COMMAND_FAILED", command, run)
	}
	return success("Docker containers updated", true, map[string]interface{}{"operation": command, "containers": ids})
}

func userAdd(ctx core.Context, _ core.Request, inputs map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("USER_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	username := strings.TrimSpace(inputs["username"].(string))
	password := inputs["password"].(string)
	if !localUsername(username) || username == "root" {
		return failed("USERNAME_INVALID", "Username must use a safe local account name", core.ExitInvalidCommand)
	}
	if len(password) < 12 {
		return failed("PASSWORD_TOO_SHORT", "Password must contain at least 12 characters", core.ExitInvalidCommand)
	}
	if adapters.Run(ctx, "id", username).ExitCode == 0 {
		return failed("USER_EXISTS", "User already exists", core.ExitPrecheckFailed)
	}
	if run := adapters.Run(ctx, "useradd", "--create-home", "--shell", "/bin/bash", username); run.ExitCode != 0 {
		return commandFailed("USER_CREATE_FAILED", "useradd", run)
	}
	if run := adapters.RunWithInput(ctx, username+":"+password+"\n", "chpasswd"); run.ExitCode != 0 {
		_ = adapters.Run(ctx, "userdel", "--remove", username)
		return commandFailed("PASSWORD_CHANGE_FAILED", "chpasswd", run)
	}
	if inputs["sudo"].(bool) {
		if run := adapters.Run(ctx, "usermod", "-aG", "sudo", username); run.ExitCode != 0 {
			return commandFailed("SUDO_GROUP_FAILED", "sudo", run)
		}
	}
	resources := loadManaged(ctx.Env)
	resources.Users = mergeUnique(resources.Users, username)
	if err := saveManaged(ctx.Env, resources); err != nil {
		_ = adapters.Run(ctx, "userdel", "--remove", username)
		return managedStateFailure(err)
	}
	id := adapters.Run(ctx, "id", username)
	groups := adapters.Run(ctx, "groups", username)
	return success("Local user created", true, map[string]interface{}{"username": username, "id": id.Stdout, "groups": groups.Stdout})
}

func userDelete(ctx core.Context, _ core.Request, inputs map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("USER_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	username := strings.TrimSpace(inputs["username"].(string))
	if !localUsername(username) || username == "root" || username == currentUsername() {
		return failed("USER_DELETE_BLOCKED", "The requested account cannot be deleted safely", core.ExitManagedScopeViolation)
	}
	resources := loadManaged(ctx.Env)
	if !containsString(resources.Users, username) {
		return failed("MANAGED_SCOPE_VIOLATION", "User is not registered as Sindri-managed", core.ExitManagedScopeViolation)
	}
	args := []string{}
	if inputs["remove_home"].(bool) {
		args = append(args, "--remove")
	}
	args = append(args, username)
	if run := adapters.Run(ctx, "userdel", args...); run.ExitCode != 0 {
		return commandFailed("USER_DELETE_FAILED", "userdel", run)
	}
	resources.Users = removeString(resources.Users, username)
	if err := saveManaged(ctx.Env, resources); err != nil {
		return managedStateFailure(err)
	}
	return success("Local user deleted", true, map[string]interface{}{"username": username, "home_removed": inputs["remove_home"]})
}

func userPasswordChange(ctx core.Context, _ core.Request, inputs map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("USER_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	username := strings.TrimSpace(inputs["username"].(string))
	password := inputs["password"].(string)
	if !localUsername(username) || len(password) < 12 {
		return failed("PASSWORD_INPUT_INVALID", "A valid username and a password of at least 12 characters are required", core.ExitInvalidCommand)
	}
	if adapters.Run(ctx, "id", username).ExitCode != 0 {
		return failed("USER_NOT_FOUND", "User does not exist", core.ExitPrecheckFailed)
	}
	if run := adapters.RunWithInput(ctx, username+":"+password+"\n", "chpasswd"); run.ExitCode != 0 {
		return commandFailed("PASSWORD_CHANGE_FAILED", "chpasswd", run)
	}
	return success("Local user password changed", true, map[string]interface{}{"username": username})
}

func certificateDelete(ctx core.Context, _ core.Request, inputs map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("CERTIFICATE_DELETE_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	name := strings.TrimSpace(inputs["certificate"].(string))
	if !certificateName.MatchString(name) {
		return failed("CERTIFICATE_NAME_INVALID", "Certificate name is invalid", core.ExitInvalidCommand)
	}
	if !adapters.CommandExists("certbot") {
		return failed("CERTBOT_NOT_FOUND", "Certbot is not installed", core.ExitPrecheckFailed)
	}
	run := runCertbot(ctx, "delete", "--cert-name", name, "--non-interactive")
	if run.ExitCode != 0 {
		return commandFailed("CERTIFICATE_DELETE_FAILED", "certbot", run)
	}
	if _, err := os.Stat(hostPath(ctx.Env, filepath.Join("/etc/letsencrypt/live", name))); err == nil {
		return failed("CERTIFICATE_DELETE_VERIFY_FAILED", "Certificate directory still exists", core.ExitVerificationFailed)
	}
	return success("Certificate deleted", true, map[string]interface{}{"certificate": name})
}

func shutdownHost(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("SHUTDOWN_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	if err := core.EnsureRuntimeDirs(ctx.Env); err != nil {
		return failed("RECOVERY_BUNDLE_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	if body, err := os.ReadFile(filepath.Join(ctx.Env.DataDir, "recovery", "active.json")); err == nil {
		var existing recoveryPointer
		if json.Unmarshal(body, &existing) == nil && (existing.Status == "active" || existing.Status == "applying") {
			return failed("SHUTDOWN_ALREADY_ACTIVE", "A shutdown recovery state is already active; run sindri recovery first", core.ExitPrecheckFailed)
		}
	}
	bundle := captureRecoveryBundle(ctx)
	body, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return failed("RECOVERY_BUNDLE_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	sum := sha256.Sum256(body)
	checksum := "sha256:" + hex.EncodeToString(sum[:])
	directory := filepath.Join(ctx.Env.DataDir, "recovery", "shutdown-"+time.Now().UTC().Format("20060102T150405Z"))
	if err := os.MkdirAll(directory, 0700); err != nil {
		return failed("RECOVERY_BUNDLE_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	bundlePath := filepath.Join(directory, "state.json")
	if err := atomicWrite(bundlePath, append(body, '\n'), 0600); err != nil {
		return failed("RECOVERY_BUNDLE_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	pointer := recoveryPointer{BundlePath: bundlePath, Checksum: checksum, Status: "applying"}
	if err := writeRecoveryPointer(ctx.Env, pointer); err != nil {
		return failed("RECOVERY_BUNDLE_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	if failure := applyLockdown(ctx, bundle); failure != nil {
		_ = restoreRecoveryBundle(ctx, bundle)
		pointer.Status = "rolled_back"
		_ = writeRecoveryPointer(ctx.Env, pointer)
		return *failure
	}
	pointer.Status = "active"
	if err := writeRecoveryPointer(ctx.Env, pointer); err != nil {
		_ = restoreRecoveryBundle(ctx, bundle)
		return failed("RECOVERY_BUNDLE_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	return success("Reversible network lockdown is active", true, map[string]interface{}{"recovery_bundle": bundlePath, "checksum": checksum, "ssh_ports": bundle.SSHPorts})
}

func recoverHost(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("RECOVERY_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	pointer, bundle, failure := loadActiveRecovery(ctx.Env)
	if failure != nil {
		return *failure
	}
	if restoreFailure := restoreRecoveryBundle(ctx, bundle); restoreFailure != nil {
		return *restoreFailure
	}
	pointer.Status = "recovered"
	if err := writeRecoveryPointer(ctx.Env, pointer); err != nil {
		return managedStateFailure(err)
	}
	return success("Previous network and service state restored", true, map[string]interface{}{"recovery_bundle": pointer.BundlePath})
}

func exterminatusHost(ctx core.Context, req core.Request, _ map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("EXTERMINATUS_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	hostname, _ := os.Hostname()
	if req.Approval == nil || req.Approval.ConfirmationPhrase != "EXTERMINATUS" || req.Approval.HostnameConfirmation != hostname {
		return failed("EXTERMINATUS_CONFIRMATION_INVALID", "EXTERMINATUS and the exact server hostname are required", core.ExitVerificationFailed)
	}
	resources := loadManaged(ctx.Env)
	inventory := map[string]interface{}{
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"hostname":   hostname,
		"managed":    resources,
	}
	inventoryBody, _ := json.MarshalIndent(inventory, "", "  ")
	inventoryPath := filepath.Join(ctx.Env.DataDir, "recovery", "exterminatus-"+time.Now().UTC().Format("20060102T150405Z")+".json")
	if err := atomicWrite(inventoryPath, append(inventoryBody, '\n'), 0600); err != nil {
		return failed("EXTERMINATUS_INVENTORY_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	deleted := []string{}
	skipped := []string{}
	failures := []string{}
	if result := dockerClean(ctx, req, nil); result.Status == core.StatusFailed {
		failures = append(failures, "docker resources: "+result.Error.Message)
	} else if result.Changed {
		deleted = append(deleted, "Docker resources")
	} else {
		skipped = append(skipped, "Docker resources (not installed or already empty)")
	}
	for _, name := range certbotCertificateNames(ctx.Env) {
		if run := runCertbot(ctx, "delete", "--cert-name", name, "--non-interactive"); run.ExitCode != 0 {
			failures = append(failures, "certificate "+name)
		} else {
			deleted = append(deleted, "certificate "+name)
		}
	}
	for _, username := range resources.Users {
		if username == "root" || username == currentUsername() || !localUsername(username) {
			skipped = append(skipped, "user "+username)
			continue
		}
		if run := adapters.Run(ctx, "userdel", "--remove", username); run.ExitCode != 0 {
			failures = append(failures, "user "+username)
		} else {
			deleted = append(deleted, "user "+username)
		}
	}
	for _, project := range resources.Projects {
		removed, err := safeRemoveManaged(project)
		if err != nil {
			failures = append(failures, "project "+project+": "+err.Error())
		} else if removed {
			deleted = append(deleted, "project "+project)
		} else {
			skipped = append(skipped, "project "+project+" (already absent)")
		}
	}
	for _, packageName := range resources.Packages {
		run := runApt(ctx, "purge", "-y", packageName)
		if run.ExitCode != 0 {
			failures = append(failures, "package "+packageName+": "+firstLine(run.Stderr))
		} else {
			deleted = append(deleted, "package "+packageName)
		}
	}
	for _, path := range resources.Files {
		removed, err := safeRemoveManaged(path)
		if err != nil {
			failures = append(failures, "file "+path+": "+err.Error())
		} else if removed {
			deleted = append(deleted, "file "+path)
		} else {
			skipped = append(skipped, "file "+path+" (already absent)")
		}
	}
	for _, path := range []string{
		hostPath(ctx.Env, "/var/lib/docker"),
		hostPath(ctx.Env, "/var/lib/containerd"),
		hostPath(ctx.Env, "/etc/docker"),
	} {
		if containsString(resources.Packages, "docker-ce") {
			removed, err := safeRemoveManaged(path)
			if err != nil {
				failures = append(failures, path)
			} else if removed {
				deleted = append(deleted, path)
			} else {
				skipped = append(skipped, path+" (already absent)")
			}
		}
	}
	ports := sshPorts(ctx.Env)
	if adapters.CommandExists("ufw") {
		_ = adapters.Run(ctx, "ufw", "--force", "reset")
		_ = adapters.Run(ctx, "ufw", "default", "deny", "incoming")
		for _, port := range ports {
			_ = adapters.Run(ctx, "ufw", "allow", fmt.Sprintf("%d/tcp", port))
		}
		_ = adapters.Run(ctx, "ufw", "--force", "enable")
	}
	_ = adapters.Run(ctx, "sysctl", "-w", "net.ipv4.icmp_echo_ignore_all=1")
	_ = adapters.Run(ctx, "sync")
	if run := runSystemctl(ctx, "poweroff", "--no-block"); run.ExitCode != 0 {
		failures = append(failures, "poweroff: "+firstLine(run.Stderr))
	}
	report := map[string]interface{}{
		"inventory": inventoryPath,
		"deleted":   deleted,
		"skipped":   skipped,
		"failed":    failures,
		"provider_action_required": []string{
			"Delete provider snapshots and backups",
			"Reimage or destroy the VPS through the hosting provider",
		},
	}
	status := core.StatusPartial
	exitCode := core.ExitProviderActionRequired
	if len(failures) > 0 {
		exitCode = core.ExitPartialSuccess
	}
	return core.Result{Status: status, Changed: true, Message: "EXTERMINATUS completed; provider action is still required", Data: report, ExitCode: exitCode}
}

func captureRecoveryBundle(ctx core.Context) recoveryBundle {
	hostname, _ := os.Hostname()
	bundle := recoveryBundle{
		Schema:         "sindri.shutdown-recovery.v1",
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		Hostname:       hostname,
		UFWInstalled:   adapters.CommandExists("ufw"),
		SSHPorts:       sshPorts(ctx.Env),
		IPv4ICMPIgnore: readTrim(hostPath(ctx.Env, "/proc/sys/net/ipv4/icmp_echo_ignore_all")),
		IPv6ICMPIgnore: readTrim(hostPath(ctx.Env, "/proc/sys/net/ipv6/icmp/echo_ignore_all")),
	}
	if bundle.UFWInstalled {
		status := adapters.Run(ctx, "ufw", "status")
		bundle.UFWActive = strings.Contains(strings.ToLower(status.Stdout), "status: active")
		added := adapters.Run(ctx, "ufw", "show", "added")
		for _, line := range strings.Split(added.Stdout, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ufw ") {
				bundle.UFWRules = append(bundle.UFWRules, line)
			}
		}
	}
	if adapters.CommandExists("docker") {
		bundle.RunningContainers = strings.Fields(adapters.Run(ctx, "docker", "ps", "-q").Stdout)
	}
	resources := loadManaged(ctx.Env)
	for _, service := range resources.Services {
		if runSystemctl(ctx, "is-active", "--quiet", service).ExitCode == 0 {
			bundle.RunningServices = append(bundle.RunningServices, service)
		}
	}
	return bundle
}

func applyLockdown(ctx core.Context, bundle recoveryBundle) *core.Result {
	for _, id := range bundle.RunningContainers {
		if run := adapters.Run(ctx, "docker", "stop", id); run.ExitCode != 0 {
			result := commandFailed("LOCKDOWN_FAILED", "containers", run)
			return &result
		}
	}
	for _, service := range bundle.RunningServices {
		if run := runSystemctl(ctx, "stop", service); run.ExitCode != 0 {
			result := commandFailed("LOCKDOWN_FAILED", "services", run)
			return &result
		}
	}
	if bundle.UFWInstalled {
		if run := adapters.Run(ctx, "ufw", "--force", "reset"); run.ExitCode != 0 {
			result := commandFailed("LOCKDOWN_FAILED", "firewall_reset", run)
			return &result
		}
		_ = adapters.Run(ctx, "ufw", "default", "deny", "incoming")
		_ = adapters.Run(ctx, "ufw", "default", "allow", "outgoing")
		for _, port := range bundle.SSHPorts {
			if run := adapters.Run(ctx, "ufw", "allow", fmt.Sprintf("%d/tcp", port)); run.ExitCode != 0 {
				result := commandFailed("LOCKDOWN_FAILED", "preserve_ssh", run)
				return &result
			}
		}
		if run := adapters.Run(ctx, "ufw", "--force", "enable"); run.ExitCode != 0 {
			result := commandFailed("LOCKDOWN_FAILED", "firewall_enable", run)
			return &result
		}
	}
	if run := adapters.Run(ctx, "sysctl", "-w", "net.ipv4.icmp_echo_ignore_all=1"); run.ExitCode != 0 {
		result := commandFailed("LOCKDOWN_FAILED", "icmp", run)
		return &result
	}
	_ = adapters.Run(ctx, "sysctl", "-w", "net.ipv6.icmp.echo_ignore_all=1")
	return nil
}

func restoreRecoveryBundle(ctx core.Context, bundle recoveryBundle) *core.Result {
	if bundle.UFWInstalled {
		if run := adapters.Run(ctx, "ufw", "--force", "reset"); run.ExitCode != 0 {
			result := commandFailed("RECOVERY_FAILED", "firewall_reset", run)
			return &result
		}
		for _, line := range bundle.UFWRules {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != "ufw" {
				continue
			}
			if run := adapters.Run(ctx, "ufw", fields[1:]...); run.ExitCode != 0 {
				result := commandFailed("RECOVERY_FAILED", "firewall_rules", run)
				return &result
			}
		}
		action := "disable"
		if bundle.UFWActive {
			action = "enable"
		}
		if run := adapters.Run(ctx, "ufw", "--force", action); run.ExitCode != 0 {
			result := commandFailed("RECOVERY_FAILED", "firewall_state", run)
			return &result
		}
	}
	if bundle.IPv4ICMPIgnore != "" {
		_ = adapters.Run(ctx, "sysctl", "-w", "net.ipv4.icmp_echo_ignore_all="+bundle.IPv4ICMPIgnore)
	}
	if bundle.IPv6ICMPIgnore != "" {
		_ = adapters.Run(ctx, "sysctl", "-w", "net.ipv6.icmp.echo_ignore_all="+bundle.IPv6ICMPIgnore)
	}
	for _, service := range bundle.RunningServices {
		if run := runSystemctl(ctx, "start", service); run.ExitCode != 0 {
			result := commandFailed("RECOVERY_FAILED", "services", run)
			return &result
		}
	}
	if len(bundle.RunningContainers) > 0 {
		if run := adapters.Run(ctx, "docker", append([]string{"start"}, bundle.RunningContainers...)...); run.ExitCode != 0 {
			result := commandFailed("RECOVERY_FAILED", "containers", run)
			return &result
		}
	}
	return nil
}

func loadActiveRecovery(env core.Environment) (recoveryPointer, recoveryBundle, *core.Result) {
	var pointer recoveryPointer
	var bundle recoveryBundle
	body, err := os.ReadFile(filepath.Join(env.DataDir, "recovery", "active.json"))
	if err != nil {
		result := failed("RECOVERY_STATE_MISSING", err.Error(), core.ExitRecoveryStateMissing)
		return pointer, bundle, &result
	}
	if err := json.Unmarshal(body, &pointer); err != nil || pointer.BundlePath == "" {
		result := failed("RECOVERY_STATE_CORRUPTED", "Recovery pointer is invalid", core.ExitRecoveryStateCorrupted)
		return pointer, bundle, &result
	}
	if pointer.Status != "active" {
		result := failed("RECOVERY_STATE_INACTIVE", "No active shutdown recovery state exists", core.ExitRecoveryStateMissing)
		return pointer, bundle, &result
	}
	bundleBody, err := os.ReadFile(pointer.BundlePath)
	if err != nil {
		result := failed("RECOVERY_STATE_MISSING", err.Error(), core.ExitRecoveryStateMissing)
		return pointer, bundle, &result
	}
	sum := sha256.Sum256(bytesTrimSpace(bundleBody))
	checksum := "sha256:" + hex.EncodeToString(sum[:])
	if checksum != pointer.Checksum {
		result := failed("RECOVERY_STATE_CORRUPTED", "Recovery checksum mismatch", core.ExitRecoveryStateCorrupted)
		return pointer, bundle, &result
	}
	if err := json.Unmarshal(bundleBody, &bundle); err != nil || bundle.Schema != "sindri.shutdown-recovery.v1" {
		result := failed("RECOVERY_STATE_CORRUPTED", "Recovery bundle is invalid", core.ExitRecoveryStateCorrupted)
		return pointer, bundle, &result
	}
	return pointer, bundle, nil
}

func writeRecoveryPointer(env core.Environment, pointer recoveryPointer) error {
	body, err := json.MarshalIndent(pointer, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(env.DataDir, "recovery", "active.json"), append(body, '\n'), 0600)
}

func loadManaged(env core.Environment) managedResources {
	var resources managedResources
	body, err := os.ReadFile(filepath.Join(env.DataDir, "managed-resources.json"))
	if err == nil {
		_ = json.Unmarshal(body, &resources)
	}
	return resources
}

func saveManaged(env core.Environment, resources managedResources) error {
	if err := core.EnsureRuntimeDirs(env); err != nil {
		return err
	}
	sort.Strings(resources.Users)
	sort.Strings(resources.Packages)
	sort.Strings(resources.Services)
	sort.Strings(resources.Files)
	sort.Strings(resources.Projects)
	body, err := json.MarshalIndent(resources, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(env.DataDir, "managed-resources.json"), append(body, '\n'), 0600)
}

func requireLinuxRoot(code string) *core.Result {
	if runtime.GOOS != "linux" {
		result := failed(code, "This operation requires Linux", core.ExitUnsupportedOS)
		return &result
	}
	if os.Geteuid() != 0 {
		result := failed(code, "This operation requires root privileges", core.ExitInsufficientPrivileges)
		return &result
	}
	return nil
}

func requireUbuntuRoot(ctx core.Context, code string) *core.Result {
	if failure := requireLinuxRoot(code); failure != nil {
		return failure
	}
	id := osReleaseValue(hostPath(ctx.Env, "/etc/os-release"), "ID")
	version := osReleaseValue(hostPath(ctx.Env, "/etc/os-release"), "VERSION_ID")
	if id != "ubuntu" || (version != "22.04" && version != "24.04" && version != "26.04") || runtime.GOARCH != "amd64" {
		result := failed(code, "Supported Ubuntu amd64 releases are 22.04, 24.04 and 26.04", core.ExitUnsupportedOS)
		return &result
	}
	return nil
}

func hostPath(env core.Environment, absolute string) string {
	clean := filepath.Clean(absolute)
	if env.HostRoot == "" || env.HostRoot == string(filepath.Separator) {
		return clean
	}
	return filepath.Join(env.HostRoot, strings.TrimPrefix(clean, string(filepath.Separator)))
}

func osReleaseValue(path, key string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if ok && name == key {
			return strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	return ""
}

func sshPorts(env core.Environment) []int {
	ports := []int{}
	paths := []string{hostPath(env, "/etc/ssh/sshd_config")}
	matches, _ := filepath.Glob(hostPath(env, "/etc/ssh/sshd_config.d/*.conf"))
	paths = append(paths, matches...)
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(body), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) == 2 && strings.EqualFold(fields[0], "Port") {
				if port, parseErr := strconv.Atoi(fields[1]); parseErr == nil && port > 0 && port <= 65535 {
					ports = append(ports, port)
				}
			}
		}
	}
	if len(ports) == 0 {
		ports = append(ports, 22)
	}
	sort.Ints(ports)
	out := []int{}
	for _, port := range ports {
		if !containsInt(out, port) {
			out = append(out, port)
		}
	}
	return out
}

func certbotCertificateNames(env core.Environment) []string {
	matches, _ := filepath.Glob(hostPath(env, "/etc/letsencrypt/renewal/*.conf"))
	names := make([]string, 0, len(matches))
	for _, path := range matches {
		name := strings.TrimSuffix(filepath.Base(path), ".conf")
		if certificateName.MatchString(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func atomicWrite(path string, body []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".sindri-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(body); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func diskFreeBytes(path string) (uint64, error) {
	var stats syscall.Statfs_t
	if err := syscall.Statfs(path, &stats); err != nil {
		return 0, err
	}
	return stats.Bavail * uint64(stats.Bsize), nil
}

func safeRemoveManaged(path string) (bool, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("refusing to recursively remove a symbolic link")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	forbidden := map[string]bool{
		"/": true, "/boot": true, "/dev": true, "/proc": true, "/sys": true,
		"/run": true, "/etc": true, "/usr": true, "/bin": true, "/sbin": true,
		"/lib": true, "/lib64": true, "/var": true,
	}
	if forbidden[filepath.Clean(resolved)] {
		return false, fmt.Errorf("protected system path")
	}
	if err := os.RemoveAll(resolved); err != nil {
		return false, err
	}
	return true, nil
}

func commandFailed(code, step string, run adapters.CommandResult) core.Result {
	message := strings.TrimSpace(run.Stderr)
	if message == "" {
		message = strings.TrimSpace(run.Stdout)
	}
	if message == "" {
		message = fmt.Sprintf("%s exited with code %d", strings.Join(run.Command, " "), run.ExitCode)
	}
	exitCode := core.ExitGeneralFailure
	if run.TimedOut {
		exitCode = core.ExitTimeout
	}
	return failed(code, step+": "+message, exitCode)
}

func managedStateFailure(err error) core.Result {
	return core.Result{
		Status:   core.StatusPartial,
		Changed:  true,
		Message:  "The system operation completed, but Sindri could not persist its managed-resource inventory",
		Error:    &core.ErrorInfo{Code: "MANAGED_STATE_WRITE_FAILED", Message: err.Error()},
		ExitCode: core.ExitPartialSuccess,
	}
}

func failed(code, message string, exitCode int) core.Result {
	return core.Result{
		Status:   core.StatusFailed,
		Error:    &core.ErrorInfo{Code: code, Message: message},
		ExitCode: exitCode,
	}
}

func mergeUnique(current []string, values ...string) []string {
	out := append([]string{}, current...)
	for _, value := range values {
		if value != "" && !containsString(out, value) {
			out = append(out, value)
		}
	}
	return out
}

func removeString(values []string, target string) []string {
	out := values[:0]
	for _, value := range values {
		if value != target {
			out = append(out, value)
		}
	}
	return out
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsInt(values []int, target int) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func currentUsername() string {
	if current, err := user.Current(); err == nil {
		return current.Username
	}
	return ""
}

func firstLine(value string) string {
	line, _, _ := strings.Cut(value, "\n")
	return strings.TrimSpace(line)
}

func readTrim(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

func bytesTrimSpace(body []byte) []byte {
	return []byte(strings.TrimSpace(string(body)))
}
