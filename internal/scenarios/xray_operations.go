package scenarios

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"sindri/internal/adapters"
	"sindri/internal/core"
)

const (
	xrayReleaseBaseURL    = "https://github.com/XTLS/Xray-core/releases/latest/download"
	xrayReleaseArchive    = "Xray-linux-64.zip"
	xrayReleaseMaxBytes   = int64(128 * 1024 * 1024)
	xrayReleaseTimeout    = 10 * time.Minute
	xrayHealthAttempts    = 10
	xrayHealthInterval    = 500 * time.Millisecond
	xrayRoutingTableIPv4  = "10030"
	xrayRoutingTableIPv6  = "10031"
	xrayRoutingRuleIPv4   = "10030"
	xrayRoutingRuleIPv6   = "10031"
	xrayRoutingPacketMark = "0x1eaf"
)

var (
	xrayReleaseSHA256 = regexp.MustCompile(`(?mi)^SHA(?:2-)?256=\s*([a-f0-9]{64})\s*$`)
	xrayReleaseLoader = downloadLatestXrayRelease
)

type xrayReleaseBundle struct {
	Files  map[string][]byte
	SHA256 string
}

func xrayInstall(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	if failure := requireUbuntuRoot(ctx, "XRAY_INSTALL_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	if runtime.GOARCH != "amd64" {
		return failed("XRAY_ARCH_UNSUPPORTED", "Xray installation currently supports linux/amd64", core.ExitUnsupportedOS)
	}
	resources := loadManaged(ctx.Env)
	binary := hostPath(ctx.Env, xrayBinaryPath)
	managedInstallation := xrayInstallationManaged(ctx.Env) || containsString(resources.Files, binary)
	if !managedInstallation {
		for _, item := range []string{
			xrayBinaryPath, xrayShareDirectory, xrayConfigDirectory, xrayProfilesDirectory,
			xrayRuntimeDirectory, "/var/log/xray", xraySystemdServicePath,
			xrayRoutingServicePath, xrayRoutingScriptPath,
		} {
			if fileExists(hostPath(ctx.Env, item)) {
				return failed("XRAY_UNMANAGED_INSTALLATION", item+" already exists and is not managed by Sindri", core.ExitManagedScopeViolation)
			}
		}
	}
	userLookup := adapters.Run(ctx, "id", "-u", xrayServiceUser)
	groupLookup := adapters.Run(ctx, "getent", "group", xrayServiceUser)
	if !managedInstallation && (userLookup.ExitCode == 0 || groupLookup.ExitCode == 0) {
		return failed("XRAY_UNMANAGED_INSTALLATION", "the "+xrayServiceUser+" user or group already exists and is not managed by Sindri", core.ExitManagedScopeViolation)
	}
	for _, command := range []struct {
		step string
		args []string
	}{
		{"apt_update", []string{"update"}},
		{"dependencies", []string{"install", "-y", "ca-certificates", "nftables", "iproute2", "nano"}},
	} {
		if run := runApt(ctx, command.args...); run.ExitCode != 0 {
			return commandFailed("XRAY_INSTALL_FAILED", command.step, run)
		}
	}
	if userLookup.ExitCode != 0 {
		userArgs := []string{"--system", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin"}
		if groupLookup.ExitCode == 0 {
			userArgs = append(userArgs, "--gid", xrayServiceUser)
		} else {
			userArgs = append(userArgs, "--user-group")
		}
		userArgs = append(userArgs, xrayServiceUser)
		if run := adapters.Run(ctx, "useradd", userArgs...); run.ExitCode != 0 {
			return commandFailed("XRAY_USER_CREATE_FAILED", "useradd", run)
		}
	}

	bundle, err := xrayReleaseLoader(ctx)
	if err != nil {
		return failed("XRAY_DOWNLOAD_FAILED", err.Error(), core.ExitVerificationFailed)
	}
	if err := os.MkdirAll(hostPath(ctx.Env, xrayProfilesDirectory), 0700); err != nil {
		return failed("XRAY_INSTALL_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	marker := []byte("{\n  \"schema\": 1,\n  \"owner\": \"sindri\"\n}\n")
	if err := atomicWrite(hostPath(ctx.Env, xrayManagedMarkerPath), marker, 0600); err != nil {
		return failed("XRAY_INSTALL_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	for name, target := range map[string]string{
		"xray": binary, "geoip.dat": hostPath(ctx.Env, xrayShareDirectory+"/geoip.dat"),
		"geosite.dat": hostPath(ctx.Env, xrayShareDirectory+"/geosite.dat"),
	} {
		body, ok := bundle.Files[name]
		if !ok || len(body) == 0 {
			return failed("XRAY_RELEASE_INVALID", "release archive is missing "+name, core.ExitVerificationFailed)
		}
		mode := os.FileMode(0644)
		if name == "xray" {
			mode = 0755
		}
		if err := atomicWrite(target, body, mode); err != nil {
			return failed("XRAY_INSTALL_FAILED", err.Error(), core.ExitGeneralFailure)
		}
	}
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{
		{hostPath(ctx.Env, xrayProfilesDirectory), 0700},
		{hostPath(ctx.Env, xrayConfigDirectory), 0750},
		{hostPath(ctx.Env, xrayRuntimeDirectory), 0700},
	} {
		if err := os.MkdirAll(directory.path, directory.mode); err != nil {
			return failed("XRAY_INSTALL_FAILED", err.Error(), core.ExitGeneralFailure)
		}
		_ = os.Chmod(directory.path, directory.mode)
	}
	profilesPath := hostPath(ctx.Env, xrayProfilesPath)
	if _, err := os.Stat(profilesPath); os.IsNotExist(err) {
		if err := atomicWrite(profilesPath, []byte("# One VLESS URL per line. Lines beginning with # are ignored.\n"), 0600); err != nil {
			return failed("XRAY_INSTALL_FAILED", err.Error(), core.ExitGeneralFailure)
		}
	}
	configPath := hostPath(ctx.Env, xrayGeneratedConfig)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		placeholder := []byte("{\n  \"log\": {\"loglevel\": \"warning\"},\n  \"inbounds\": [],\n  \"outbounds\": [{\"tag\": \"blocked\", \"protocol\": \"blackhole\"}]\n}\n")
		if err := validateXrayConfig(ctx, binary, placeholder); err != nil {
			return failed("XRAY_INSTALL_VERIFY_FAILED", err.Error(), core.ExitVerificationFailed)
		}
		if err := atomicWrite(configPath, placeholder, 0640); err != nil {
			return failed("XRAY_INSTALL_FAILED", err.Error(), core.ExitGeneralFailure)
		}
	}
	if err := installXrayServiceFiles(ctx); err != nil {
		return failed("XRAY_SERVICE_INSTALL_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	if run := adapters.Run(ctx, "chown", "root:"+xrayServiceUser, hostPath(ctx.Env, xrayConfigDirectory), configPath); run.ExitCode != 0 {
		return commandFailed("XRAY_PERMISSION_FAILED", "chown", run)
	}
	_ = os.Chmod(configPath, 0640)
	if run := runSystemctl(ctx, "daemon-reload"); run.ExitCode != 0 {
		return commandFailed("XRAY_SERVICE_INSTALL_FAILED", "daemon_reload", run)
	}
	version := adapters.Run(ctx, binary, "version")
	if version.ExitCode != 0 {
		return commandFailed("XRAY_INSTALL_VERIFY_FAILED", "version", version)
	}

	resources.Users = mergeUnique(resources.Users, xrayServiceUser)
	resources.Packages = mergeUnique(resources.Packages, "ca-certificates", "nftables", "iproute2", "nano")
	resources.Services = mergeUnique(resources.Services, xrayServiceName, xrayRoutingServiceName)
	resources.Files = mergeUnique(resources.Files,
		binary,
		hostPath(ctx.Env, xrayShareDirectory+"/geoip.dat"),
		hostPath(ctx.Env, xrayShareDirectory+"/geosite.dat"),
		profilesPath, configPath, hostPath(ctx.Env, xrayManagedMarkerPath),
		hostPath(ctx.Env, xraySystemdServicePath),
		hostPath(ctx.Env, xrayRoutingServicePath),
		hostPath(ctx.Env, xrayRoutingScriptPath),
	)
	if err := saveManaged(ctx.Env, resources); err != nil {
		return managedStateFailure(err)
	}
	return success("Xray installed and ready for VLESS profiles", true, map[string]interface{}{
		"version": firstLine(version.Stdout), "profiles": xrayProfilesPath,
		"http_proxy": xrayHTTPProxyURL, "release_sha256": bundle.SHA256,
	})
}

func xrayOn(ctx core.Context, _ core.Request, inputs map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("XRAY_ON_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	if !xrayInstallationManaged(ctx.Env) {
		return failed("XRAY_NOT_MANAGED", "run sindri xray install first", core.ExitManagedScopeViolation)
	}
	binary := hostPath(ctx.Env, xrayBinaryPath)
	if _, err := os.Stat(binary); err != nil {
		return failed("XRAY_NOT_INSTALLED", "run sindri xray install first", core.ExitPrecheckFailed)
	}
	profiles, err := loadXrayProfiles(ctx.Env)
	if err != nil {
		return failed("XRAY_PROFILES_READ_FAILED", err.Error(), core.ExitPrecheckFailed)
	}
	if len(profiles) == 0 {
		return failed("XRAY_PROFILES_EMPTY", "run sindri xray config and add at least one VLESS link", core.ExitPrecheckFailed)
	}
	selected := strings.TrimSpace(fmt.Sprint(inputs["profile"]))
	if selected == "<nil>" {
		selected = ""
	}
	if selected == "" && len(profiles) == 1 {
		selected = profiles[0].Name
	}
	if selected == "" {
		return core.Result{
			Status: core.StatusInputRequired, Message: "Choose an Xray profile",
			Fields: []core.FieldRequirement{{
				Name: "profile", Type: core.InputChoice, Required: true,
				Prompt: "Available Xray profiles:", Values: xrayProfileNames(profiles),
			}},
			Data: map[string]interface{}{"profiles": xrayProfileNames(profiles)}, ExitCode: core.ExitInputRequired,
		}
	}
	if number, err := strconv.Atoi(selected); err == nil && number >= 1 && number <= len(profiles) {
		selected = profiles[number-1].Name
	}
	profile := findXrayProfile(profiles, selected)
	if profile == nil {
		return failed("XRAY_PROFILE_NOT_FOUND", fmt.Sprintf("profile %q was not found", selected), core.ExitInvalidCommand)
	}
	config, err := buildXrayConfig(*profile)
	if err != nil {
		return failed("XRAY_CONFIG_GENERATION_FAILED", err.Error(), core.ExitVerificationFailed)
	}
	if err := validateXrayConfig(ctx, binary, config); err != nil {
		return failed("XRAY_CONFIG_INVALID", err.Error(), core.ExitVerificationFailed)
	}
	configPath := hostPath(ctx.Env, xrayGeneratedConfig)
	if err := atomicWrite(configPath, config, 0640); err != nil {
		return failed("XRAY_CONFIG_WRITE_FAILED", err.Error(), core.ExitGeneralFailure)
	}
	if run := adapters.Run(ctx, "chown", "root:"+xrayServiceUser, configPath); run.ExitCode != 0 {
		return commandFailed("XRAY_PERMISSION_FAILED", "chown", run)
	}
	if run := runSystemctl(ctx, "enable", xrayRoutingServiceName, xrayServiceName); run.ExitCode != 0 {
		return commandFailed("XRAY_ENABLE_FAILED", "enable", run)
	}
	if run := runSystemctl(ctx, "restart", xrayRoutingServiceName); run.ExitCode != 0 {
		return commandFailed("XRAY_ROUTING_FAILED", "enable_fail_closed_routing", run)
	}
	if err := saveXrayRuntimeState(ctx.Env, true, profile.Name); err != nil {
		return xrayFailClosedResult("XRAY_STATE_WRITE_FAILED", err.Error(), profile.Name)
	}
	if run := runSystemctl(ctx, "restart", xrayServiceName); run.ExitCode != 0 {
		return xrayFailClosedResult("XRAY_START_FAILED", commandResultMessage(run), profile.Name)
	}
	if run := runSystemctl(ctx, "is-active", "--quiet", xrayRoutingServiceName); run.ExitCode != 0 {
		return xrayFailClosedResult("XRAY_ROUTING_VERIFY_FAILED", commandResultMessage(run), profile.Name)
	}
	if run := runSystemctl(ctx, "is-active", "--quiet", xrayServiceName); run.ExitCode != 0 {
		return xrayFailClosedResult("XRAY_START_VERIFY_FAILED", commandResultMessage(run), profile.Name)
	}
	info, err := waitForXrayProxy(ctx, xrayHealthAttempts, xrayHealthInterval)
	if err != nil {
		return xrayFailClosedResult("XRAY_HEALTHCHECK_FAILED", err.Error(), profile.Name)
	}
	return success("Xray transparent proxy is enabled", true, map[string]interface{}{
		"profile": profile.Name, "fail_closed": true, "host_traffic": true,
		"docker_traffic": true, "tcp": true, "udp": true, "dns": true,
		"ip": info.IP, "country": info.Country, "region": info.Region, "city": info.City, "org": info.Org,
	})
}

func xrayOff(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("XRAY_OFF_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	if !xrayInstallationManaged(ctx.Env) {
		if fileExists(hostPath(ctx.Env, xrayBinaryPath)) || fileExists(hostPath(ctx.Env, xraySystemdServicePath)) {
			return failed("XRAY_NOT_MANAGED", "refusing to change an Xray installation not owned by Sindri", core.ExitManagedScopeViolation)
		}
		return success("Xray is not installed", false, map[string]interface{}{"installed": false})
	}
	installed := false
	if _, err := os.Stat(hostPath(ctx.Env, xrayBinaryPath)); err == nil {
		installed = true
	}
	if _, err := os.Stat(hostPath(ctx.Env, xrayRoutingScriptPath)); err == nil {
		installed = true
	}
	if !installed {
		return success("Xray is not installed", false, map[string]interface{}{"installed": false})
	}
	if result := disableXray(ctx); result != nil {
		return *result
	}
	state := loadXrayRuntimeState(ctx.Env)
	if err := saveXrayRuntimeState(ctx.Env, false, state.ProfileName); err != nil {
		return managedStateFailure(err)
	}
	return success("Xray transparent proxy is disabled", true, map[string]interface{}{"fail_closed": false, "direct_connection": true})
}

func xrayStatus(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("XRAY_STATUS_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	binary := hostPath(ctx.Env, xrayBinaryPath)
	if _, err := os.Stat(binary); err != nil {
		return success("Xray is not installed", false, map[string]interface{}{"installed": false})
	}
	if !xrayInstallationManaged(ctx.Env) {
		return success("An unmanaged Xray installation is present", false, map[string]interface{}{"installed": true, "managed": false})
	}
	serviceActive := runSystemctl(ctx, "is-active", "--quiet", xrayServiceName).ExitCode == 0
	routingActive := adapters.Run(ctx, "nft", "list", "table", "inet", "sindri_xray").ExitCode == 0
	state := loadXrayRuntimeState(ctx.Env)
	profiles, profileErr := loadXrayProfiles(ctx.Env)
	profileNames := []string{}
	if profileErr == nil {
		profileNames = xrayProfileNames(profiles)
	}
	version := adapters.Run(ctx, binary, "version")
	data := map[string]interface{}{
		"installed": true, "active": serviceActive, "routing_active": routingActive,
		"fail_closed": routingActive && !serviceActive, "selected_profile": state.ProfileName,
		"profiles": profileNames, "version": firstLine(version.Stdout), "http_proxy": xrayHTTPProxyURL,
	}
	if !routingActive && (state.Enabled || serviceActive) {
		return core.Result{
			Status: core.StatusFailed, Message: "Xray fail-closed routing is missing", Data: data,
			Error: &core.ErrorInfo{Code: "XRAY_ROUTING_INACTIVE", Message: "transparent routing is not active; run sindri xray on again"}, ExitCode: core.ExitVerificationFailed,
		}
	}
	if routingActive && !serviceActive {
		return core.Result{
			Status: core.StatusFailed, Message: "Xray is down; fail-closed routing is blocking internet traffic", Data: data,
			Error: &core.ErrorInfo{Code: "XRAY_INACTIVE", Message: "Xray is not active; inspect the service logs or run sindri xray on again"}, ExitCode: core.ExitVerificationFailed,
		}
	}
	if serviceActive {
		info, err := proxyIPInfoLookup(ctx)
		if err != nil {
			data["proxy_error"] = err.Error()
			return core.Result{
				Status: core.StatusFailed, Message: "Xray is running but the proxy health check failed", Data: data,
				Error: &core.ErrorInfo{Code: "XRAY_UNHEALTHY", Message: err.Error()}, ExitCode: core.ExitVerificationFailed,
			}
		}
		data["ip"] = info.IP
		data["country"] = info.Country
	}
	return success("Xray status collected", false, data)
}

func xrayUninstall(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	if failure := requireLinuxRoot("XRAY_UNINSTALL_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	if !xrayInstallationManaged(ctx.Env) {
		if fileExists(hostPath(ctx.Env, xrayBinaryPath)) || fileExists(hostPath(ctx.Env, xraySystemdServicePath)) {
			return failed("XRAY_NOT_MANAGED", "refusing to remove an Xray installation not owned by Sindri", core.ExitManagedScopeViolation)
		}
		return success("Xray is not installed", false, map[string]interface{}{"installed": false})
	}
	for _, service := range []struct {
		name string
		unit string
	}{
		{name: xrayServiceName, unit: xraySystemdServicePath},
		{name: xrayRoutingServiceName, unit: xrayRoutingServicePath},
	} {
		if !fileExists(hostPath(ctx.Env, service.unit)) {
			continue
		}
		if run := runSystemctl(ctx, "stop", service.name); run.ExitCode != 0 {
			return commandFailed("XRAY_UNINSTALL_FAILED", "stop_"+service.name, run)
		}
		if run := runSystemctl(ctx, "disable", service.name); run.ExitCode != 0 {
			return commandFailed("XRAY_UNINSTALL_FAILED", "disable_"+service.name, run)
		}
	}
	if script := hostPath(ctx.Env, xrayRoutingScriptPath); fileExists(script) {
		if run := adapters.Run(ctx, script, "off"); run.ExitCode != 0 {
			return commandFailed("XRAY_UNINSTALL_FAILED", "remove_routing", run)
		}
	} else {
		_ = adapters.Run(ctx, "nft", "delete", "table", "inet", "sindri_xray")
		removeXrayPolicyRouting(ctx)
	}
	files := []string{
		hostPath(ctx.Env, xraySystemdServicePath),
		hostPath(ctx.Env, xrayRoutingServicePath),
		hostPath(ctx.Env, xrayRoutingScriptPath),
		hostPath(ctx.Env, xrayBinaryPath),
	}
	for _, file := range files {
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			return failed("XRAY_UNINSTALL_FAILED", err.Error(), core.ExitGeneralFailure)
		}
	}
	for _, directory := range []string{xrayConfigDirectory, xrayProfilesDirectory, xrayShareDirectory, xrayRuntimeDirectory, "/var/log/xray"} {
		if _, err := safeRemoveManaged(hostPath(ctx.Env, directory)); err != nil {
			return failed("XRAY_UNINSTALL_FAILED", directory+": "+err.Error(), core.ExitGeneralFailure)
		}
	}
	if run := adapters.Run(ctx, "id", "-u", xrayServiceUser); run.ExitCode == 0 {
		if run := adapters.Run(ctx, "userdel", xrayServiceUser); run.ExitCode != 0 {
			return commandFailed("XRAY_UNINSTALL_FAILED", "remove_user", run)
		}
	}
	if run := adapters.Run(ctx, "getent", "group", xrayServiceUser); run.ExitCode == 0 {
		if run := adapters.Run(ctx, "groupdel", xrayServiceUser); run.ExitCode != 0 {
			return commandFailed("XRAY_UNINSTALL_FAILED", "remove_group", run)
		}
	}
	_ = runSystemctl(ctx, "daemon-reload")
	if fileExists(hostPath(ctx.Env, xrayBinaryPath)) || adapters.Run(ctx, "nft", "list", "table", "inet", "sindri_xray").ExitCode == 0 {
		return failed("XRAY_UNINSTALL_VERIFY_FAILED", "Xray binary or routing table is still present", core.ExitVerificationFailed)
	}
	resources := loadManaged(ctx.Env)
	resources.Users = removeString(resources.Users, xrayServiceUser)
	resources.Services = removeString(removeString(resources.Services, xrayServiceName), xrayRoutingServiceName)
	for _, file := range files {
		resources.Files = removeString(resources.Files, file)
	}
	for _, file := range []string{
		hostPath(ctx.Env, xrayShareDirectory+"/geoip.dat"), hostPath(ctx.Env, xrayShareDirectory+"/geosite.dat"),
		hostPath(ctx.Env, xrayProfilesPath), hostPath(ctx.Env, xrayManagedMarkerPath), hostPath(ctx.Env, xrayGeneratedConfig), hostPath(ctx.Env, xrayRuntimeStatePath),
	} {
		resources.Files = removeString(resources.Files, file)
	}
	if err := saveManaged(ctx.Env, resources); err != nil {
		return managedStateFailure(err)
	}
	return success("Xray service, profiles, configuration and routing rules removed", true, nil)
}

func disableXray(ctx core.Context) *core.Result {
	if run := runSystemctl(ctx, "disable", xrayServiceName); run.ExitCode != 0 {
		result := commandFailed("XRAY_OFF_FAILED", "disable_service", run)
		return &result
	}
	if run := runSystemctl(ctx, "stop", xrayServiceName); run.ExitCode != 0 {
		result := commandFailed("XRAY_OFF_FAILED", "stop_service", run)
		return &result
	}
	if run := runSystemctl(ctx, "disable", xrayRoutingServiceName); run.ExitCode != 0 {
		result := commandFailed("XRAY_OFF_FAILED", "disable_routing", run)
		return &result
	}
	if run := runSystemctl(ctx, "stop", xrayRoutingServiceName); run.ExitCode != 0 {
		result := commandFailed("XRAY_OFF_FAILED", "stop_routing", run)
		return &result
	}
	if script := hostPath(ctx.Env, xrayRoutingScriptPath); fileExists(script) {
		if run := adapters.Run(ctx, script, "off"); run.ExitCode != 0 {
			result := commandFailed("XRAY_OFF_FAILED", "remove_routing", run)
			return &result
		}
	}
	if adapters.Run(ctx, "nft", "list", "table", "inet", "sindri_xray").ExitCode == 0 {
		result := failed("XRAY_OFF_VERIFY_FAILED", "Sindri Xray nftables table is still active", core.ExitVerificationFailed)
		return &result
	}
	return nil
}

func waitForXrayProxy(ctx core.Context, attempts int, interval time.Duration) (proxyIPInfo, error) {
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		lookupContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		info, err := proxyIPInfoLookup(core.Context{Context: lookupContext, Env: ctx.Env, Log: ctx.Log})
		cancel()
		if err == nil {
			return info, nil
		}
		lastErr = err
		if ctx.Log != nil {
			ctx.Log.Write("xray_health attempt=%d/%d error=%s", attempt, attempts, err)
		}
		if attempt < attempts {
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return proxyIPInfo{}, ctx.Err()
			case <-timer.C:
			}
		}
	}
	return proxyIPInfo{}, lastErr
}

func xrayFailClosedResult(code, message, profile string) core.Result {
	return core.Result{
		Status: core.StatusFailed, Changed: true, Message: "Xray failed; internet traffic remains blocked by fail-closed routing",
		Data:  map[string]interface{}{"profile": profile, "fail_closed": true, "routing_active": true},
		Error: &core.ErrorInfo{Code: code, Message: message}, ExitCode: core.ExitVerificationFailed,
	}
}

func installXrayServiceFiles(ctx core.Context) error {
	xrayService := `[Unit]
Description=Sindri Xray transparent proxy
Documentation=https://xtls.github.io/
Wants=network-online.target
After=network-online.target sindri-xray-routing.service
Requires=sindri-xray-routing.service

[Service]
Type=simple
User=sindri-xray
Group=sindri-xray
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Environment=XRAY_LOCATION_ASSET=/usr/local/share/xray
ExecStartPre=/usr/local/bin/xray run -test -config /etc/xray/config.json
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=always
RestartSec=2s
LimitNOFILE=1048576
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
`
	routingService := `[Unit]
Description=Sindri fail-closed Xray transparent routing
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target network-online.target docker.service xray.service shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/lib/sindri/xray-routing on
ExecStop=/usr/local/lib/sindri/xray-routing off

[Install]
WantedBy=network-pre.target
`
	if err := atomicWrite(hostPath(ctx.Env, xraySystemdServicePath), []byte(xrayService), 0644); err != nil {
		return err
	}
	if err := atomicWrite(hostPath(ctx.Env, xrayRoutingServicePath), []byte(routingService), 0644); err != nil {
		return err
	}
	return atomicWrite(hostPath(ctx.Env, xrayRoutingScriptPath), []byte(xrayRoutingScript()), 0755)
}

func xrayRoutingScript() string {
	return `#!/bin/sh
set -eu

remove_rules() {
  nft delete table inet sindri_xray 2>/dev/null || true
  ip rule del priority 10030 2>/dev/null || true
  ip route flush table 10030 2>/dev/null || true
  if [ -f /proc/net/if_inet6 ]; then
    ip -6 rule del priority 10031 2>/dev/null || true
    ip -6 route flush table 10031 2>/dev/null || true
  fi
}

case "${1:-}" in
  on)
    remove_rules
    xray_uid=$(id -u sindri-xray)
    ip rule add priority 10030 fwmark 0x1eaf table 10030
    ip route add local 0.0.0.0/0 dev lo table 10030
    if [ -f /proc/net/if_inet6 ]; then
      ip -6 rule add priority 10031 fwmark 0x1eaf table 10031
      ip -6 route add local ::/0 dev lo table 10031
    fi
    if ! nft -f - <<EOF
table inet sindri_xray {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    ct direction reply return
    meta mark 0xff return
    meta mark 0x1eaf meta nfproto ipv4 meta l4proto { tcp, udp } tproxy ip to 127.0.0.1:12345 accept
    meta mark 0x1eaf meta nfproto ipv6 meta l4proto { tcp, udp } tproxy ip6 to [::1]:12346 accept
    fib daddr type local return
    ip daddr { 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } return
    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } meta l4proto tcp return
    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } meta l4proto udp udp dport != 53 return
    ip6 daddr { ::1, fe80::/10, ff00::/8 } return
    ip6 daddr fc00::/7 meta l4proto tcp return
    ip6 daddr fc00::/7 meta l4proto udp udp dport != 53 return
    meta nfproto ipv4 meta l4proto { tcp, udp } meta mark set 0x1eaf tproxy ip to 127.0.0.1:12345 accept
    meta nfproto ipv6 meta l4proto { tcp, udp } meta mark set 0x1eaf tproxy ip6 to [::1]:12346 accept
  }

  chain output {
    type route hook output priority mangle; policy accept;
    ct direction reply return
    meta skuid $xray_uid return
    ip daddr { 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } return
    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } meta l4proto tcp return
    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } meta l4proto udp udp dport != 53 return
    ip6 daddr { ::1, fe80::/10, ff00::/8 } return
    ip6 daddr fc00::/7 meta l4proto tcp return
    ip6 daddr fc00::/7 meta l4proto udp udp dport != 53 return
    meta mark 0xff return
    meta l4proto { tcp, udp } meta mark set 0x1eaf accept
  }
}
EOF
    then
      remove_rules
      exit 1
    fi
    ;;
  off)
    remove_rules
    ;;
  status)
    nft list table inet sindri_xray >/dev/null
    ;;
  *)
    echo "usage: $0 on|off|status" >&2
    exit 2
    ;;
esac
`
}

func removeXrayPolicyRouting(ctx core.Context) {
	_ = adapters.Run(ctx, "ip", "rule", "del", "priority", xrayRoutingRuleIPv4)
	_ = adapters.Run(ctx, "ip", "route", "flush", "table", xrayRoutingTableIPv4)
	_ = adapters.Run(ctx, "ip", "-6", "rule", "del", "priority", xrayRoutingRuleIPv6)
	_ = adapters.Run(ctx, "ip", "-6", "route", "flush", "table", xrayRoutingTableIPv6)
}

func downloadLatestXrayRelease(ctx context.Context) (xrayReleaseBundle, error) {
	client := &http.Client{
		Timeout: xrayReleaseTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 8 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("Xray download redirected away from HTTPS")
			}
			return nil
		},
	}
	digestURL := xrayReleaseBaseURL + "/" + xrayReleaseArchive + ".dgst"
	archiveURL := xrayReleaseBaseURL + "/" + xrayReleaseArchive
	before, err := downloadXrayReleaseAsset(ctx, client, digestURL, 1024*1024)
	if err != nil {
		return xrayReleaseBundle{}, fmt.Errorf("download digest: %w", err)
	}
	expected, err := parseXrayReleaseSHA256(before)
	if err != nil {
		return xrayReleaseBundle{}, err
	}
	archive, err := downloadXrayReleaseAsset(ctx, client, archiveURL, xrayReleaseMaxBytes)
	if err != nil {
		return xrayReleaseBundle{}, fmt.Errorf("download archive: %w", err)
	}
	after, err := downloadXrayReleaseAsset(ctx, client, digestURL, 1024*1024)
	if err != nil {
		return xrayReleaseBundle{}, fmt.Errorf("recheck digest: %w", err)
	}
	afterHash, err := parseXrayReleaseSHA256(after)
	if err != nil || afterHash != expected {
		return xrayReleaseBundle{}, errors.New("Xray release changed during download; retry the command")
	}
	sum := sha256.Sum256(archive)
	actual := hex.EncodeToString(sum[:])
	if actual != expected {
		return xrayReleaseBundle{}, fmt.Errorf("Xray archive SHA-256 mismatch: expected %s, got %s", expected, actual)
	}
	files, err := extractXrayReleaseFiles(archive)
	if err != nil {
		return xrayReleaseBundle{}, err
	}
	return xrayReleaseBundle{Files: files, SHA256: actual}, nil
}

func downloadXrayReleaseAsset(ctx context.Context, client *http.Client, address string, maximum int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("User-Agent", "Sindri xray-install")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	if response.ContentLength > maximum {
		return nil, errors.New("download is larger than the configured limit")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maximum {
		return nil, errors.New("download is larger than the configured limit")
	}
	return body, nil
}

func parseXrayReleaseSHA256(body []byte) (string, error) {
	match := xrayReleaseSHA256.FindSubmatch(body)
	if len(match) != 2 {
		return "", errors.New("Xray digest does not contain SHA256")
	}
	return strings.ToLower(string(match[1])), nil
}

func extractXrayReleaseFiles(archive []byte) (map[string][]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("open Xray archive: %w", err)
	}
	wanted := map[string]int64{"xray": 128 * 1024 * 1024, "geoip.dat": 256 * 1024 * 1024, "geosite.dat": 256 * 1024 * 1024}
	files := map[string][]byte{}
	for _, item := range reader.File {
		name := filepath.Base(filepath.ToSlash(item.Name))
		limit, ok := wanted[name]
		if !ok || item.FileInfo().IsDir() {
			continue
		}
		if item.UncompressedSize64 > uint64(limit) {
			return nil, fmt.Errorf("Xray archive member %s is too large", name)
		}
		file, err := item.Open()
		if err != nil {
			return nil, err
		}
		body, readErr := io.ReadAll(io.LimitReader(file, limit+1))
		closeErr := file.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if int64(len(body)) > limit {
			return nil, fmt.Errorf("Xray archive member %s is too large", name)
		}
		files[name] = body
	}
	for name := range wanted {
		if len(files[name]) == 0 {
			return nil, fmt.Errorf("Xray archive is missing %s", name)
		}
	}
	return files, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
