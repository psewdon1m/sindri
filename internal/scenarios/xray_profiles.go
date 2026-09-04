package scenarios

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"sindri/internal/adapters"
	"sindri/internal/core"
)

const (
	xrayBinaryPath         = "/usr/local/bin/xray"
	xrayShareDirectory     = "/usr/local/share/xray"
	xrayConfigDirectory    = "/etc/xray"
	xrayGeneratedConfig    = "/etc/xray/config.json"
	xrayProfilesDirectory  = "/etc/sindri/xray"
	xrayProfilesPath       = "/etc/sindri/xray/profiles.vless"
	xrayManagedMarkerPath  = "/etc/sindri/xray/managed.json"
	xrayRuntimeDirectory   = "/var/lib/sindri/xray"
	xrayRuntimeStatePath   = "/var/lib/sindri/xray/state.json"
	xraySystemdServicePath = "/etc/systemd/system/xray.service"
	xrayRoutingServicePath = "/etc/systemd/system/sindri-xray-routing.service"
	xrayRoutingScriptPath  = "/usr/local/lib/sindri/xray-routing"
	xrayServiceName        = "xray.service"
	xrayRoutingServiceName = "sindri-xray-routing.service"
	xrayServiceUser        = "sindri-xray"
	xrayTransparentPortV4  = 12345
	xrayTransparentPortV6  = 12346
)

var (
	xrayUUIDPattern      = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	xrayPublicKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{40,64}$`)
	xrayShortIDPattern   = regexp.MustCompile(`(?i)^[0-9a-f]{0,16}$`)
	xrayConfigEditor     = adapters.RunInteractive
	xrayConfigEditSteps  = []core.StepSpec{
		{ID: "precheck", Name: "Verify the Xray installation"},
		{ID: "edit", Name: "Edit the VLESS profile list"},
		{ID: "parse", Name: "Parse VLESS profiles"},
		{ID: "verify", Name: "Validate generated Xray configurations"},
	}
)

type xrayProfile struct {
	Name        string
	URI         string
	Address     string
	Port        int
	UserID      string
	Encryption  string
	Flow        string
	Security    string
	ServerName  string
	Fingerprint string
	Password    string
	ShortID     string
	SpiderX     string
	Network     string
	HeaderType  string
}

type xrayRuntimeState struct {
	Schema      int    `json:"schema"`
	Enabled     bool   `json:"enabled"`
	ProfileName string `json:"profile_name,omitempty"`
	UpdatedAt   string `json:"updated_at"`
}

func xrayConfigEdit(ctx core.Context, req core.Request, _ map[string]interface{}) core.Result {
	if req.Source == "machine" {
		return xrayConfigFailure("XRAY_CONFIG_EDITOR_CLI_ONLY", "the nano editor is available only through the interactive CLI", "precheck", core.ExitPrecheckFailed)
	}
	if failure := requireLinuxRoot("XRAY_CONFIG_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	if !xrayInstallationManaged(ctx.Env) {
		return xrayConfigFailure("XRAY_NOT_MANAGED", "run sindri xray install first", "precheck", core.ExitManagedScopeViolation)
	}
	binary := hostPath(ctx.Env, xrayBinaryPath)
	if info, err := os.Stat(binary); err != nil || !info.Mode().IsRegular() {
		return xrayConfigFailure("XRAY_NOT_INSTALLED", "run sindri xray install first", "precheck", core.ExitPrecheckFailed)
	}
	if !adapters.CommandExists("nano") {
		return xrayConfigFailure("NANO_NOT_FOUND", "nano is not installed; run sindri mir or install nano", "edit", core.ExitPrecheckFailed)
	}

	profilesPath := hostPath(ctx.Env, xrayProfilesPath)
	if err := os.MkdirAll(filepath.Dir(profilesPath), 0700); err != nil {
		return xrayConfigFailure("XRAY_CONFIG_CREATE_FAILED", err.Error(), "precheck", core.ExitGeneralFailure)
	}
	before, err := os.ReadFile(profilesPath)
	if os.IsNotExist(err) {
		before = []byte("# One VLESS URL per line. Lines beginning with # are ignored.\n")
		if err := atomicWrite(profilesPath, before, 0600); err != nil {
			return xrayConfigFailure("XRAY_CONFIG_CREATE_FAILED", err.Error(), "precheck", core.ExitGeneralFailure)
		}
	} else if err != nil {
		return xrayConfigFailure("XRAY_CONFIG_READ_FAILED", err.Error(), "precheck", core.ExitPrecheckFailed)
	}
	beforeHash := sha256.Sum256(before)

	run := xrayConfigEditor(ctx, "nano", profilesPath)
	if run.ExitCode != 0 {
		failure := commandFailed("XRAY_CONFIG_EDITOR_FAILED", "nano", run)
		failure.Message = "Xray profile editor failed"
		failure.Steps = failedSteps(xrayConfigEditSteps, "edit")
		return failure
	}
	_ = os.Chmod(profilesPath, 0600)
	after, err := os.ReadFile(profilesPath)
	if err != nil {
		return xrayConfigFailure("XRAY_CONFIG_READ_FAILED", err.Error(), "parse", core.ExitVerificationFailed)
	}
	profiles, err := parseVLESSProfiles(string(after))
	if err != nil {
		_ = atomicWrite(profilesPath, before, 0600)
		return xrayConfigFailure("XRAY_PROFILE_INVALID", err.Error(), "parse", core.ExitInvalidCommand)
	}
	state := loadXrayRuntimeState(ctx.Env)
	if state.Enabled && state.ProfileName != "" && findXrayProfile(profiles, state.ProfileName) == nil {
		_ = atomicWrite(profilesPath, before, 0600)
		return xrayConfigFailure("XRAY_ACTIVE_PROFILE_REMOVED", "turn Xray off or retain the active profile "+state.ProfileName, "verify", core.ExitPrecheckFailed)
	}
	for _, profile := range profiles {
		config, err := buildXrayConfig(profile)
		if err != nil {
			_ = atomicWrite(profilesPath, before, 0600)
			return xrayConfigFailure("XRAY_CONFIG_GENERATION_FAILED", err.Error(), "verify", core.ExitVerificationFailed)
		}
		if err := validateXrayConfig(ctx, binary, config); err != nil {
			_ = atomicWrite(profilesPath, before, 0600)
			return xrayConfigFailure("XRAY_CONFIG_INVALID", profile.Name+": "+err.Error(), "verify", core.ExitVerificationFailed)
		}
	}
	afterHash := sha256.Sum256(after)
	names := xrayProfileNames(profiles)
	return success("Xray VLESS profiles saved", beforeHash != afterHash, map[string]interface{}{
		"count": len(names), "profiles": names, "path": xrayProfilesPath,
	})
}

func parseVLESSProfiles(body string) ([]xrayProfile, error) {
	profiles := []xrayProfile{}
	seen := map[string]bool{}
	for lineNumber, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		profile, err := parseVLESSProfile(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		if seen[profile.Name] {
			return nil, fmt.Errorf("line %d: duplicate profile name %q", lineNumber+1, profile.Name)
		}
		seen[profile.Name] = true
		profiles = append(profiles, profile)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })
	return profiles, nil
}

func parseVLESSProfile(value string) (xrayProfile, error) {
	parsed, err := url.Parse(value)
	if err != nil || !strings.EqualFold(parsed.Scheme, "vless") {
		return xrayProfile{}, errors.New("a vless:// URL is required")
	}
	if parsed.User == nil || parsed.User.Username() == "" {
		return xrayProfile{}, errors.New("VLESS user ID is missing")
	}
	userID := parsed.User.Username()
	if !xrayUUIDPattern.MatchString(userID) {
		return xrayProfile{}, errors.New("VLESS user ID must be a canonical UUID")
	}
	if _, passwordSet := parsed.User.Password(); passwordSet {
		return xrayProfile{}, errors.New("VLESS URL must not contain a user password")
	}
	address := strings.TrimSpace(parsed.Hostname())
	if address == "" {
		return xrayProfile{}, errors.New("VLESS server address is missing")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return xrayProfile{}, errors.New("VLESS server port is invalid")
	}
	query := parsed.Query()
	encryption := query.Get("encryption")
	flow := query.Get("flow")
	security := query.Get("security")
	network := query.Get("type")
	headerType := query.Get("headerType")
	serverName := strings.TrimSpace(query.Get("sni"))
	fingerprint := strings.TrimSpace(query.Get("fp"))
	publicKey := strings.TrimSpace(query.Get("pbk"))
	shortID := strings.TrimSpace(query.Get("sid"))
	if encryption != "none" {
		return xrayProfile{}, errors.New(`only encryption=none is currently supported`)
	}
	if flow != "xtls-rprx-vision" && flow != "xtls-rprx-vision-udp443" {
		return xrayProfile{}, errors.New("only XTLS Vision flow is currently supported")
	}
	if security != "reality" {
		return xrayProfile{}, errors.New("only security=reality is currently supported")
	}
	if network != "tcp" {
		return xrayProfile{}, errors.New("only type=tcp is currently supported")
	}
	if headerType != "" && headerType != "none" {
		return xrayProfile{}, errors.New("only headerType=none is currently supported")
	}
	if net.ParseIP(serverName) == nil && !validDNSName(serverName) {
		return xrayProfile{}, errors.New("a valid REALITY sni value is required")
	}
	if fingerprint == "" {
		return xrayProfile{}, errors.New("REALITY fingerprint is missing")
	}
	if !xrayPublicKeyPattern.MatchString(publicKey) {
		return xrayProfile{}, errors.New("REALITY public key is invalid")
	}
	if !xrayShortIDPattern.MatchString(shortID) || len(shortID)%2 != 0 {
		return xrayProfile{}, errors.New("REALITY short ID must contain an even number of hexadecimal characters")
	}
	name, err := url.PathUnescape(parsed.EscapedFragment())
	if err != nil {
		return xrayProfile{}, errors.New("profile name is not valid URL encoding")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = net.JoinHostPort(address, strconv.Itoa(port))
	}
	if len([]rune(name)) > 120 || strings.ContainsAny(name, "\r\n\x00") {
		return xrayProfile{}, errors.New("profile name is invalid")
	}
	return xrayProfile{
		Name: name, URI: value, Address: address, Port: port, UserID: userID,
		Encryption: encryption, Flow: flow, Security: security, ServerName: serverName,
		Fingerprint: fingerprint, Password: publicKey, ShortID: shortID,
		SpiderX: query.Get("spx"), Network: network, HeaderType: headerType,
	}, nil
}

func validDNSName(value string) bool {
	if len(value) < 1 || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, char := range label {
			if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func buildXrayConfig(profile xrayProfile) ([]byte, error) {
	reality := map[string]interface{}{
		"serverName": profile.ServerName, "fingerprint": profile.Fingerprint,
		"password": profile.Password, "shortId": profile.ShortID,
	}
	if profile.SpiderX != "" {
		reality["spiderX"] = profile.SpiderX
	}
	config := map[string]interface{}{
		"log": map[string]interface{}{"loglevel": "warning"},
		"inbounds": []interface{}{
			map[string]interface{}{
				"tag": "http-in", "listen": "127.0.0.1", "port": 18080,
				"protocol": "http", "settings": map[string]interface{}{},
			},
			transparentXrayInbound("tproxy-v4", "0.0.0.0", xrayTransparentPortV4),
			transparentXrayInbound("tproxy-v6", "::", xrayTransparentPortV6),
		},
		"outbounds": []interface{}{
			map[string]interface{}{
				"tag": "proxy", "protocol": "vless",
				"settings": map[string]interface{}{
					"address": profile.Address, "port": profile.Port, "id": profile.UserID,
					"encryption": profile.Encryption, "flow": profile.Flow,
				},
				"streamSettings": map[string]interface{}{
					"network": profile.Network, "security": profile.Security,
					"realitySettings": reality,
					"tcpSettings":     map[string]interface{}{"header": map[string]interface{}{"type": "none"}},
					"sockopt":         map[string]interface{}{"mark": 255},
				},
			},
			map[string]interface{}{"tag": "blocked", "protocol": "blackhole"},
		},
		"routing": map[string]interface{}{
			"domainStrategy": "IPIfNonMatch",
			"rules": []interface{}{
				map[string]interface{}{
					"type": "field", "inboundTag": []string{"http-in", "tproxy-v4", "tproxy-v6"}, "outboundTag": "proxy",
				},
			},
		},
	}
	body, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func transparentXrayInbound(tag, listen string, port int) map[string]interface{} {
	return map[string]interface{}{
		"tag": tag, "listen": listen, "port": port, "protocol": "dokodemo-door",
		"settings":       map[string]interface{}{"network": "tcp,udp", "followRedirect": true},
		"sniffing":       map[string]interface{}{"enabled": true, "destOverride": []string{"http", "tls", "quic"}},
		"streamSettings": map[string]interface{}{"sockopt": map[string]interface{}{"tproxy": "tproxy"}},
	}
}

func validateXrayConfig(ctx core.Context, binary string, config []byte) error {
	directory := hostPath(ctx.Env, xrayConfigDirectory)
	if err := os.MkdirAll(directory, 0750); err != nil {
		return err
	}
	temp, err := os.CreateTemp(directory, ".sindri-xray-*.json")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err := temp.Chmod(0600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(config); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	run := adapters.RunWithTimeout(ctx, serviceCommandTimeout, binary, "run", "-test", "-config", name)
	if run.ExitCode != 0 {
		message := commandResultMessage(run)
		if message == "" {
			message = "Xray rejected the generated configuration"
		}
		return errors.New(message)
	}
	return nil
}

func loadXrayProfiles(env core.Environment) ([]xrayProfile, error) {
	body, err := os.ReadFile(hostPath(env, xrayProfilesPath))
	if err != nil {
		return nil, err
	}
	return parseVLESSProfiles(string(body))
}

func xrayProfileNames(profiles []xrayProfile) []string {
	names := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		names = append(names, profile.Name)
	}
	return names
}

func findXrayProfile(profiles []xrayProfile, name string) *xrayProfile {
	for index := range profiles {
		if profiles[index].Name == name {
			return &profiles[index]
		}
	}
	return nil
}

func loadXrayRuntimeState(env core.Environment) xrayRuntimeState {
	var state xrayRuntimeState
	body, err := os.ReadFile(hostPath(env, xrayRuntimeStatePath))
	if err == nil {
		_ = json.Unmarshal(body, &state)
	}
	return state
}

func saveXrayRuntimeState(env core.Environment, enabled bool, profileName string) error {
	state := xrayRuntimeState{Schema: 1, Enabled: enabled, ProfileName: profileName, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(hostPath(env, xrayRuntimeStatePath), append(body, '\n'), 0600)
}

func xrayInstallationManaged(env core.Environment) bool {
	return fileExists(hostPath(env, xrayManagedMarkerPath))
}

func xrayProfilesSHA256(profiles []xrayProfile) string {
	hasher := sha256.New()
	for _, profile := range profiles {
		_, _ = hasher.Write([]byte(profile.URI))
		_, _ = hasher.Write([]byte{0})
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func xrayConfigFailure(code, message, step string, exitCode int) core.Result {
	return core.Result{
		Status: core.StatusFailed, Message: "Xray profile configuration failed",
		Error: &core.ErrorInfo{Code: code, Message: message}, Steps: failedSteps(xrayConfigEditSteps, step), ExitCode: exitCode,
	}
}
