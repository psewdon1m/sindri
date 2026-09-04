package scenarios

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"sindri/internal/adapters"
	"sindri/internal/core"
)

func TestParseVLESSProfileSupportsRealityVisionAndDecodedName(t *testing.T) {
	link := testVLESSLink("%F0%9F%87%B3%F0%9F%87%B1%20-%20Netherlands%20-%20Smart")
	profile, err := parseVLESSProfile(link)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Name != "🇳🇱 - Netherlands - Smart" || profile.Address != "node.example.test" || profile.Port != 2443 {
		t.Fatalf("parsed profile = %#v", profile)
	}
	if profile.Password != strings.Repeat("A", 43) || profile.ShortID != "3b9ca2bc82d2c603" || profile.Fingerprint != "firefox" {
		t.Fatalf("REALITY settings were not parsed: %#v", profile)
	}
}

func TestParseVLESSProfilesSortsAndRejectsDuplicateNames(t *testing.T) {
	profiles, err := parseVLESSProfiles(testVLESSLink("Zulu") + "\n" + testVLESSLink("Alpha") + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 || profiles[0].Name != "Alpha" || profiles[1].Name != "Zulu" {
		t.Fatalf("profiles were not sorted: %#v", profiles)
	}
	if _, err := parseVLESSProfiles(testVLESSLink("Same") + "\n" + testVLESSLink("Same")); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate profile error = %v", err)
	}
}

func TestBuildXrayConfigUsesCurrentRealityFieldsAndDualStackTProxy(t *testing.T) {
	profile, err := parseVLESSProfile(testVLESSLink("Example"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := buildXrayConfig(profile)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]interface{}
	if err := json.Unmarshal(body, &config); err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, expected := range []string{
		`"listen": "127.0.0.1"`, `"port": 18080`,
		`"listen": "0.0.0.0"`, `"port": 12345`,
		`"listen": "::"`, `"port": 12346`,
		`"protocol": "dokodemo-door"`, `"tproxy": "tproxy"`,
		`"password": "` + strings.Repeat("A", 43) + `"`, `"mark": 255`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("generated config is missing %s:\n%s", expected, text)
		}
	}
	if strings.Contains(text, `"publicKey"`) || strings.Contains(text, profile.URI) {
		t.Fatalf("generated config contains a legacy field or source URI:\n%s", text)
	}
}

func TestXrayRoutingScriptIsScopedAndFailClosed(t *testing.T) {
	script := xrayRoutingScript()
	for _, expected := range []string{
		"table inet sindri_xray", "chain prerouting", "chain output",
		"ct direction reply return", "meta skuid $xray_uid return",
		"tproxy ip to 127.0.0.1:12345", "tproxy ip6 to [::1]:12346",
		"ip rule add priority 10030", "ip -6 rule add priority 10031",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("routing script is missing %q", expected)
		}
	}
	if strings.Contains(script, "flush ruleset") {
		t.Fatal("routing script must not flush unrelated nftables rules")
	}
}

func TestXrayConfigEditorAcceptsMultipleLinksAndRollsBackInvalidEdits(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("Xray editor test requires a root Linux test container")
	}
	env := testEnvironment(t)
	binary := hostPath(env, xrayBinaryPath)
	if err := os.MkdirAll(filepath.Dir(binary), 0755); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, binary, "#!/bin/sh\nexit 0\n")
	writeFile(t, hostPath(env, xrayManagedMarkerPath), "{}\n")
	fakeBin := t.TempDir()
	writeExecutable(t, filepath.Join(fakeBin, "nano"), "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+"/usr/bin:/bin")
	validProfiles := testVLESSLink("Netherlands") + "\n" + testVLESSLink("Japan") + "\n"
	originalEditor := xrayConfigEditor
	xrayConfigEditor = func(_ context.Context, _ string, args ...string) adapters.CommandResult {
		if err := os.WriteFile(args[0], []byte(validProfiles), 0600); err != nil {
			return adapters.CommandResult{ExitCode: 1, Stderr: err.Error()}
		}
		return adapters.CommandResult{}
	}
	t.Cleanup(func() { xrayConfigEditor = originalEditor })

	result := xrayConfigEdit(core.Context{Context: context.Background(), Env: env}, core.Request{Source: "cli"}, nil)
	assertResult(t, "xray config edit", result, core.StatusSuccess)
	if result.Data["count"] != 2 {
		t.Fatalf("profile count = %#v", result.Data["count"])
	}

	xrayConfigEditor = func(_ context.Context, _ string, args ...string) adapters.CommandResult {
		if err := os.WriteFile(args[0], []byte("not-vless\n"), 0600); err != nil {
			return adapters.CommandResult{ExitCode: 1, Stderr: err.Error()}
		}
		return adapters.CommandResult{}
	}
	failed := xrayConfigEdit(core.Context{Context: context.Background(), Env: env}, core.Request{Source: "cli"}, nil)
	assertResult(t, "invalid xray config edit", failed, core.StatusFailed)
	restored, err := os.ReadFile(hostPath(env, xrayProfilesPath))
	if err != nil || string(restored) != validProfiles {
		t.Fatalf("valid profiles were not restored: %v, %q", err, restored)
	}
}

func testVLESSLink(name string) string {
	return "vless://11111111-2222-4333-8444-555555555555@node.example.test:2443" +
		"?encryption=none&flow=xtls-rprx-vision&security=reality&sni=cover.example.test" +
		"&fp=firefox&pbk=" + strings.Repeat("A", 43) + "&sid=3b9ca2bc82d2c603&type=tcp&headerType=none#" + name
}
