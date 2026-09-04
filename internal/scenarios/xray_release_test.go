package scenarios

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseAndExtractXrayRelease(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for name, body := range map[string]string{"xray": "binary", "geoip.dat": "geoip", "geosite.dat": "geosite"} {
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(archive.Bytes())
	wantHash := hex.EncodeToString(sum[:])
	if got, err := parseXrayReleaseSHA256([]byte("MD5= ignored\nSHA1= ignored\nSHA2-256= " + wantHash + "\n")); err != nil || got != wantHash {
		t.Fatalf("parsed checksum = %q, %v", got, err)
	}
	files, err := extractXrayReleaseFiles(archive.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(files["xray"]) != "binary" || string(files["geoip.dat"]) != "geoip" || string(files["geosite.dat"]) != "geosite" {
		t.Fatalf("extracted files = %#v", files)
	}
}

func TestGeneratedConfigAgainstOfficialXrayRelease(t *testing.T) {
	if os.Getenv("SINDRI_XRAY_LIVE_TEST") != "1" {
		t.Skip("set SINDRI_XRAY_LIVE_TEST=1 to validate against the current official Xray release")
	}
	bundle, err := downloadLatestXrayRelease(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	binary := filepath.Join(directory, "xray")
	if err := os.WriteFile(binary, bundle.Files["xray"], 0755); err != nil {
		t.Fatal(err)
	}
	profile, err := parseVLESSProfile(testVLESSLink("Live validation"))
	if err != nil {
		t.Fatal(err)
	}
	config, err := buildXrayConfig(profile)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "config.json")
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "run", "-test", "-config", configPath)
	command.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+directory)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("official Xray rejected generated config: %v\n%s", err, strings.TrimSpace(string(output)))
	}
}

func TestRoutingScriptInIsolatedNetworkNamespace(t *testing.T) {
	if os.Getenv("SINDRI_XRAY_ROUTING_TEST") != "1" {
		t.Skip("set SINDRI_XRAY_ROUTING_TEST=1 inside an isolated network namespace")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("routing integration test requires root Linux")
	}
	if output, err := exec.Command("useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", xrayServiceUser).CombinedOutput(); err != nil {
		t.Fatalf("create test Xray user: %v: %s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("userdel", xrayServiceUser).Run() })
	script := filepath.Join(t.TempDir(), "xray-routing")
	if err := os.WriteFile(script, []byte(xrayRoutingScript()), 0755); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"on", "status", "off"} {
		if output, err := exec.Command(script, action).CombinedOutput(); err != nil {
			t.Fatalf("routing %s failed: %v\n%s", action, err, output)
		}
	}
	if err := exec.Command("nft", "list", "table", "inet", "sindri_xray").Run(); err == nil {
		t.Fatal("routing table remains after off")
	}
}
