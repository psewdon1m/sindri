package scenarios

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"sindri/internal/core"
)

func TestDownloadGeoDataAssetsVerifiesStableChecksums(t *testing.T) {
	bodies := map[string]string{
		"geosite.dat": "verified geosite data\n",
		"geoip.dat":   "verified geoip data\n",
	}
	server := newGeoDataTestServer(t, bodies, nil)
	defer server.Close()

	assets, err := downloadGeoDataAssets(context.Background(), server.Client(), server.URL, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != len(geoDataNames) {
		t.Fatalf("downloaded %d assets, want %d", len(assets), len(geoDataNames))
	}
	for _, asset := range assets {
		body, err := os.ReadFile(asset.Path)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != bodies[asset.Name] {
			t.Fatalf("%s body = %q", asset.Name, body)
		}
		if asset.SHA256 != sha256String(bodies[asset.Name]) {
			t.Fatalf("%s hash = %q", asset.Name, asset.SHA256)
		}
	}
}

func TestDownloadGeoDataAssetsRejectsChecksumMismatch(t *testing.T) {
	bodies := map[string]string{"geosite.dat": "site", "geoip.dat": "ip"}
	overrides := map[string]string{"geosite.dat": strings.Repeat("0", 64)}
	server := newGeoDataTestServer(t, bodies, overrides)
	defer server.Close()

	_, err := downloadGeoDataAssets(context.Background(), server.Client(), server.URL, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %v, want checksum mismatch", err)
	}
}

func TestDownloadGeoDataAssetsRejectsChangingRelease(t *testing.T) {
	bodies := map[string]string{"geosite.dat": "site", "geoip.dat": "ip"}
	var mutex sync.Mutex
	checksumRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		name := strings.TrimPrefix(request.URL.Path, "/")
		if strings.HasSuffix(name, ".sha256sum") {
			assetName := strings.TrimSuffix(name, ".sha256sum")
			mutex.Lock()
			checksumRequests++
			generation := checksumRequests
			mutex.Unlock()
			hash := sha256String(bodies[assetName])
			if generation > len(geoDataNames) {
				hash = strings.Repeat("f", 64)
			}
			fmt.Fprintf(writer, "%s  %s\n", hash, assetName)
			return
		}
		_, _ = writer.Write([]byte(bodies[name]))
	}))
	defer server.Close()

	_, err := downloadGeoDataAssets(context.Background(), server.Client(), server.URL, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "release changed") {
		t.Fatalf("error = %v, want release changed", err)
	}
}

func TestWriteGeoDataBackupIncludesFilesAndManifest(t *testing.T) {
	env := testEnvironment(t)
	currentDirectory := t.TempDir()
	replacementDirectory := t.TempDir()
	current := makeTestGeoDataAssets(t, currentDirectory, "old")
	replacement := makeTestGeoDataAssets(t, replacementDirectory, "new")

	backup, err := writeGeoDataBackup(env, "node", current, replacement)
	if err != nil {
		t.Fatal(err)
	}
	for _, asset := range current {
		body, err := os.ReadFile(filepath.Join(backup, asset.Name))
		if err != nil || string(body) != "old "+asset.Name {
			t.Fatalf("backup %s = %q, %v", asset.Name, body, err)
		}
	}
	manifest, err := os.ReadFile(filepath.Join(backup, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), `"container": "node"`) || !strings.Contains(string(manifest), `"previous_sha256"`) {
		t.Fatalf("unexpected manifest: %s", manifest)
	}
}

func TestGeoGetRejectsInvalidContainerName(t *testing.T) {
	result := geoGet(core.Context{Context: context.Background()}, core.Request{}, map[string]interface{}{"container": "bad/name"})
	if result.Status != core.StatusFailed || result.ExitCode != core.ExitInvalidCommand {
		t.Fatalf("result = %#v", result)
	}
	if result.Error == nil || result.Error.Code != "GEODATA_CONTAINER_NAME_INVALID" {
		t.Fatalf("error = %#v", result.Error)
	}
}

func TestPruneGeoDataBackupsRetainsNewestManagedDirectories(t *testing.T) {
	env := testEnvironment(t)
	root := filepath.Join(env.DataDir, "backups", "geodata")
	for index := 1; index <= 5; index++ {
		directory := filepath.Join(root, fmt.Sprintf("2026090%dT120000Z-12345678", index))
		writeFile(t, filepath.Join(directory, "manifest.json"), "{}\n")
	}
	unmanaged := filepath.Join(root, "keep-me")
	writeFile(t, filepath.Join(unmanaged, "manifest.json"), "{}\n")

	if err := pruneGeoDataBackups(env, 3); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	remaining := make([]string, 0, len(entries))
	for _, entry := range entries {
		remaining = append(remaining, entry.Name())
	}
	want := []string{
		"20260903T120000Z-12345678", "20260904T120000Z-12345678", "20260905T120000Z-12345678", "keep-me",
	}
	if strings.Join(remaining, ",") != strings.Join(want, ",") {
		t.Fatalf("remaining backups = %#v, want %#v", remaining, want)
	}
}

func newGeoDataTestServer(t *testing.T, bodies, checksumOverrides map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		name := strings.TrimPrefix(request.URL.Path, "/")
		if strings.HasSuffix(name, ".sha256sum") {
			assetName := strings.TrimSuffix(name, ".sha256sum")
			body, ok := bodies[assetName]
			if !ok {
				http.NotFound(writer, request)
				return
			}
			hash := sha256String(body)
			if override := checksumOverrides[assetName]; override != "" {
				hash = override
			}
			fmt.Fprintf(writer, "%s  %s\n", hash, assetName)
			return
		}
		body, ok := bodies[name]
		if !ok {
			http.NotFound(writer, request)
			return
		}
		_, _ = writer.Write([]byte(body))
	}))
}

func makeTestGeoDataAssets(t *testing.T, directory, prefix string) []geoDataAsset {
	t.Helper()
	assets := make([]geoDataAsset, 0, len(geoDataNames))
	for _, name := range geoDataNames {
		path := filepath.Join(directory, name)
		writeFile(t, path, prefix+" "+name)
		hash, size, err := hashGeoDataFile(path)
		if err != nil {
			t.Fatal(err)
		}
		assets = append(assets, geoDataAsset{Name: name, Path: path, SHA256: hash, Size: size})
	}
	return assets
}

func sha256String(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}
