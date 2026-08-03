package releases

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxDownloadBytes   = 4 << 20
	defaultManifestURL = "https://github.com/psewdon1m/sindri/releases/download/sindri-current/sindri-release-manifest.json"
)

type Installer struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

type Repository struct {
	URL  string `json:"url"`
	Ref  string `json:"ref"`
	Path string `json:"path"`
}

type Manifest struct {
	SchemaVersion int        `json:"schema_version"`
	Product       string     `json:"product"`
	Version       string     `json:"version"`
	Repository    Repository `json:"repository"`
	Installer     Installer  `json:"installer"`
}

type Manager struct {
	Client *http.Client
}

func NewManager() Manager {
	return Manager{Client: &http.Client{Timeout: 30 * time.Second}}
}

func ManifestURL(product string) string {
	if product != "sindri" {
		return ""
	}
	if override := strings.TrimSpace(os.Getenv("SINDRI_MANIFEST_URL")); override != "" {
		return override
	}
	return defaultManifestURL
}

func (m Manager) Execute(ctx context.Context, product, action string) (Manifest, string, error) {
	if product != "sindri" {
		return Manifest{}, "", errors.New("Sindri only manages its own release lifecycle")
	}
	manifestURL := ManifestURL(product)
	if manifestURL == "" {
		return Manifest{}, "", errors.New("Sindri release manifest URL is unavailable")
	}
	manifest, err := m.loadManifest(ctx, manifestURL)
	if err != nil {
		return Manifest{}, "", err
	}
	if manifest.Product != product {
		return Manifest{}, "", fmt.Errorf("manifest product %q does not match %q", manifest.Product, product)
	}
	installerPath, cleanup, err := m.downloadVerified(ctx, manifestURL, manifest.Installer)
	if err != nil {
		return Manifest{}, "", err
	}
	defer cleanup()
	output, err := runInstaller(ctx, installerPath, action)
	return manifest, output, err
}

func (m Manager) loadManifest(ctx context.Context, rawURL string) (Manifest, error) {
	if err := validateRemoteURL(rawURL); err != nil {
		return Manifest{}, err
	}
	body, err := m.download(ctx, rawURL)
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("invalid release manifest: %w", err)
	}
	if manifest.SchemaVersion != 1 || manifest.Product == "" || manifest.Version == "" || manifest.Repository.URL == "" || manifest.Repository.Path == "" || manifest.Installer.URL == "" || manifest.Installer.SHA256 == "" {
		return Manifest{}, errors.New("release manifest is incomplete")
	}
	return manifest, nil
}

func (m Manager) downloadVerified(ctx context.Context, manifestURL string, installer Installer) (string, func(), error) {
	installerURL, err := resolveURL(manifestURL, installer.URL)
	if err != nil {
		return "", func() {}, err
	}
	if err := validateRemoteURL(installerURL); err != nil {
		return "", func() {}, err
	}
	body, err := m.download(ctx, installerURL)
	if err != nil {
		return "", func() {}, err
	}
	sum := sha256.Sum256(body)
	actual := hex.EncodeToString(sum[:])
	expected := strings.ToLower(strings.TrimPrefix(installer.SHA256, "sha256:"))
	if actual != expected {
		return "", func() {}, fmt.Errorf("installer checksum mismatch: expected %s, got %s", expected, actual)
	}
	file, err := os.CreateTemp("", "sindri-installer-*.sh")
	if err != nil {
		return "", func() {}, err
	}
	path := file.Name()
	cleanup := func() { _ = os.Remove(path) }
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	if err := os.Chmod(path, 0700); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

func (m Manager) download(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s returned HTTP %d", rawURL, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxDownloadBytes))
}

func runInstaller(ctx context.Context, path, action string) (string, error) {
	cmd := exec.CommandContext(ctx, "bash", path, action)
	cmd.Env = append(os.Environ(), "SINDRI_MANAGED_INSTALL=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(output)), fmt.Errorf("installer failed: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func validateRemoteURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost" || parsed.Hostname() == "::1") {
		return nil
	}
	return errors.New("release URLs must use HTTPS")
}

func resolveURL(baseURL, ref string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	next, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(next).String(), nil
}

func LocalInstallerPath(product string) string {
	return filepath.Join("/usr/lib", product, "install.sh")
}

func releaseManifestURL(repositoryURL, asset string) (string, error) {
	repositoryURL = strings.TrimSuffix(strings.TrimSpace(repositoryURL), "/")
	repositoryURL = strings.TrimSuffix(repositoryURL, ".git")
	if err := validateRemoteURL(repositoryURL); err != nil {
		return "", err
	}
	parsed, err := url.Parse(repositoryURL)
	if err != nil {
		return "", err
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Hostname() == "" {
		return "", errors.New("repository URL is invalid")
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/") +
		"/releases/download/sindri-current/" + url.PathEscape(asset)
	parsed.RawPath = ""
	return parsed.String(), nil
}
