package releases

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestManagerDownloadsAndVerifiesInstaller(t *testing.T) {
	installer := []byte("#!/usr/bin/env bash\nprintf 'managed:%s:%s' \"$1\" \"${SINDRI_MANAGED_INSTALL:-}\"\n")
	sum := sha256.Sum256(installer)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/install.sh" {
			_, _ = w.Write(installer)
			return
		}
		_, _ = fmt.Fprintf(w, `{"schema_version":1,"product":"sindri","version":"1.2.3","repository":{"url":"https://github.com/example/sindri","ref":"v1.2.3","path":"sindri"},"installer":{"url":"/install.sh","sha256":"%s"}}`, hex.EncodeToString(sum[:]))
	}))
	defer server.Close()
	t.Setenv("SINDRI_MANIFEST_URL", server.URL+"/manifest.json")

	manifest, output, err := (Manager{Client: server.Client()}).Execute(context.Background(), "sindri", "update")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != "1.2.3" || output != "managed:update:1" {
		t.Fatalf("unexpected result: %#v %q", manifest, output)
	}
}

func TestManagerRejectsChecksumMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/install.sh" {
			_, _ = w.Write([]byte("unsafe"))
			return
		}
		_, _ = w.Write([]byte(`{"schema_version":1,"product":"sindri","version":"1.0.0","repository":{"url":"https://github.com/example/sindri","ref":"v1.0.0","path":"sindri"},"installer":{"url":"/install.sh","sha256":"00"}}`))
	}))
	defer server.Close()
	t.Setenv("SINDRI_MANIFEST_URL", server.URL+"/manifest.json")

	_, _, err := (Manager{Client: server.Client()}).Execute(context.Background(), "sindri", "update")
	if err == nil {
		t.Fatal("expected checksum validation error")
	}
}

func TestManifestURLUsesOwnReleaseManifestAndRejectsAgentLifecycle(t *testing.T) {
	t.Setenv("SINDRI_MANIFEST_URL", "")
	got := ManifestURL("sindri")
	want := defaultManifestURL
	if got != want {
		t.Fatalf("manifest URL mismatch: got %q want %q", got, want)
	}
	if ManifestURL("agent-node") != "" {
		t.Fatal("Sindri must not expose an Agent release manifest")
	}
	if _, _, err := NewManager().Execute(context.Background(), "agent-node", "update"); err == nil {
		t.Fatal("Sindri must reject Agent lifecycle operations")
	}
}
