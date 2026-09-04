package scenarios

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sindri/internal/core"
)

func TestCertificateStatusListsCertificatesWithIssuanceTimeAndPaths(t *testing.T) {
	env := testEnvironment(t)
	firstIssuedAt := time.Date(2026, time.August, 12, 9, 8, 7, 0, time.UTC)
	secondIssuedAt := time.Date(2026, time.September, 4, 12, 34, 56, 0, time.UTC)
	writeCertificateStatusFixture(t, env, "zeta.example.test", secondIssuedAt)
	writeCertificateStatusFixture(t, env, "alpha.example.test", firstIssuedAt)
	writeFile(t, hostPath(env, certificateLiveDirectory+"/README"), "managed by Certbot\n")

	result := certificateStatus(core.Context{Env: env}, core.Request{}, nil)
	assertResult(t, "certificate status", result, core.StatusSuccess)
	if result.Changed {
		t.Fatal("certificate status unexpectedly reported a change")
	}
	if count := result.Data["count"]; count != 2 {
		t.Fatalf("certificate count = %#v, want 2", count)
	}
	certificates, ok := result.Data["certificates"].([]certificateStatusEntry)
	if !ok || len(certificates) != 2 {
		t.Fatalf("certificate data = %#v", result.Data["certificates"])
	}
	if certificates[0] != (certificateStatusEntry{
		Name:          "alpha.example.test",
		IssuedAt:      "2026-08-12T09:08:07Z",
		FullchainPath: "/etc/letsencrypt/live/alpha.example.test/fullchain.pem",
		PrivkeyPath:   "/etc/letsencrypt/live/alpha.example.test/privkey.pem",
	}) {
		t.Fatalf("first certificate = %#v", certificates[0])
	}
	if certificates[1].Name != "zeta.example.test" || certificates[1].IssuedAt != "2026-09-04T12:34:56Z" {
		t.Fatalf("second certificate = %#v", certificates[1])
	}
}

func TestCertificateStatusReturnsAnEmptyListWhenCertbotDirectoryIsMissing(t *testing.T) {
	result := certificateStatus(core.Context{Env: testEnvironment(t)}, core.Request{}, nil)
	assertResult(t, "empty certificate status", result, core.StatusSuccess)
	certificates, ok := result.Data["certificates"].([]certificateStatusEntry)
	if !ok || certificates == nil || len(certificates) != 0 {
		t.Fatalf("empty certificate data = %#v", result.Data["certificates"])
	}
}

func TestCertificateStatusRejectsAnInvalidFullchain(t *testing.T) {
	env := testEnvironment(t)
	directory := hostPath(env, certificateLiveDirectory+"/broken.example.test")
	writeFile(t, filepath.Join(directory, "fullchain.pem"), "not a certificate\n")
	writeFile(t, filepath.Join(directory, "privkey.pem"), "private key fixture\n")

	result := certificateStatus(core.Context{Env: env}, core.Request{}, nil)
	assertResult(t, "invalid certificate status", result, core.StatusFailed)
	if result.Error == nil || result.Error.Code != "CERTIFICATE_STATUS_FAILED" || result.ExitCode != core.ExitVerificationFailed {
		t.Fatalf("invalid certificate result = %#v", result)
	}
}

func writeCertificateStatusFixture(t *testing.T, env core.Environment, name string, issuedAt time.Time) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(issuedAt.Unix()),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    issuedAt,
		NotAfter:     issuedAt.Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := hostPath(env, certificateLiveDirectory+"/"+name)
	if err := os.MkdirAll(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "fullchain.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "privkey.pem"), []byte("private key fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
}
