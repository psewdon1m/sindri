package scenarios

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"time"

	"sindri/internal/core"
)

const certificateLiveDirectory = "/etc/letsencrypt/live"

type certificateStatusEntry struct {
	Name          string `json:"name"`
	IssuedAt      string `json:"issued_at"`
	FullchainPath string `json:"fullchain_path"`
	PrivkeyPath   string `json:"privkey_path"`
}

func certificateStatus(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	entries, err := os.ReadDir(hostPath(ctx.Env, certificateLiveDirectory))
	if os.IsNotExist(err) {
		return certificateStatusSuccess(nil)
	}
	if err != nil {
		return failed("CERTIFICATE_STATUS_FAILED", fmt.Sprintf("read %s: %v", certificateLiveDirectory, err), core.ExitGeneralFailure)
	}

	certificates := make([]certificateStatusEntry, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || !certificateName.MatchString(name) {
			continue
		}

		fullchainPath := path.Join(certificateLiveDirectory, name, "fullchain.pem")
		privkeyPath := path.Join(certificateLiveDirectory, name, "privkey.pem")
		if _, err := os.Stat(hostPath(ctx.Env, privkeyPath)); err != nil {
			return failed("CERTIFICATE_STATUS_FAILED", fmt.Sprintf("inspect %s: %v", privkeyPath, err), core.ExitVerificationFailed)
		}
		certificate, err := readLeafCertificate(hostPath(ctx.Env, fullchainPath))
		if err != nil {
			return failed("CERTIFICATE_STATUS_FAILED", fmt.Sprintf("inspect %s: %v", fullchainPath, err), core.ExitVerificationFailed)
		}
		certificates = append(certificates, certificateStatusEntry{
			Name:          name,
			IssuedAt:      certificate.NotBefore.UTC().Format(time.RFC3339),
			FullchainPath: fullchainPath,
			PrivkeyPath:   privkeyPath,
		})
	}
	sort.Slice(certificates, func(i, j int) bool { return certificates[i].Name < certificates[j].Name })
	return certificateStatusSuccess(certificates)
}

func certificateStatusSuccess(certificates []certificateStatusEntry) core.Result {
	if certificates == nil {
		certificates = []certificateStatusEntry{}
	}
	message := fmt.Sprintf("Certificates found: %d", len(certificates))
	if len(certificates) == 0 {
		message = "No certificates found"
	}
	return success(message, false, map[string]interface{}{
		"directory":    certificateLiveDirectory,
		"count":        len(certificates),
		"certificates": certificates,
	})
}

func readLeafCertificate(filename string) (*x509.Certificate, error) {
	body, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, err
	}
	for len(body) > 0 {
		var block *pem.Block
		block, body = pem.Decode(body)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}
			return certificate, nil
		}
	}
	return nil, fmt.Errorf("no PEM certificate found")
}
