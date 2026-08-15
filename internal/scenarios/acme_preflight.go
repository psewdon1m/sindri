package scenarios

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"sindri/internal/adapters"
	"sindri/internal/core"
)

const letsEncryptDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"

type hostLookupFunc func(context.Context, string) ([]string, error)

var acmeConnectivityCheck = verifyACMEConnectivity

func verifyACMEConnectivity(ctx core.Context, domain string) (string, error) {
	lookup := net.DefaultResolver.LookupHost
	if err := resolveWithRetry(ctx, lookup, domain, 5, 500*time.Millisecond); err != nil {
		logDNSDiagnostics(ctx)
		return "DOMAIN_DNS_UNAVAILABLE", fmt.Errorf("DNS lookup for %s failed after retries: %w; inspect resolvectl status and /etc/resolv.conf", domain, err)
	}

	parsed, _ := url.Parse(letsEncryptDirectoryURL)
	if err := resolveWithRetry(ctx, lookup, parsed.Hostname(), 5, 500*time.Millisecond); err != nil {
		logDNSDiagnostics(ctx)
		return "ACME_DNS_UNAVAILABLE", fmt.Errorf("DNS lookup for %s failed after retries: %w; inspect resolvectl status and /etc/resolv.conf", parsed.Hostname(), err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, letsEncryptDirectoryURL, nil)
		if err == nil {
			var response *http.Response
			response, err = client.Do(request)
			if err == nil {
				body, readErr := io.ReadAll(io.LimitReader(response.Body, 128*1024))
				_ = response.Body.Close()
				if readErr != nil {
					err = readErr
				} else if response.StatusCode != http.StatusOK {
					err = fmt.Errorf("HTTP %d", response.StatusCode)
				} else {
					var directory struct {
						NewOrder string `json:"newOrder"`
					}
					if decodeErr := json.Unmarshal(body, &directory); decodeErr != nil || !strings.HasPrefix(directory.NewOrder, "https://") {
						err = fmt.Errorf("ACME directory response is invalid")
					} else {
						return "", nil
					}
				}
			}
		}
		lastErr = err
		ctx.Log.Write("acme_https attempt=%d error=%v", attempt, err)
		if !waitForRetry(ctx, 750*time.Millisecond) {
			break
		}
	}
	logDNSDiagnostics(ctx)
	return "ACME_DIRECTORY_UNAVAILABLE", fmt.Errorf("Let's Encrypt ACME directory is unreachable after retries: %w", lastErr)
}

func resolveWithRetry(ctx context.Context, lookup hostLookupFunc, hostname string, attempts int, delay time.Duration) error {
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		attemptContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		addresses, err := lookup(attemptContext, hostname)
		cancel()
		if err == nil && len(addresses) > 0 {
			return nil
		}
		if err == nil {
			err = fmt.Errorf("resolver returned no addresses")
		}
		lastErr = err
		if attempt < attempts && !waitForRetry(ctx, delay) {
			break
		}
	}
	return lastErr
}

func waitForRetry(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func logDNSDiagnostics(ctx core.Context) {
	if body, err := os.ReadFile(hostPath(ctx.Env, "/etc/resolv.conf")); err == nil {
		ctx.Log.Write("dns_diagnostic resolv_conf=%s", strings.TrimSpace(string(body)))
	}
	if adapters.CommandExists("readlink") {
		result := adapters.RunWithTimeout(ctx, 5*time.Second, "readlink", "-f", "/etc/resolv.conf")
		ctx.Log.Write("dns_diagnostic resolv_conf_target=%s error=%s", result.Stdout, result.Stderr)
	}
	if adapters.CommandExists("resolvectl") {
		result := adapters.RunWithTimeout(ctx, 10*time.Second, "resolvectl", "status")
		ctx.Log.Write("dns_diagnostic resolvectl=%s error=%s", result.Stdout, result.Stderr)
	}
}
