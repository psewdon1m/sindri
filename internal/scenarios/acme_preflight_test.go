package scenarios

import (
	"context"
	"errors"
	"testing"
)

func TestResolveWithRetryRecoversFromTransientDNSFailure(t *testing.T) {
	attempts := 0
	lookup := func(_ context.Context, hostname string) ([]string, error) {
		attempts++
		if hostname != "acme-v02.api.letsencrypt.org" {
			t.Fatalf("unexpected hostname: %s", hostname)
		}
		if attempts < 3 {
			return nil, errors.New("temporary DNS failure")
		}
		return []string{"172.65.32.248"}, nil
	}
	if err := resolveWithRetry(context.Background(), lookup, "acme-v02.api.letsencrypt.org", 5, 0); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("attempt count = %d, want 3", attempts)
	}
}

func TestResolveWithRetryReportsPersistentDNSFailure(t *testing.T) {
	attempts := 0
	lookup := func(context.Context, string) ([]string, error) {
		attempts++
		return nil, errors.New("resolver unavailable")
	}
	if err := resolveWithRetry(context.Background(), lookup, "acme-v02.api.letsencrypt.org", 4, 0); err == nil {
		t.Fatal("persistent DNS failure was accepted")
	}
	if attempts != 4 {
		t.Fatalf("attempt count = %d, want 4", attempts)
	}
}
