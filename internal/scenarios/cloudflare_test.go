package scenarios

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchCloudflareCIDRsValidatesAddressFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("173.245.48.0/20\n103.21.244.0/22\n"))
	}))
	defer server.Close()

	ranges, err := fetchCloudflareCIDRs(context.Background(), server.Client(), server.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 2 || ranges[0] != "173.245.48.0/20" {
		t.Fatalf("unexpected ranges: %#v", ranges)
	}
	if _, err := fetchCloudflareCIDRs(context.Background(), server.Client(), server.URL, true); err == nil {
		t.Fatal("IPv4 range was accepted as IPv6")
	}
}

func TestCloudflareRealIPConfigTrustsOnlyValidatedRanges(t *testing.T) {
	body := string(cloudflareRealIPConfig([]string{"173.245.48.0/20", "2606:4700::/32"}, "test"))
	for _, expected := range []string{
		"set_real_ip_from 173.245.48.0/20;",
		"set_real_ip_from 2606:4700::/32;",
		"real_ip_header CF-Connecting-IP;",
		"real_ip_recursive on;",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("missing %q in config: %s", expected, body)
		}
	}
}
