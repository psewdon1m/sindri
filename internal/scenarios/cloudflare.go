package scenarios

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	cloudflareIPv4URL = "https://www.cloudflare.com/ips-v4"
	cloudflareIPv6URL = "https://www.cloudflare.com/ips-v6"
)

var embeddedCloudflareRanges = strings.Fields(`
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
2400:cb00::/32
2606:4700::/32
2803:f800::/32
2405:b500::/32
2405:8100::/32
2a06:98c0::/29
2c0f:f248::/32
`)

var cloudflareRangeLoader = loadCloudflareRanges

func loadCloudflareRanges(ctx context.Context) ([]string, string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	type result struct {
		ipv6   bool
		ranges []string
		err    error
	}
	results := make(chan result, 2)
	go func() {
		ranges, err := fetchCloudflareCIDRs(ctx, client, cloudflareIPv4URL, false)
		results <- result{ranges: ranges, err: err}
	}()
	go func() {
		ranges, err := fetchCloudflareCIDRs(ctx, client, cloudflareIPv6URL, true)
		results <- result{ipv6: true, ranges: ranges, err: err}
	}()
	var ipv4, ipv6 []string
	var err4, err6 error
	for count := 0; count < 2; count++ {
		loaded := <-results
		if loaded.ipv6 {
			ipv6, err6 = loaded.ranges, loaded.err
		} else {
			ipv4, err4 = loaded.ranges, loaded.err
		}
	}
	if err4 != nil || err6 != nil {
		return append([]string(nil), embeddedCloudflareRanges...), "embedded", fmt.Errorf("live Cloudflare range refresh failed: IPv4: %v; IPv6: %v", err4, err6)
	}
	if len(ipv4) < 10 || len(ipv6) < 5 {
		return append([]string(nil), embeddedCloudflareRanges...), "embedded", fmt.Errorf("live Cloudflare range list was unexpectedly short")
	}
	return append(ipv4, ipv6...), "cloudflare.com", nil
}

func fetchCloudflareCIDRs(ctx context.Context, client *http.Client, endpoint string, wantIPv6 bool) ([]string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}

	seen := map[string]bool{}
	ranges := []string{}
	scanner := bufio.NewScanner(io.LimitReader(response.Body, 64*1024))
	for scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		if value == "" {
			continue
		}
		ip, network, parseErr := net.ParseCIDR(value)
		if parseErr != nil || network.String() != value {
			return nil, fmt.Errorf("invalid CIDR %q", value)
		}
		isIPv6 := ip.To4() == nil
		if isIPv6 != wantIPv6 {
			return nil, fmt.Errorf("unexpected address family for %q", value)
		}
		if !seen[value] {
			seen[value] = true
			ranges = append(ranges, value)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ranges, nil
}

func cloudflareRealIPConfig(ranges []string, source string) []byte {
	var body strings.Builder
	body.WriteString("# Managed by Sindri. Do not edit manually.\n")
	body.WriteString("# Trusted Cloudflare HTTP proxy ranges: " + source + "\n")
	for _, network := range ranges {
		fmt.Fprintf(&body, "set_real_ip_from %s;\n", network)
	}
	body.WriteString("real_ip_header CF-Connecting-IP;\n")
	body.WriteString("real_ip_recursive on;\n")
	return []byte(body.String())
}
