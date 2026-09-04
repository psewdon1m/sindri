package scenarios

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"sindri/internal/core"
)

const (
	xrayHTTPProxyURL = "http://127.0.0.1:18080"
	ipInfoStatusURL  = "https://ipinfo.io/json"
	ipStatusTimeout  = 15 * time.Second
	ipStatusMaxBytes = int64(1024 * 1024)
)

type proxyIPInfo struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	Region  string `json:"region"`
	City    string `json:"city"`
	Org     string `json:"org"`
}

var proxyIPInfoLookup = fetchProxyIPInfo

func ipStatus(ctx core.Context, _ core.Request, _ map[string]interface{}) core.Result {
	info, err := proxyIPInfoLookup(ctx)
	if err != nil {
		return failed("PROXY_IP_STATUS_FAILED", err.Error(), core.ExitPrecheckFailed)
	}
	return success("Proxy egress IP collected", false, map[string]interface{}{
		"proxy":   xrayHTTPProxyURL,
		"ip":      info.IP,
		"country": info.Country,
		"region":  info.Region,
		"city":    info.City,
		"org":     info.Org,
	})
}

func fetchProxyIPInfo(ctx core.Context) (proxyIPInfo, error) {
	proxyURL, err := url.Parse(xrayHTTPProxyURL)
	if err != nil {
		return proxyIPInfo{}, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	client := &http.Client{
		Timeout:   ipStatusTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("ip status redirected away from HTTPS")
			}
			return nil
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, ipInfoStatusURL, nil)
	if err != nil {
		return proxyIPInfo{}, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "Sindri ip-status")
	response, err := client.Do(request)
	if err != nil {
		return proxyIPInfo{}, fmt.Errorf("proxy %s is unavailable: %w", xrayHTTPProxyURL, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return proxyIPInfo{}, fmt.Errorf("ipinfo.io returned HTTP %d through the proxy", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, ipStatusMaxBytes+1))
	if err != nil {
		return proxyIPInfo{}, err
	}
	if int64(len(body)) > ipStatusMaxBytes {
		return proxyIPInfo{}, errors.New("ipinfo.io response is too large")
	}
	var info proxyIPInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return proxyIPInfo{}, fmt.Errorf("decode ipinfo.io response: %w", err)
	}
	info.IP = strings.TrimSpace(info.IP)
	if net.ParseIP(info.IP) == nil {
		return proxyIPInfo{}, errors.New("ipinfo.io response does not contain a valid IP address")
	}
	return info, nil
}
