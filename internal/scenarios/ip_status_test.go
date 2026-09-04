package scenarios

import (
	"errors"
	"testing"

	"sindri/internal/core"
)

func TestIPStatusReturnsOnlyProxyEgressFields(t *testing.T) {
	original := proxyIPInfoLookup
	proxyIPInfoLookup = func(core.Context) (proxyIPInfo, error) {
		return proxyIPInfo{IP: "203.0.113.9", Country: "NL", Region: "North Holland", City: "Amsterdam", Org: "AS64500 Example"}, nil
	}
	t.Cleanup(func() { proxyIPInfoLookup = original })

	result := ipStatus(core.Context{}, core.Request{}, nil)
	assertResult(t, "ip status", result, core.StatusSuccess)
	for key, expected := range map[string]interface{}{
		"proxy": xrayHTTPProxyURL, "ip": "203.0.113.9", "country": "NL",
		"region": "North Holland", "city": "Amsterdam", "org": "AS64500 Example",
	} {
		if result.Data[key] != expected {
			t.Fatalf("%s = %#v, want %#v", key, result.Data[key], expected)
		}
	}
}

func TestIPStatusReportsAnUnavailableProxy(t *testing.T) {
	original := proxyIPInfoLookup
	proxyIPInfoLookup = func(core.Context) (proxyIPInfo, error) {
		return proxyIPInfo{}, errors.New("connection refused")
	}
	t.Cleanup(func() { proxyIPInfoLookup = original })

	result := ipStatus(core.Context{}, core.Request{}, nil)
	assertResult(t, "failed ip status", result, core.StatusFailed)
	if result.Error == nil || result.Error.Code != "PROXY_IP_STATUS_FAILED" {
		t.Fatalf("unexpected proxy failure: %#v", result)
	}
}
