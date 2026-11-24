package api

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestRealIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	for _, c := range []struct {
		remote, xff string
		trusted     []netip.Prefix
		want        string
	}{
		{"192.168.1.5:5000", "1.2.3.4", nil, "192.168.1.5"},                           // no proxies configured: header ignored
		{"192.168.1.5:5000", "1.2.3.4", trusted, "192.168.1.5"},                       // not from a trusted proxy: header ignored
		{"10.0.0.2:5000", "198.51.100.7", trusted, "198.51.100.7"},                    // through the proxy
		{"10.0.0.2:5000", "6.6.6.6, 198.51.100.7, 10.0.0.3", trusted, "198.51.100.7"}, // spoofed first hop ignored
		{"10.0.0.2:5000", "junk", trusted, "10.0.0.2"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		r.Header.Set("X-Forwarded-For", c.xff)
		if got := realIP(r, c.trusted); got != c.want {
			t.Errorf("%s via %q: got %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
}
