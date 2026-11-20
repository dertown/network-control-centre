package powerdns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dertown/network-control-centre/internal/dns"
)

func pdnsServer(t *testing.T, daemon string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "k" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
			return
		}
		if r.URL.Path != "/api/v1/servers/localhost" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"id":"localhost","daemon_type":"` + daemon + `","version":"4.9"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCheck(t *testing.T) {
	ctx := context.Background()
	auth := pdnsServer(t, "authoritative")
	rec := pdnsServer(t, "recursor")
	cases := []struct {
		name, addr, sid, key, want string
	}{
		{"ok", auth.URL, "", "k", ""},
		{"address with api path", auth.URL + "/api/v1/", "", "k", ""},
		{"wrong key", auth.URL, "", "x", "API key was rejected"},
		{"wrong server id", auth.URL, "ns1", "k", `HTTP 404`},
		{"wrong path", auth.URL + "/pdns", "", "k", `HTTP 404`},
		{"recursor", rec.URL, "", "k", "Recursor"},
		{"missing key", auth.URL, "", "", "api_key is missing"},
		{"unreachable", "http://127.0.0.1:1", "", "k", "connect"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := dns.Server{Address: c.addr, Options: map[string]string{}}
			if c.sid != "" {
				s.Options["server_id"] = c.sid
			}
			err := dns.Check(ctx, Provider{}, s, map[string]string{"api_key": c.key})
			if c.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
}
