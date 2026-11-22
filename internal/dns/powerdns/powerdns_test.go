package powerdns

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dertown/network-control-centre/internal/dns"
	"github.com/dertown/network-control-centre/internal/mocklab"
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

func TestForwarders(t *testing.T) {
	ctx := context.Background()
	rec := mocklab.NewRecursor("rk")
	srv := httptest.NewServer(rec)
	defer srv.Close()
	s := dns.Server{Name: "pdns", Address: "http://auth:8081", Options: map[string]string{"recursor_url": srv.URL}}

	// the Recursor's own key, and the Authoritative key as a fallback
	for _, creds := range []map[string]string{{"api_key": "x", "recursor_api_key": "rk"}, {"api_key": "rk"}} {
		f, err := Provider{}.Forwarders(ctx, s, creds)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(f.Servers, ",") != "203.0.113.53,203.0.113.54" || !f.RecursionDesired || !strings.Contains(f.Source, srv.URL) {
			t.Fatalf("forwarding: %+v", f)
		}
	}

	rec.NoRecurse = true
	if f, _ := (Provider{}).Forwarders(ctx, s, map[string]string{"api_key": "rk"}); f.RecursionDesired {
		t.Fatal("forward-zones should report no recursion")
	}
	rec.Forwarders = nil
	if f, _ := (Provider{}).Forwarders(ctx, s, map[string]string{"api_key": "rk"}); f == nil || len(f.Servers) != 0 {
		t.Fatalf("full recursion: %+v", f)
	}

	if _, err := (Provider{}).Forwarders(ctx, s, map[string]string{"api_key": "wrong"}); err == nil || !strings.Contains(err.Error(), "API key was rejected") {
		t.Fatalf("bad key: %v", err)
	}
	if _, err := (Provider{}).Forwarders(ctx, dns.Server{Address: "http://auth:8081"}, map[string]string{"api_key": "k"}); !errors.Is(err, dns.ErrNoResolver) {
		t.Fatalf("no recursor_url: %v", err)
	}
}

func TestStripPort(t *testing.T) {
	for in, want := range map[string]string{"1.2.3.4:53": "1.2.3.4", "1.2.3.4": "1.2.3.4", "[2001:db8::1]:53": "2001:db8::1", "2001:db8::1": "2001:db8::1"} {
		if got := StripPort(in); got != want {
			t.Errorf("StripPort(%q) = %q, want %q", in, got, want)
		}
	}
}
