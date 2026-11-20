// Package mocklab emulates a small UniFi network and a PowerDNS server so NCC can be
// tested and demonstrated without touching a real network.
package mocklab

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"

	_ "embed"
)

// StatDevice is a recorded UniFi stat/device response: a Dream Router 7, two U6 Pro access
// points, a UniFi switch, a switch with an unknown model code and a third-party LLDP switch.
//
//go:embed stat_device.json
var StatDevice []byte

// StatSta is a recorded UniFi stat/sta (clients) response.
//
//go:embed stat_sta.json
var StatSta []byte

// UniFi returns a handler that behaves like a UniFi OS console for the read-only API NCC uses.
// It accepts username "ncc" with password "demo-password", or API key "demo-key".
func UniFi() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["username"] != "ncc" || in["password"] != "demo-password" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "demo", Path: "/", HttpOnly: true})
		w.Header().Set("X-Csrf-Token", "demo-csrf")
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("POST /api/auth/logout", func(w http.ResponseWriter, r *http.Request) {})
	ok := func(r *http.Request) bool {
		if r.Header.Get("X-API-KEY") == "demo-key" {
			return true
		}
		c, err := r.Cookie("TOKEN")
		return err == nil && c.Value == "demo"
	}
	serve := func(b []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !ok(r) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(b)
		}
	}
	mux.HandleFunc("GET /proxy/network/api/s/default/stat/device", serve(StatDevice))
	mux.HandleFunc("GET /proxy/network/api/s/default/stat/sta", serve(StatSta))
	return mux
}

// PowerDNS is an in-memory PowerDNS Authoritative API with home.lan. and 1.168.192.in-addr.arpa.
type PowerDNS struct {
	APIKey string
	mu     sync.Mutex
	zones  map[string]map[string]rrset // zone -> "name|type" -> rrset
	// Patches records every PATCH body received, per zone.
	Patches map[string][]json.RawMessage
}

type record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type rrset struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	TTL        int      `json:"ttl"`
	ChangeType string   `json:"changetype,omitempty"`
	Records    []record `json:"records"`
}

// NewPowerDNS returns a server seeded with a couple of records.
func NewPowerDNS(apiKey string) *PowerDNS {
	p := &PowerDNS{APIKey: apiKey, zones: map[string]map[string]rrset{}, Patches: map[string][]json.RawMessage{}}
	add := func(zone, name, typ string, ttl int, vals ...string) {
		if p.zones[zone] == nil {
			p.zones[zone] = map[string]rrset{}
		}
		rs := rrset{Name: name, Type: typ, TTL: ttl}
		for _, v := range vals {
			rs.Records = append(rs.Records, record{Content: v})
		}
		p.zones[zone][name+"|"+typ] = rs
	}
	add("home.lan.", "home.lan.", "SOA", 3600, "ns1.home.lan. hostmaster.home.lan. 1 10800 3600 604800 3600")
	add("home.lan.", "home.lan.", "NS", 3600, "ns1.home.lan.")
	add("home.lan.", "ns1.home.lan.", "A", 3600, "192.168.1.10")
	add("home.lan.", "router.home.lan.", "A", 3600, "192.168.1.1")
	add("home.lan.", "old.home.lan.", "A", 300, "192.168.1.9")
	add("1.168.192.in-addr.arpa.", "1.168.192.in-addr.arpa.", "SOA", 3600, "ns1.home.lan. hostmaster.home.lan. 1 10800 3600 604800 3600")
	add("1.168.192.in-addr.arpa.", "1.1.168.192.in-addr.arpa.", "PTR", 3600, "router.home.lan.")
	return p
}

// ServeHTTP implements the subset of /api/v1/servers/localhost NCC uses.
func (p *PowerDNS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("X-API-Key") != p.APIKey {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
		return
	}
	const base = "/api/v1/servers/localhost/zones"
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.URL.Path == "/api/v1/servers/localhost" && r.Method == http.MethodGet {
		_, _ = w.Write([]byte(`{"type":"Server","id":"localhost","daemon_type":"authoritative","version":"4.9.0-mock"}`))
		return
	}
	if r.URL.Path == base && r.Method == http.MethodGet {
		var out []map[string]any
		names := make([]string, 0, len(p.zones))
		for z := range p.zones {
			names = append(names, z)
		}
		sort.Strings(names)
		for _, z := range names {
			out = append(out, map[string]any{"id": z, "name": z, "kind": "Native", "serial": 1})
		}
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	zone := strings.TrimPrefix(r.URL.Path, base+"/")
	z, ok := p.zones[zone]
	if !ok || zone == r.URL.Path {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"Could not find domain"}`))
		return
	}
	switch r.Method {
	case http.MethodGet:
		var sets []rrset
		for _, rs := range z {
			sets = append(sets, rs)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": zone, "name": zone, "rrsets": sets})
	case http.MethodPatch:
		raw, _ := io.ReadAll(r.Body)
		var body struct {
			RRSets []rrset `json:"rrsets"`
		}
		if err := json.Unmarshal(raw, &body); err != nil || len(body.RRSets) == 0 {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"error":"bad request body"}`))
			return
		}
		for _, rs := range body.RRSets {
			if !strings.HasSuffix(rs.Name, ".") || (rs.Name != zone && !strings.HasSuffix(rs.Name, "."+zone)) {
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = w.Write([]byte(`{"error":"RRset ` + rs.Name + ` is out of zone"}`))
				return
			}
		}
		for _, rs := range body.RRSets {
			key := rs.Name + "|" + rs.Type
			if rs.ChangeType == "DELETE" {
				delete(z, key)
				continue
			}
			rs.ChangeType = ""
			z[key] = rs
		}
		p.Patches[zone] = append(p.Patches[zone], raw)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
