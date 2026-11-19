// Package powerdns implements the NCC DNS provider for the PowerDNS Authoritative HTTP API.
package powerdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/dns"
	"github.com/dertown/network-control-centre/internal/netutil"
)

func init() { dns.Register(Provider{}) }

// Provider implements dns.Provider.
//
// Server.Address is the API base, e.g. http://pdns.lan:8081.
// Options: "server_id" (default "localhost"), "tls" ("verify" default, or "pin") and "tls_fingerprint".
// Credentials: {"api_key": "..."} (the webserver api-key from pdns.conf).
type Provider struct{}

// Kind implements dns.Provider.
func (Provider) Kind() string { return "powerdns" }

type api struct {
	base, key string
	http      *http.Client
}

func newAPI(s dns.Server, creds map[string]string) (*api, error) {
	if creds["api_key"] == "" {
		return nil, errors.New("powerdns: api_key is missing from the vault entry")
	}
	u, err := url.Parse(strings.TrimRight(s.Address, "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("powerdns: bad address %q", s.Address)
	}
	sid := s.Options["server_id"]
	if sid == "" {
		sid = "localhost"
	}
	hc, _ := netutil.NewClient(s.Options["tls"], s.Options["tls_fingerprint"], 15*time.Second)
	return &api{base: u.String() + "/api/v1/servers/" + url.PathEscape(sid), key: creds["api_key"], http: hc}, nil
}

func (a *api) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", a.key)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(raw))
		}
		return fmt.Errorf("powerdns: %s %s: HTTP %d: %s", method, path, resp.StatusCode, e.Error)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type pdnsZone struct {
	ID     string      `json:"id"`
	Name   string      `json:"name"`
	Kind   string      `json:"kind"`
	Serial uint32      `json:"serial"`
	RRSets []pdnsRRSet `json:"rrsets,omitempty"`
}

type pdnsRecord struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type pdnsRRSet struct {
	Name       string       `json:"name"`
	Type       string       `json:"type"`
	TTL        int          `json:"ttl,omitempty"`
	ChangeType string       `json:"changetype,omitempty"`
	Records    []pdnsRecord `json:"records"`
}

// ListZones implements dns.Provider.
func (Provider) ListZones(ctx context.Context, s dns.Server, creds map[string]string) ([]dns.Zone, error) {
	a, err := newAPI(s, creds)
	if err != nil {
		return nil, err
	}
	var zs []pdnsZone
	if err := a.do(ctx, http.MethodGet, "/zones", nil, &zs); err != nil {
		return nil, err
	}
	out := make([]dns.Zone, 0, len(zs))
	for _, z := range zs {
		out = append(out, dns.Zone{Name: z.Name, Kind: z.Kind, Serial: z.Serial})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func zonePath(zone string) string { return "/zones/" + url.PathEscape(dns.FQDN(zone)) }

// ListRecords implements dns.Provider.
func (Provider) ListRecords(ctx context.Context, s dns.Server, creds map[string]string, zone string) ([]dns.RRSet, error) {
	a, err := newAPI(s, creds)
	if err != nil {
		return nil, err
	}
	var z pdnsZone
	if err := a.do(ctx, http.MethodGet, zonePath(zone), nil, &z); err != nil {
		return nil, err
	}
	out := make([]dns.RRSet, 0, len(z.RRSets))
	for _, r := range z.RRSets {
		rs := dns.RRSet{Name: r.Name, Type: r.Type, TTL: r.TTL}
		for _, rec := range r.Records {
			if !rec.Disabled {
				rs.Records = append(rs.Records, rec.Content)
			}
		}
		out = append(out, rs)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Type < out[j].Type
	})
	return out, nil
}

// Apply implements dns.Provider. PowerDNS applies one PATCH atomically.
func (Provider) Apply(ctx context.Context, s dns.Server, creds map[string]string, zone string, changes []dns.Change) error {
	a, err := newAPI(s, creds)
	if err != nil {
		return err
	}
	type patch struct {
		RRSets []pdnsRRSet `json:"rrsets"`
	}
	body := patch{}
	for _, c := range changes {
		r := pdnsRRSet{Name: dns.FQDN(c.RRSet.Name), Type: strings.ToUpper(c.RRSet.Type), ChangeType: c.Op, Records: []pdnsRecord{}}
		if c.Op == dns.Replace {
			r.TTL = c.RRSet.TTL
			if r.TTL == 0 {
				r.TTL = 3600
			}
			for _, v := range c.RRSet.Records {
				r.Records = append(r.Records, pdnsRecord{Content: canonical(r.Type, v)})
			}
		}
		body.RRSets = append(body.RRSets, r)
	}
	return a.do(ctx, http.MethodPatch, zonePath(zone), body, nil)
}

// canonical adds the trailing dot PowerDNS requires on host names inside record content.
func canonical(typ, v string) string {
	v = strings.TrimSpace(v)
	switch typ {
	case "CNAME", "PTR", "NS":
		return dns.FQDN(v)
	case "MX", "SRV":
		f := strings.Fields(v)
		if len(f) > 0 && f[len(f)-1] != "." {
			f[len(f)-1] = dns.FQDN(f[len(f)-1])
		}
		return strings.Join(f, " ")
	case "TXT":
		if !strings.HasPrefix(v, "\"") {
			return "\"" + strings.ReplaceAll(v, "\"", "\\\"") + "\""
		}
	}
	return v
}
