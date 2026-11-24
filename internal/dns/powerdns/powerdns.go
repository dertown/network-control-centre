// Package powerdns implements the NCC DNS provider for the PowerDNS Authoritative HTTP API.
package powerdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dertown/network-control-centre/internal/catalog"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/dns"
	"github.com/dertown/network-control-centre/internal/netutil"
)

func init() {
	dns.Register(Provider{}, catalog.Vendor{
		Label: "PowerDNS", Groups: []string{catalog.GroupDNS}, Order: 10,
		Summary:     "PowerDNS Authoritative over its HTTP API, with the Recursor for the router DNS check.",
		Help:        "Use the address of the PowerDNS webserver (webserver-address/webserver-port) and the api-key from pdns.conf.",
		NameDefault: "powerdns", AddressDefault: "http://192.168.1.10:8081",
		Fields: []catalog.Field{
			{Key: "server_id", Label: "Server id", Type: catalog.Text, Store: catalog.StoreOption, Default: "localhost"},
			{Key: "api_key", Label: "API key", Type: catalog.Token, Store: catalog.StoreSecret, Required: true},
			catalog.TLSField("verify"),
			{Key: "recursor_url", Label: "Recursor API URL", Type: catalog.Text, Store: catalog.StoreOption, Placeholder: "http://192.168.1.10:8082",
				Section: "Router DNS check (optional)",
				Help: "The Authoritative server never forwards; to check that internet queries go to your ISP, give the API of the " +
					"PowerDNS Recursor your clients use (webserver=yes, api-key in recursor.conf)."},
			{Key: "recursor_api_key", Label: "Recursor API key (if different)", Type: catalog.Token, Store: catalog.StoreSecret},
			{Key: "resolver_ips", Label: "Address clients use", Type: catalog.Text, Store: catalog.StoreOption, Placeholder: "the Recursor's address"},
			{Key: "isp_dns", Label: "ISP DNS servers", Type: catalog.Text, Store: catalog.StoreOption, Placeholder: "learned from the router's WAN"},
		},
	})
}

// Provider implements dns.Provider.
//
// Server.Address is the API base, e.g. http://pdns.lan:8081.
// Options: "server_id" (default "localhost"), "tls" ("verify" default, or "pin") and "tls_fingerprint".
// Credentials: {"api_key": "..."} (the webserver api-key from pdns.conf).
type Provider struct{}

// Kind implements dns.Provider.
func (Provider) Kind() string { return "powerdns" }

type api struct {
	base, sid, key string
	http           *http.Client
}

func newAPI(s dns.Server, creds map[string]string) (*api, error) {
	if creds["api_key"] == "" {
		return nil, errors.New("powerdns: api_key is missing from the vault entry")
	}
	u, err := url.Parse(strings.TrimRight(s.Address, "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("powerdns: bad address %q", s.Address)
	}
	// Accept an address that already ends in the API path, e.g. http://pdns:8081/api/v1.
	u.Path = strings.TrimRight(strings.TrimSuffix(strings.TrimSuffix(u.Path, "/api/v1"), "/api"), "/")
	sid := s.Options["server_id"]
	if sid == "" {
		sid = "localhost"
	}
	hc, _ := netutil.NewClient(s.Options["tls"], s.Options["tls_fingerprint"], 15*time.Second)
	return &api{base: u.String() + "/api/v1/servers/" + url.PathEscape(sid), sid: sid, key: creds["api_key"], http: hc}, nil
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
		return &httpError{Method: method, Path: path, Status: resp.StatusCode, Msg: e.Error}
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// httpError is a non-2xx answer from the API.
type httpError struct {
	Method, Path string
	Status       int
	Msg          string
}

func (e *httpError) Error() string {
	path := e.Path
	if path == "" {
		path = "/"
	}
	return fmt.Sprintf("powerdns: %s %s: HTTP %d: %s", e.Method, path, e.Status, e.Msg)
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

// Check implements dns.Checker. It reads the server object, which proves the
// address, server_id and api_key are all right, and explains the usual failures.
func (Provider) Check(ctx context.Context, s dns.Server, creds map[string]string) error {
	a, err := newAPI(s, creds)
	if err != nil {
		return err
	}
	var info struct {
		ID         string `json:"id"`
		DaemonType string `json:"daemon_type"`
		Version    string `json:"version"`
	}
	err = a.do(ctx, http.MethodGet, "", nil, &info)
	var he *httpError
	if errors.As(err, &he) {
		switch he.Status {
		case http.StatusUnauthorized, http.StatusForbidden:
			return fmt.Errorf("powerdns: the API key was rejected (HTTP %d); check api-key in pdns.conf matches the stored credentials", he.Status)
		case http.StatusNotFound:
			return fmt.Errorf("powerdns: HTTP 404 for %s; check that the address is the API base (e.g. http://pdns:8081), that webserver and api are enabled in pdns.conf, and that server_id %q is right", a.base, a.sid)
		}
	}
	if err != nil {
		return err
	}
	if info.DaemonType == "recursor" {
		return errors.New("powerdns: this is a PowerDNS Recursor; NCC needs the Authoritative server API")
	}
	return nil
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

// Forwarders implements dns.Forwarder. The PowerDNS Authoritative server never forwards, so
// this reads the PowerDNS Recursor that answers clients, through its own API.
//
// Options: "recursor_url" is the Recursor's API base (webserver-address/webserver-port in
// recursor.conf, e.g. http://ns1:8082); without it there is nothing to read and
// dns.ErrNoResolver is returned. The Recursor's own api-key goes in the credentials as
// "recursor_api_key"; when it is missing the Authoritative "api_key" is tried.
func (Provider) Forwarders(ctx context.Context, s dns.Server, creds map[string]string) (*dns.Forwarding, error) {
	base := strings.TrimSpace(s.Options["recursor_url"])
	if base == "" {
		return nil, dns.ErrNoResolver
	}
	key := creds["recursor_api_key"]
	if key == "" {
		key = creds["api_key"]
	}
	rs := dns.Server{ID: s.ID, Name: s.Name, Kind: s.Kind, Address: base,
		Options: map[string]string{"server_id": "localhost", "tls": s.Options["recursor_tls"], "tls_fingerprint": s.Options["recursor_tls_fingerprint"]}}
	a, err := newAPI(rs, map[string]string{"api_key": key})
	if err != nil {
		return nil, fmt.Errorf("powerdns recursor: %w", err)
	}
	var zones []struct {
		Name             string   `json:"name"`
		Kind             string   `json:"kind"`
		Servers          []string `json:"servers"`
		RecursionDesired bool     `json:"recursion_desired"`
	}
	if err := a.do(ctx, http.MethodGet, "/zones", nil, &zones); err != nil {
		var he *httpError
		if errors.As(err, &he) && (he.Status == http.StatusUnauthorized || he.Status == http.StatusForbidden) {
			return nil, fmt.Errorf("powerdns recursor: the API key was rejected (HTTP %d); set the Recursor's api-key from recursor.conf on this connection", he.Status)
		}
		return nil, err
	}
	f := &dns.Forwarding{Source: "PowerDNS Recursor at " + base, Servers: []string{}}
	for _, z := range zones {
		if z.Name != "." || !strings.EqualFold(z.Kind, "Forwarded") {
			continue
		}
		f.RecursionDesired = z.RecursionDesired
		for _, srv := range z.Servers {
			f.Servers = append(f.Servers, StripPort(srv))
		}
	}
	return f, nil
}

// StripPort drops the port from a forwarder address: "1.2.3.4:53" and "[2001:db8::1]:53"
// become "1.2.3.4" and "2001:db8::1". An address without a port is returned as is.
func StripPort(a string) string {
	a = strings.TrimSpace(a)
	if strings.HasPrefix(a, "[") {
		if i := strings.Index(a, "]"); i > 0 {
			return a[1:i]
		}
	}
	if strings.Count(a, ":") == 1 {
		return a[:strings.Index(a, ":")]
	}
	return a
}

// CreateZone implements dns.ZoneManager. PowerDNS writes the SOA from its default-soa-content
// setting and the NS records from the nameservers; soa_edit_api keeps the serial moving on
// every change NCC makes through the API.
func (Provider) CreateZone(ctx context.Context, s dns.Server, creds map[string]string, spec dns.ZoneSpec) error {
	a, err := newAPI(s, creds)
	if err != nil {
		return err
	}
	kind := spec.Kind
	if kind == "" {
		kind = "Native"
	}
	ns := make([]string, 0, len(spec.Nameservers))
	for _, n := range spec.Nameservers {
		ns = append(ns, dns.FQDN(n))
	}
	body := map[string]any{"name": dns.FQDN(spec.Name), "kind": kind, "nameservers": ns, "soa_edit_api": "DEFAULT"}
	err = a.do(ctx, http.MethodPost, "/zones", body, nil)
	var he *httpError
	if errors.As(err, &he) && he.Status == http.StatusConflict {
		return fmt.Errorf("powerdns: zone %s already exists", dns.FQDN(spec.Name))
	}
	return err
}

// DeleteZone implements dns.ZoneManager.
func (Provider) DeleteZone(ctx context.Context, s dns.Server, creds map[string]string, zone string) error {
	a, err := newAPI(s, creds)
	if err != nil {
		return err
	}
	return a.do(ctx, http.MethodDelete, zonePath(zone), nil, nil)
}
