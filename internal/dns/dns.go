// Package dns defines the DNS provider interface and shared helpers.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
)

// Zone is an authoritative zone.
type Zone struct {
	Name   string `json:"name"` // fully qualified, trailing dot
	Kind   string `json:"kind,omitempty"`
	Serial uint32 `json:"serial,omitempty"`
}

// RRSet is all records of one name and type.
type RRSet struct {
	Name    string   `json:"name"` // fully qualified, trailing dot
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Records []string `json:"records"` // presentation format content
}

// Change kinds.
const (
	Replace = "REPLACE"
	Delete  = "DELETE"
)

// Change replaces or deletes one RRSet.
type Change struct {
	Op    string `json:"op"`
	RRSet RRSet  `json:"rrset"`
}

// Server is a configured DNS server.
type Server struct {
	ID      int64             `json:"id"`
	Name    string            `json:"name"`
	Kind    string            `json:"kind"`
	Address string            `json:"address"`
	Options map[string]string `json:"options"`
}

// Provider talks to one kind of DNS server.
type Provider interface {
	Kind() string
	ListZones(ctx context.Context, s Server, creds map[string]string) ([]Zone, error)
	ListRecords(ctx context.Context, s Server, creds map[string]string, zone string) ([]RRSet, error)
	Apply(ctx context.Context, s Server, creds map[string]string, zone string, changes []Change) error
}

// Checker is implemented by providers that can test a connection more cheaply
// than listing zones. Check returns nil when the server answers and accepts
// the credentials.
type Checker interface {
	Check(ctx context.Context, s Server, creds map[string]string) error
}

// Check tests that a DNS server is reachable and the credentials work. It uses
// the provider's own Checker when it has one, and otherwise lists the zones.
func Check(ctx context.Context, p Provider, s Server, creds map[string]string) error {
	if c, ok := p.(Checker); ok {
		return c.Check(ctx, s, creds)
	}
	_, err := p.ListZones(ctx, s, creds)
	return err
}

var (
	mu        sync.RWMutex
	providers = map[string]Provider{}
)

// Register adds a provider.
func Register(p Provider) { mu.Lock(); providers[p.Kind()] = p; mu.Unlock() }

// Get returns a provider by kind.
func Get(kind string) (Provider, error) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := providers[kind]
	if !ok {
		return nil, fmt.Errorf("no DNS provider %q", kind)
	}
	return p, nil
}

// Kinds lists registered providers.
func Kinds() []string {
	mu.RLock()
	defer mu.RUnlock()
	var out []string
	for k := range providers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// FQDN lower-cases a name and adds the trailing dot.
func FQDN(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	if !strings.HasSuffix(n, ".") {
		n += "."
	}
	return n
}

// Qualify turns a relative name ("nas", "@") into a full name inside zone.
func Qualify(name, zone string) string {
	zone = FQDN(zone)
	name = strings.TrimSpace(name)
	if name == "" || name == "@" {
		return zone
	}
	if strings.HasSuffix(name, ".") {
		return FQDN(name)
	}
	fq := FQDN(name)
	if strings.HasSuffix(fq, "."+zone) || fq == zone {
		return fq
	}
	return FQDN(name + "." + zone)
}

// InZone reports whether name is at or below zone.
func InZone(name, zone string) bool {
	name, zone = FQDN(name), FQDN(zone)
	return name == zone || strings.HasSuffix(name, "."+zone)
}

var supported = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "TXT": true, "MX": true,
	"SRV": true, "PTR": true, "NS": true, "CAA": true, "SOA": true}

// Validate checks a change before it is sent anywhere.
func Validate(zone string, c Change) error {
	if c.Op != Replace && c.Op != Delete {
		return fmt.Errorf("unknown op %q", c.Op)
	}
	r := c.RRSet
	t := strings.ToUpper(r.Type)
	if !supported[t] {
		return fmt.Errorf("record type %q is not supported", r.Type)
	}
	if !InZone(r.Name, zone) {
		return fmt.Errorf("%s is not inside zone %s", r.Name, zone)
	}
	if t == "SOA" && c.Op == Delete {
		return errors.New("refusing to delete the SOA record")
	}
	if c.Op == Delete {
		return nil
	}
	if len(r.Records) == 0 {
		return errors.New("at least one record value is required")
	}
	if r.TTL < 0 || r.TTL > 604800 {
		return errors.New("TTL must be between 0 and 604800")
	}
	for _, v := range r.Records {
		switch t {
		case "A":
			a, err := netip.ParseAddr(v)
			if err != nil || !a.Is4() {
				return fmt.Errorf("%q is not an IPv4 address", v)
			}
		case "AAAA":
			a, err := netip.ParseAddr(v)
			if err != nil || !a.Is6() || a.Is4In6() {
				return fmt.Errorf("%q is not an IPv6 address", v)
			}
		case "CNAME", "PTR", "NS":
			if strings.ContainsAny(v, " \t") || v == "" {
				return fmt.Errorf("%q is not a host name", v)
			}
		}
	}
	if t == "CNAME" && len(r.Records) != 1 {
		return errors.New("a CNAME holds exactly one target")
	}
	return nil
}

// PTRName returns the reverse-lookup name for an IP, e.g. 10.1.2.3 -> 3.2.1.10.in-addr.arpa.
func PTRName(ip string) (string, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", err
	}
	if a.Is4() {
		b := a.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0]), nil
	}
	b := a.As16()
	var sb strings.Builder
	const hexd = "0123456789abcdef"
	for i := 15; i >= 0; i-- {
		sb.WriteByte(hexd[b[i]&0x0f])
		sb.WriteByte('.')
		sb.WriteByte(hexd[b[i]>>4])
		sb.WriteByte('.')
	}
	sb.WriteString("ip6.arpa.")
	return sb.String(), nil
}

// BestZone returns the longest zone that contains name, or "".
func BestZone(name string, zones []Zone) string {
	best := ""
	for _, z := range zones {
		if InZone(name, z.Name) && len(z.Name) > len(best) {
			best = FQDN(z.Name)
		}
	}
	return best
}
