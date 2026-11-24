// Package dns defines the DNS provider interface and shared helpers.
package dns

import (
	"context"
	"errors"
	"fmt"
	"github.com/dertown/network-control-centre/internal/catalog"
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

// Forwarding is how a resolver answers names it is not authoritative for (the internet).
type Forwarding struct {
	// Source says where NCC read this, e.g. "PowerDNS Recursor at http://ns1:8082".
	Source string `json:"source"`
	// Servers are the upstream resolvers internet queries ("." and below) are forwarded to,
	// without ports. Empty means the resolver does full recursion from the root servers itself.
	Servers []string `json:"servers"`
	// RecursionDesired is set when forwarded queries ask the upstream to recurse, which a
	// provider's resolver needs (PowerDNS forward-zones-recurse rather than forward-zones).
	RecursionDesired bool `json:"recursion_desired"`
}

// ErrNoResolver is returned by Forwarders when the connection has no resolver NCC can read
// (e.g. an authoritative-only server with no recursor configured).
var ErrNoResolver = errors.New("no resolver to read")

// Forwarder is implemented by providers that can read the upstream resolvers their server
// forwards internet queries to.
type Forwarder interface {
	Forwarders(ctx context.Context, s Server, creds map[string]string) (*Forwarding, error)
}

var (
	mu        sync.RWMutex
	providers = map[string]Provider{}
)

// Register adds a provider and its entries for the Settings wizard (see package catalog).
func Register(p Provider, entries ...catalog.Vendor) {
	mu.Lock()
	providers[p.Kind()] = p
	mu.Unlock()
	catalog.Register(p.Kind(), "dns", entries...)
}

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

// ZoneSpec describes a zone to create.
type ZoneSpec struct {
	Name string `json:"name"` // fully qualified, trailing dot
	// Kind is the provider's zone kind; PowerDNS: Native (default), Master or Slave.
	Kind string `json:"kind,omitempty"`
	// Nameservers are the zone's NS host names. At least one is required.
	Nameservers []string `json:"nameservers"`
}

// ZoneManager is implemented by providers that can create and delete zones.
type ZoneManager interface {
	CreateZone(ctx context.Context, s Server, creds map[string]string, spec ZoneSpec) error
	DeleteZone(ctx context.Context, s Server, creds map[string]string, zone string) error
}

// ValidateZoneName checks a zone name such as "iot.corp.lan." and returns it fully qualified.
func ValidateZoneName(name string) (string, error) {
	fq := FQDN(name)
	if fq == "." {
		return "", errors.New("a zone name is required")
	}
	if len(fq) > 254 {
		return "", errors.New("the zone name is longer than 253 characters")
	}
	labels := strings.Split(strings.TrimSuffix(fq, "."), ".")
	if len(labels) < 2 && !strings.HasSuffix(fq, ".arpa.") {
		return "", fmt.Errorf("%s is a top-level name; use a domain such as %scorp.lan.", fq, fq)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return "", fmt.Errorf("%q is not a valid zone name (empty or over-long label)", name)
		}
		for i, r := range l {
			ok := r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
			if !ok || (r == '-' && (i == 0 || i == len(l)-1)) {
				return "", fmt.Errorf("%q is not a valid zone name: label %q may only hold letters, digits and inner hyphens", name, l)
			}
		}
	}
	return fq, nil
}

// ParentZone returns the longest zone in zones that strictly contains zone, or "".
func ParentZone(zone string, zones []Zone) string {
	zone = FQDN(zone)
	best := ""
	for _, z := range zones {
		n := FQDN(z.Name)
		if n != zone && InZone(zone, n) && len(n) > len(best) {
			best = n
		}
	}
	return best
}

// ReverseZone returns the reverse-lookup zone for a subnet: the in-addr.arpa zone at the
// nearest whole-octet boundary (a /22 gets the /16 zone, a /26 the /24 zone), or for IPv6
// the ip6.arpa zone at the nearest nibble.
func ReverseZone(p netip.Prefix) string {
	p = p.Masked()
	a := p.Addr()
	if a.Is4() {
		bits := p.Bits() / 8 * 8
		if p.Bits() > 24 {
			bits = 24
		}
		if bits == 0 {
			return "in-addr.arpa."
		}
		b := a.As4()
		parts := make([]string, 0, 3)
		for i := bits/8 - 1; i >= 0; i-- {
			parts = append(parts, fmt.Sprint(b[i]))
		}
		return strings.Join(parts, ".") + ".in-addr.arpa."
	}
	nibbles := p.Bits() / 4
	full, _ := PTRName(a.String()) // 32 nibbles, least significant first
	labels := strings.Split(strings.TrimSuffix(full, "ip6.arpa."), ".")
	labels = labels[:32]
	return strings.Join(append(labels[32-nibbles:], "ip6.arpa."), ".")
}
