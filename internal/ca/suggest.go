package ca

import (
	"crypto/x509"
	"net"
	"sort"
	"strings"
	"time"
)

// HostRecord is an address or alias record read from a DNS server.
type HostRecord struct {
	Name   string   // fully qualified, with or without the trailing dot
	Type   string   // A, AAAA or CNAME (others are ignored)
	Values []string // addresses, or the CNAME target
	Zone   string
	Server string
}

// Holder is a certificate that may already cover a name.
type Holder struct {
	Name string
	Cert *x509.Certificate
}

// Suggestion is a certificate NCC proposes from the DNS records.
type Suggestion struct {
	Name   string   `json:"name"` // host name, or *.zone for a wildcard
	Zone   string   `json:"zone"`
	Server string   `json:"server"`
	IPs    []string `json:"ips"`
	Alias  string   `json:"alias,omitempty"` // CNAME target
	// Kind is host or wildcard.
	Kind string `json:"kind"`
	// Hosts is, for a wildcard, how many of the zone's host names it would cover.
	Hosts int `json:"hosts,omitempty"`
	// CoveredBy names a certificate that already covers this name, with its days left.
	CoveredBy   string `json:"covered_by,omitempty"`
	CoveredDays int    `json:"covered_days,omitempty"`
	// Outside is set when the internal CA's allowed domains do not include this name.
	Outside bool `json:"outside,omitempty"`
}

func isReverseZone(z string) bool {
	z = strings.TrimSuffix(strings.ToLower(z), ".")
	return strings.HasSuffix(z, "in-addr.arpa") || strings.HasSuffix(z, "ip6.arpa")
}

// Suggest turns DNS records into certificate suggestions: one per host name (A, AAAA or CNAME),
// plus a wildcard per zone with two or more names that still need one. Names a valid
// certificate already covers (for more than WarnDays) are marked, so they can be skipped.
// permitted are the CA's allowed domains (empty = any).
func Suggest(records []HostRecord, holders []Holder, permitted []string, now time.Time) []Suggestion {
	byName := map[string]*Suggestion{}
	var order []string
	for _, r := range records {
		t := strings.ToUpper(r.Type)
		if t != "A" && t != "AAAA" && t != "CNAME" {
			continue
		}
		if isReverseZone(r.Zone) {
			continue
		}
		name, err := CleanDNSName(r.Name, true)
		if err != nil || strings.HasPrefix(name, "*.") {
			continue // wildcard records and names with odd characters are not proposed one by one
		}
		if strings.HasPrefix(name, "_") || strings.Contains(name, "._") {
			continue // service labels (_dmarc, _acme-challenge...) are not hosts
		}
		s := byName[name]
		if s == nil {
			s = &Suggestion{Name: name, Zone: strings.TrimSuffix(strings.ToLower(r.Zone), "."), Server: r.Server, Kind: "host", IPs: []string{}}
			byName[name] = s
			order = append(order, name)
		}
		for _, v := range r.Values {
			v = strings.TrimSpace(v)
			if t == "CNAME" {
				s.Alias = strings.TrimSuffix(v, ".")
				continue
			}
			if ip := net.ParseIP(v); ip != nil && !contains(s.IPs, ip.String()) {
				s.IPs = append(s.IPs, ip.String())
			}
		}
	}
	cover := func(name string) (string, int) {
		bestDays := -1
		best := ""
		for _, h := range holders {
			if h.Cert == nil || h.Cert.NotAfter.Before(now) || h.Cert.NotBefore.After(now) {
				continue
			}
			if h.Cert.VerifyHostname(strings.Replace(name, "*.", "ncc-wildcard-check.", 1)) != nil {
				continue
			}
			if strings.HasPrefix(name, "*.") && !hasName(h.Cert, name) {
				continue // a wildcard is only "covered" by a certificate holding that wildcard
			}
			d := int(h.Cert.NotAfter.Sub(now).Hours() / 24)
			if d > bestDays {
				best, bestDays = h.Name, d
			}
		}
		return best, bestDays
	}
	out := []Suggestion{}
	zoneNeed := map[string]int{}
	zoneServer := map[string]string{}
	for _, n := range order {
		s := byName[n]
		s.Outside = !inDomains(n, permitted)
		if by, days := cover(n); by != "" {
			s.CoveredBy, s.CoveredDays = by, days
		}
		needs := s.CoveredBy == "" || s.CoveredDays <= 30
		if needs && !s.Outside && s.Zone != "" && strings.HasSuffix(n, "."+s.Zone) && !strings.Contains(strings.TrimSuffix(n, "."+s.Zone), ".") {
			zoneNeed[s.Zone]++
			zoneServer[s.Zone] = s.Server
		}
		out = append(out, *s)
	}
	for z, n := range zoneNeed {
		if n < 2 {
			continue
		}
		w := Suggestion{Name: "*." + z, Zone: z, Server: zoneServer[z], Kind: "wildcard", Hosts: n, IPs: []string{}, Outside: !inDomains(z, permitted)}
		if by, days := cover(w.Name); by != "" {
			w.CoveredBy, w.CoveredDays = by, days
		}
		out = append(out, w)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Zone != out[j].Zone {
			return out[i].Zone < out[j].Zone
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind == "wildcard"
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func hasName(c *x509.Certificate, n string) bool {
	for _, d := range c.DNSNames {
		if strings.EqualFold(d, n) {
			return true
		}
	}
	return false
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
