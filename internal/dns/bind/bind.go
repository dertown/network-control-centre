// Package bind implements the NCC DNS provider for BIND 9 and any other server that speaks
// standard DNS: zones are read with a zone transfer (AXFR) and changed with RFC 2136 dynamic
// updates, both signed with a TSIG key. Knot DNS, NSD (read only), Technitium and Windows DNS
// with secure updates off work the same way.
package bind

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/catalog"
	"github.com/dertown/network-control-centre/internal/dns"
	mdns "github.com/miekg/dns"
)

// Options.
const (
	OptZones     = "zones"          // the zones to manage, comma or space separated (DNS has no "list zones" query)
	OptTSIGName  = "tsig_name"      // the key name in named.conf, e.g. ncc-key
	OptTSIGAlg   = "tsig_algorithm" // hmac-sha256 (default), hmac-sha512, hmac-sha1
	SecretTSIG   = "tsig_secret"    // the key's base64 secret
	defaultPort  = "53"
	queryTimeout = 10 * time.Second
)

func init() {
	dns.Register(Provider{}, catalog.Vendor{
		Label: "BIND 9", Groups: []string{catalog.GroupDNS}, Order: 20,
		Summary: "BIND, Knot or any RFC 2136 server: zone transfers to read, signed dynamic updates to change.",
		Help: "NCC reads zones with a zone transfer and changes them with dynamic updates, both signed with a TSIG key. Make a key " +
			"with tsig-keygen ncc-key >> /etc/bind/named.conf.local, then in each zone add allow-transfer { key ncc-key; }; and " +
			"update-policy { grant ncc-key zonesub ANY; }; and reload BIND. Paste the key's name and secret here and list the zones " +
			"NCC should manage (DNS has no way to list a server's zones).",
		NameDefault: "bind", AddressKind: catalog.AddressHost, AddressDefault: "192.168.1.53",
		AddressLabel: "Server address (host or host:port)",
		Fields: []catalog.Field{
			{Key: OptZones, Label: "Zones", Type: catalog.Text, Store: catalog.StoreOption, Required: true, Placeholder: "home.lan, 1.168.192.in-addr.arpa"},
			{Key: OptTSIGName, Label: "TSIG key name", Type: catalog.Text, Store: catalog.StoreOption, Default: "ncc-key", Required: true},
			{Key: OptTSIGAlg, Label: "Algorithm", Type: catalog.Select, Store: catalog.StoreOption, Default: "hmac-sha256", Choices: []catalog.Choice{
				{Value: "hmac-sha256", Label: "HMAC-SHA256"}, {Value: "hmac-sha512", Label: "HMAC-SHA512"}, {Value: "hmac-sha1", Label: "HMAC-SHA1 (old)"}}},
			{Key: SecretTSIG, Label: "TSIG secret (base64)", Type: catalog.Token, Store: catalog.StoreSecret, Required: true},
		},
	})
}

// Provider implements dns.Provider for BIND.
type Provider struct{}

// Kind implements dns.Provider.
func (Provider) Kind() string { return "bind" }

type conn struct {
	addr    string
	zones   []string
	keyName string // fully qualified, empty without TSIG
	alg     string
	secret  string
}

func newConn(s dns.Server, creds map[string]string) (*conn, error) {
	addr := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(s.Address, "dns://"), "tcp://"))
	if addr == "" {
		return nil, errors.New("bind: no server address")
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), defaultPort)
	}
	c := &conn{addr: addr}
	for _, z := range strings.FieldsFunc(s.Options[OptZones], func(r rune) bool { return r == ',' || r == ' ' || r == ';' || r == '\n' }) {
		c.zones = append(c.zones, dns.FQDN(z))
	}
	if name := strings.TrimSpace(s.Options[OptTSIGName]); name != "" && creds[SecretTSIG] != "" {
		c.keyName = mdns.Fqdn(strings.ToLower(name))
		c.secret = strings.TrimSpace(creds[SecretTSIG])
		switch strings.ToLower(s.Options[OptTSIGAlg]) {
		case "hmac-sha512":
			c.alg = mdns.HmacSHA512
		case "hmac-sha1":
			c.alg = mdns.HmacSHA1
		default:
			c.alg = mdns.HmacSHA256
		}
	}
	return c, nil
}

func (c *conn) client() *mdns.Client {
	cl := &mdns.Client{Net: "tcp", Timeout: queryTimeout}
	if c.keyName != "" {
		cl.TsigSecret = map[string]string{c.keyName: c.secret}
	}
	return cl
}

func (c *conn) sign(m *mdns.Msg) {
	if c.keyName != "" {
		m.SetTsig(c.keyName, c.alg, 300, time.Now().Unix())
	}
}

func (c *conn) exchange(ctx context.Context, m *mdns.Msg) (*mdns.Msg, error) {
	c.sign(m)
	r, _, err := c.client().ExchangeContext(ctx, m, c.addr)
	if err != nil {
		return nil, fmt.Errorf("bind: %s: %w", c.addr, err)
	}
	if r.Rcode != mdns.RcodeSuccess {
		return r, fmt.Errorf("bind: %s answered %s", c.addr, mdns.RcodeToString[r.Rcode])
	}
	return r, nil
}

func (c *conn) soa(ctx context.Context, zone string) (*mdns.SOA, error) {
	m := new(mdns.Msg)
	m.SetQuestion(zone, mdns.TypeSOA)
	m.RecursionDesired = false
	r, err := c.exchange(ctx, m)
	if err != nil {
		return nil, fmt.Errorf("%w (zone %s)", err, zone)
	}
	for _, rr := range r.Answer {
		if s, ok := rr.(*mdns.SOA); ok {
			return s, nil
		}
	}
	return nil, fmt.Errorf("bind: %s is not authoritative for %s (no SOA in the answer)", c.addr, zone)
}

// ListZones implements dns.Provider: the configured zones, each checked with a SOA query.
func (Provider) ListZones(ctx context.Context, s dns.Server, creds map[string]string) ([]dns.Zone, error) {
	c, err := newConn(s, creds)
	if err != nil {
		return nil, err
	}
	out := []dns.Zone{}
	for _, z := range c.zones {
		soa, err := c.soa(ctx, z)
		if err != nil {
			return nil, err
		}
		out = append(out, dns.Zone{Name: z, Kind: "Master", Serial: soa.Serial})
	}
	return out, nil
}

// Check implements dns.Checker: a SOA query for the first zone, so a wrong address or a zone
// the server doesn't serve shows up straight away (TSIG problems show on the first transfer).
func (Provider) Check(ctx context.Context, s dns.Server, creds map[string]string) error {
	c, err := newConn(s, creds)
	if err != nil {
		return err
	}
	if len(c.zones) == 0 {
		return errors.New("bind: list the zones NCC should manage (Settings → Edit)")
	}
	_, err = c.soa(ctx, c.zones[0])
	return err
}

// content is an RR's presentation-format data, without the owner, TTL, class and type.
func content(rr mdns.RR) string {
	return strings.TrimSpace(strings.TrimPrefix(rr.String(), rr.Header().String()))
}

var skipTypes = map[uint16]bool{mdns.TypeRRSIG: true, mdns.TypeNSEC: true, mdns.TypeNSEC3: true, mdns.TypeNSEC3PARAM: true, mdns.TypeDNSKEY: true, mdns.TypeTSIG: true}

// ListRecords implements dns.Provider with a zone transfer.
func (Provider) ListRecords(ctx context.Context, s dns.Server, creds map[string]string, zone string) ([]dns.RRSet, error) {
	c, err := newConn(s, creds)
	if err != nil {
		return nil, err
	}
	zone = dns.FQDN(zone)
	m := new(mdns.Msg)
	m.SetAxfr(zone)
	c.sign(m)
	tr := &mdns.Transfer{DialTimeout: queryTimeout, ReadTimeout: 30 * time.Second}
	if c.keyName != "" {
		tr.TsigSecret = map[string]string{c.keyName: c.secret}
	}
	dl, ok := ctx.Deadline()
	conn, err := (&net.Dialer{Timeout: queryTimeout}).DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("bind: %s: %w", c.addr, err)
	}
	if ok {
		_ = conn.SetDeadline(dl)
	}
	tr.Conn = &mdns.Conn{Conn: conn}
	ch, err := tr.In(m, c.addr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("bind: zone transfer of %s: %w", zone, err)
	}
	type key struct{ name, typ string }
	sets := map[key]*dns.RRSet{}
	var order []key
	soaSeen := false
	for env := range ch {
		if env.Error != nil {
			return nil, fmt.Errorf("bind: zone transfer of %s: %w (does the zone allow transfers with this key?)", zone, env.Error)
		}
		for _, rr := range env.RR {
			h := rr.Header()
			if skipTypes[h.Rrtype] {
				continue
			}
			if h.Rrtype == mdns.TypeSOA {
				if soaSeen { // AXFR ends with the SOA again
					continue
				}
				soaSeen = true
			}
			k := key{strings.ToLower(h.Name), mdns.TypeToString[h.Rrtype]}
			set := sets[k]
			if set == nil {
				set = &dns.RRSet{Name: k.name, Type: k.typ, TTL: int(h.Ttl)}
				sets[k] = set
				order = append(order, k)
			}
			set.Records = append(set.Records, content(rr))
		}
	}
	out := make([]dns.RRSet, 0, len(order))
	for _, k := range order {
		out = append(out, *sets[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Type < out[j].Type
	})
	return out, nil
}

// Apply implements dns.Provider with one signed dynamic update per call: every change goes
// through together or not at all.
func (Provider) Apply(ctx context.Context, s dns.Server, creds map[string]string, zone string, changes []dns.Change) error {
	c, err := newConn(s, creds)
	if err != nil {
		return err
	}
	m, err := updateMsg(dns.FQDN(zone), changes)
	if err != nil {
		return err
	}
	_, err = c.exchange(ctx, m)
	return err
}

// updateMsg builds the RFC 2136 update for changes. A replace deletes the RRset and adds
// the new records; the SOA is replaced by adding the new one (it can't be deleted).
func updateMsg(zone string, changes []dns.Change) (*mdns.Msg, error) {
	m := new(mdns.Msg)
	m.SetUpdate(zone)
	for _, ch := range changes {
		name, typ := dns.FQDN(ch.RRSet.Name), strings.ToUpper(ch.RRSet.Type)
		t, ok := mdns.StringToType[typ]
		if !ok {
			return nil, fmt.Errorf("bind: unknown record type %q", typ)
		}
		if t != mdns.TypeSOA {
			m.RemoveRRset([]mdns.RR{&mdns.ANY{Hdr: mdns.RR_Header{Name: name, Rrtype: t, Class: mdns.ClassINET}}})
		}
		if ch.Op == dns.Delete {
			continue
		}
		var add []mdns.RR
		for _, v := range ch.RRSet.Records {
			rr, err := mdns.NewRR(fmt.Sprintf("%s %d IN %s %s", name, ch.RRSet.TTL, typ, v))
			if err != nil || rr == nil {
				return nil, fmt.Errorf("bind: %s %s %q: %v", name, typ, v, err)
			}
			add = append(add, rr)
		}
		m.Insert(add)
	}
	return m, nil
}
