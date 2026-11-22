package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/dns"
	"github.com/dertown/network-control-centre/internal/dnscheck"
)

// The DNS chain check: routers hand out the internal DNS server, which forwards internet
// queries to the ISP. Each DNS poll also reads the resolver side (its addresses and its
// forwarders) into dns_resolver_status; DNSChain combines that with the routers' latest
// snapshots. The rules live in internal/dnscheck.

// ResolverStatus is what one DNS server connection last reported about its resolver.
type ResolverStatus struct {
	CheckedAt  time.Time       `json:"checked_at"`
	Addresses  []string        `json:"addresses"`
	Forwarding *dns.Forwarding `json:"forwarding,omitempty"`
	NoResolver bool            `json:"no_resolver,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// Options on a DNS server connection used by the check.
const (
	// OptResolverIPs are the addresses clients should be handed (comma separated). Without
	// it NCC uses the address of the Recursor API URL or of the connection.
	OptResolverIPs = "resolver_ips"
	// OptISPDNS are the ISP's DNS servers (comma separated). Without it NCC uses what the
	// router learned from the provider on its WAN.
	OptISPDNS = "isp_dns"
	// OptRecursorURL is the PowerDNS Recursor API base.
	OptRecursorURL = "recursor_url"
)

// lookupHost is replaced in tests.
var lookupHost = func(h string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupHost(ctx, h)
}

// resolverAddresses is what clients should get as DNS for a DNS server connection.
func resolverAddresses(t *Target) []string {
	if v := strings.TrimSpace(t.Options[OptResolverIPs]); v != "" {
		return dnscheck.SplitList(v)
	}
	from := t.Options[OptRecursorURL]
	if strings.TrimSpace(from) == "" {
		from = t.Address
	}
	var out []string
	for _, a := range dnscheck.HostAddresses(from, lookupHost) {
		// NCC on the same machine reaches it on loopback, which is no use to clients
		if ip, err := netip.ParseAddr(a); err == nil && !ip.IsLoopback() {
			out = append(out, a)
		}
	}
	return out
}

// readResolver reads and stores the resolver side of one DNS server connection. Failures
// are recorded in the status, not returned: they don't make the connection itself fail.
func (p *Poller) readResolver(ctx context.Context, t *Target, prov dns.Provider, creds map[string]string) {
	st := ResolverStatus{CheckedAt: time.Now().UTC(), Addresses: resolverAddresses(t)}
	if f, ok := prov.(dns.Forwarder); ok {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		fwd, err := f.Forwarders(cctx, dns.Server{ID: t.ID, Name: t.Name, Kind: t.Kind, Address: t.Address, Options: t.Options}, creds)
		cancel()
		switch {
		case errors.Is(err, dns.ErrNoResolver):
			st.NoResolver = true
		case err != nil:
			st.Error = err.Error()
		default:
			st.Forwarding = fwd
		}
	} else {
		st.NoResolver = true
	}
	if err := SaveResolverStatus(ctx, p.DB, t.ID, st); err != nil && p.Log != nil {
		p.Log.Warn("save resolver status", "target", t.Name, "err", err)
	}
}

// SaveResolverStatus replaces the stored resolver status of one DNS server connection.
func SaveResolverStatus(ctx context.Context, db *sql.DB, targetID int64, st ResolverStatus) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO dns_resolver_status (target_id, checked_at, data) VALUES (?,?,?)
		ON CONFLICT(target_id) DO UPDATE SET checked_at = excluded.checked_at, data = excluded.data`,
		targetID, st.CheckedAt.Format(time.RFC3339Nano), string(b))
	return err
}

func resolverStatuses(ctx context.Context, db *sql.DB) (map[int64]ResolverStatus, error) {
	rows, err := db.QueryContext(ctx, `SELECT target_id, data FROM dns_resolver_status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]ResolverStatus{}
	for rows.Next() {
		var id int64
		var raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		var st ResolverStatus
		if json.Unmarshal([]byte(raw), &st) == nil {
			out[id] = st
		}
	}
	return out, rows.Err()
}

// DNSChain runs the DNS chain check from the routers' latest snapshots and the DNS
// servers' last resolver status.
func DNSChain(ctx context.Context, db *sql.DB, targets *Targets) (dnscheck.Report, error) {
	all, err := targets.List(ctx, "")
	if err != nil {
		return dnscheck.Report{}, err
	}
	snaps, err := LatestSnapshots(ctx, db)
	if err != nil {
		return dnscheck.Report{}, err
	}
	statuses, err := resolverStatuses(ctx, db)
	if err != nil {
		return dnscheck.Report{}, err
	}
	byName := map[string]Target{}
	var servers []dnscheck.Resolver
	for _, t := range all {
		if !t.Enabled {
			continue
		}
		byName[t.Name] = t
		if t.Category != CategoryDNS {
			continue
		}
		r := dnscheck.Resolver{ID: t.ID, Name: t.Name, ISP: dnscheck.SplitList(t.Options[OptISPDNS])}
		if st, ok := statuses[t.ID]; ok {
			r.Addresses, r.Forwarding, r.NoResolver, r.Error = st.Addresses, st.Forwarding, st.NoResolver, st.Error
		} else {
			r.Addresses = resolverAddresses(&t)
		}
		servers = append(servers, r)
	}
	var routers []dnscheck.Router
	for _, s := range snaps {
		t, ok := byName[s.Target]
		if !ok || t.Category != CategoryDevice || len(s.Networks) == 0 {
			continue
		}
		routers = append(routers, dnscheck.Router{Name: s.Target, Kind: t.Kind, URL: adminURL(t.Address), Networks: s.Networks})
	}
	return dnscheck.Evaluate(routers, servers), nil
}

// adminURL turns a connection address into a link a browser can open, or "".
func adminURL(a string) string {
	a = strings.TrimSpace(a)
	if a == "" {
		return ""
	}
	if !strings.Contains(a, "://") {
		a = "https://" + a
	}
	if strings.HasPrefix(a, "http://") || strings.HasPrefix(a, "https://") {
		return a
	}
	return ""
}
