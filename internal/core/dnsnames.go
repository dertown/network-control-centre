package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/dns"
)

// dnsNamesEvery is how often a DNS server's address records are read again. Listing every
// zone is heavier than the connection check that runs on each poll.
const dnsNamesEvery = 15 * time.Minute

// dnsNamesMax caps how many names one server contributes, and dnsZonesMax how many zones
// are read, so a huge server can't make polling slow.
const (
	dnsNamesMax = 20000
	dnsZonesMax = 200
)

// DNSName ties a host name to an address, as one DNS server records it.
type DNSName struct {
	Name   string `json:"name"` // fully qualified, no trailing dot, lower case
	IP     string `json:"ip"`
	Type   string `json:"type"`   // A, AAAA or PTR
	Server string `json:"server"` // DNS connection name
}

// readDNSNames refreshes the cached address records of one DNS server, at most every
// dnsNamesEvery. Failures are only logged: names are a nice-to-have for the map.
func (p *Poller) readDNSNames(ctx context.Context, t *Target, prov dns.Provider, creds map[string]string) {
	var at string
	if p.DB.QueryRowContext(ctx, `SELECT taken_at FROM dns_names WHERE target_id = ?`, t.ID).Scan(&at) == nil {
		if ts, err := time.Parse(time.RFC3339Nano, at); err == nil && time.Since(ts) < dnsNamesEvery {
			return
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	srv := dns.Server{ID: t.ID, Name: t.Name, Kind: t.Kind, Address: t.Address, Options: t.Options}
	zones, err := prov.ListZones(cctx, srv, creds)
	if err != nil {
		return
	}
	if len(zones) > dnsZonesMax {
		zones = zones[:dnsZonesMax]
	}
	var out []DNSName
	for _, z := range zones {
		sets, err := prov.ListRecords(cctx, srv, creds, z.Name)
		if err != nil {
			continue
		}
		out = append(out, AddressNames(t.Name, sets)...)
		if len(out) >= dnsNamesMax {
			out = out[:dnsNamesMax]
			break
		}
	}
	if err := SaveDNSNames(ctx, p.DB, t.ID, out); err != nil && p.Log != nil {
		p.Log.Warn("save DNS names", "target", t.Name, "err", err)
	}
}

// AddressNames picks the name-to-address pairs out of a zone's records: A and AAAA records,
// and PTR records in reverse zones.
func AddressNames(server string, sets []dns.RRSet) []DNSName {
	var out []DNSName
	for _, rs := range sets {
		name := strings.ToLower(strings.TrimSuffix(rs.Name, "."))
		switch rs.Type {
		case "A", "AAAA":
			for _, r := range rs.Records {
				if a, err := netip.ParseAddr(strings.TrimSpace(r)); err == nil {
					out = append(out, DNSName{Name: name, IP: a.String(), Type: rs.Type, Server: server})
				}
			}
		case "PTR":
			ip, ok := reverseIP(name)
			if !ok {
				continue
			}
			for _, r := range rs.Records {
				if n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r), ".")); n != "" {
					out = append(out, DNSName{Name: n, IP: ip, Type: "PTR", Server: server})
				}
			}
		}
	}
	return out
}

// reverseIP turns "20.1.168.192.in-addr.arpa" into "192.168.1.20" (IPv6 ip6.arpa too).
func reverseIP(name string) (string, bool) {
	if v4, ok := strings.CutSuffix(name, ".in-addr.arpa"); ok {
		parts := strings.Split(v4, ".")
		if len(parts) != 4 {
			return "", false
		}
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		a, err := netip.ParseAddr(strings.Join(parts, "."))
		return a.String(), err == nil
	}
	if v6, ok := strings.CutSuffix(name, ".ip6.arpa"); ok {
		nib := strings.Split(v6, ".")
		if len(nib) != 32 {
			return "", false
		}
		var b strings.Builder
		for i := len(nib) - 1; i >= 0; i-- {
			b.WriteString(nib[i])
			if i%4 == 0 && i > 0 {
				b.WriteByte(':')
			}
		}
		a, err := netip.ParseAddr(b.String())
		return a.String(), err == nil
	}
	return "", false
}

// SaveDNSNames replaces the cached address records of one DNS server.
func SaveDNSNames(ctx context.Context, db *sql.DB, targetID int64, names []DNSName) error {
	if names == nil {
		names = []DNSName{}
	}
	b, err := json.Marshal(names)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO dns_names (target_id, taken_at, data) VALUES (?,?,?)
		ON CONFLICT(target_id) DO UPDATE SET taken_at = excluded.taken_at, data = excluded.data`,
		targetID, time.Now().UTC().Format(time.RFC3339Nano), string(b))
	return err
}

// LatestDNSNames returns the cached address records of every enabled DNS server.
func LatestDNSNames(ctx context.Context, db *sql.DB) ([]DNSName, error) {
	rows, err := db.QueryContext(ctx, `SELECT d.data FROM dns_names d JOIN targets t ON t.id = d.target_id
		WHERE t.enabled = 1 ORDER BY t.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DNSName
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var ns []DNSName
		if json.Unmarshal([]byte(raw), &ns) == nil {
			out = append(out, ns...)
		}
	}
	return out, rows.Err()
}
