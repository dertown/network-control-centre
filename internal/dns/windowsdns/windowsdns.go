// Package windowsdns implements the NCC DNS provider for Windows Server DNS, including Active
// Directory-integrated zones on domain controllers. It runs the DnsServer PowerShell module's
// cmdlets over WinRM, so it sees exactly what DNS Manager shows and changes records the same way.
package windowsdns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/dertown/network-control-centre/internal/catalog"
	"github.com/dertown/network-control-centre/internal/dns"
	"github.com/dertown/network-control-centre/internal/winps"
)

// OptReplication is where new zones are stored: Domain (default), Forest, Legacy (AD) or File.
const OptReplication = "replication"

func init() {
	dns.Register(Provider{}, catalog.Vendor{
		Label: "Active Directory DNS (Windows Server)", Groups: []string{catalog.GroupDNS}, Order: 30,
		Summary: "AD-integrated and file-backed zones on a domain controller or Windows DNS server, over WinRM.",
		Help: "Use a domain controller (or any Windows DNS server) and an account in the DnsAdmins group; to only read, any " +
			"domain user with read access to the zones will do. " + winps.Help,
		NameDefault: "ad-dns", AddressKind: catalog.AddressHost, AddressDefault: "dc01.corp.example", AddressLabel: "Server (host name or address)",
		Fields: append(winps.Fields(`CORP\ncc-dns`), catalog.Field{
			Key: OptReplication, Label: "New zones are stored", Type: catalog.Select, Store: catalog.StoreOption, Default: "Domain",
			Choices: []catalog.Choice{{Value: "Domain", Label: "In AD, all DNS servers in the domain"}, {Value: "Forest", Label: "In AD, all DNS servers in the forest"},
				{Value: "File", Label: "In a zone file (non-AD server)"}},
		}),
	})
}

// Provider implements dns.Provider for Windows DNS.
type Provider struct{}

// Kind implements dns.Provider.
func (Provider) Kind() string { return "windowsdns" }

func shell(ctx context.Context, s dns.Server, creds map[string]string) (winps.Shell, error) {
	sh, err := winps.Dial(ctx, s.Address, s.Options, creds)
	if err != nil {
		return nil, fmt.Errorf("windows dns: %w", err)
	}
	return sh, nil
}

// runJSON runs a script whose output is one JSON document and decodes it.
func runJSON(ctx context.Context, sh winps.Shell, script string, out any) error {
	raw, err := sh.Run(ctx, script)
	if err != nil {
		return fmt.Errorf("windows dns: %w", err)
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "[]"
	}
	if err := json.Unmarshal([]byte(raw), out); err != nil {
		return fmt.Errorf("windows dns: unexpected answer from PowerShell: %w", err)
	}
	return nil
}

const zonesScript = `ConvertTo-Json -Compress -InputObject @(Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' } | ForEach-Object { [pscustomobject]@{n=$_.ZoneName;t=[string]$_.ZoneType;ad=[bool]$_.IsDsIntegrated} })`

// ListZones implements dns.Provider.
func (Provider) ListZones(ctx context.Context, s dns.Server, creds map[string]string) ([]dns.Zone, error) {
	sh, err := shell(ctx, s, creds)
	if err != nil {
		return nil, err
	}
	defer sh.Close()
	var zs []struct {
		N  string `json:"n"`
		T  string `json:"t"`
		AD bool   `json:"ad"`
	}
	if err := runJSON(ctx, sh, zonesScript, &zs); err != nil {
		return nil, err
	}
	out := make([]dns.Zone, 0, len(zs))
	for _, z := range zs {
		kind := z.T
		if z.AD {
			kind += " (AD)"
		}
		out = append(out, dns.Zone{Name: dns.FQDN(z.N), Kind: kind})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Check implements dns.Checker: the DnsServer module answers and the account may read zones.
func (p Provider) Check(ctx context.Context, s dns.Server, creds map[string]string) error {
	_, err := p.ListZones(ctx, s, creds)
	return err
}

// recordsScript lists a zone's records as {n: host, t: type, ttl, v: presentation value}.
func recordsScript(zone string) string {
	return `$z=` + winps.Quote(strings.TrimSuffix(zone, ".")) + `
ConvertTo-Json -Compress -InputObject @(Get-DnsServerResourceRecord -ZoneName $z | Where-Object { $_.RecordType -in 'A','AAAA','CNAME','MX','NS','PTR','SRV','TXT','SOA' } | ForEach-Object {
$d=$_.RecordData
$v=switch($_.RecordType){
'A'{$d.IPv4Address.IPAddressToString}
'AAAA'{$d.IPv6Address.IPAddressToString}
'CNAME'{$d.HostNameAlias}
'PTR'{$d.PtrDomainName}
'NS'{$d.NameServer}
'MX'{"$($d.Preference) $($d.MailExchange)"}
'SRV'{"$($d.Priority) $($d.Weight) $($d.Port) $($d.DomainName)"}
'TXT'{$d.DescriptiveText}
'SOA'{"$($d.PrimaryServer) $($d.ResponsiblePerson) $($d.SerialNumber) $([int]$d.RefreshInterval.TotalSeconds) $([int]$d.RetryDelay.TotalSeconds) $([int]$d.ExpireLimit.TotalSeconds) $([int]$d.MinimumTimeToLive.TotalSeconds)"}
}
[pscustomobject]@{n=$_.HostName;t=[string]$_.RecordType;ttl=[int]$_.TimeToLive.TotalSeconds;v=[string]$v}})`
}

type record struct {
	N   string `json:"n"`
	T   string `json:"t"`
	TTL int    `json:"ttl"`
	V   string `json:"v"`
}

// toRRSets groups Windows records into RRsets with full names and presentation values.
func toRRSets(zone string, recs []record) []dns.RRSet {
	zone = dns.FQDN(zone)
	type key struct{ n, t string }
	sets := map[key]*dns.RRSet{}
	var order []key
	for _, r := range recs {
		name := zone
		if r.N != "@" && r.N != "" {
			name = dns.FQDN(r.N + "." + zone)
		}
		v := strings.TrimSpace(r.V)
		switch r.T {
		case "CNAME", "PTR", "NS":
			v = dns.FQDN(v)
		case "MX", "SRV":
			if f := strings.Fields(v); len(f) > 0 {
				f[len(f)-1] = dns.FQDN(f[len(f)-1])
				v = strings.Join(f, " ")
			}
		case "TXT":
			v = strconv.Quote(v)
		case "SOA":
			if f := strings.Fields(v); len(f) > 2 {
				f[0], f[1] = dns.FQDN(f[0]), dns.FQDN(f[1])
				v = strings.Join(f, " ")
			}
		}
		k := key{name, r.T}
		if sets[k] == nil {
			sets[k] = &dns.RRSet{Name: name, Type: r.T, TTL: r.TTL}
			order = append(order, k)
		}
		sets[k].Records = append(sets[k].Records, v)
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
	return out
}

// ListRecords implements dns.Provider.
func (Provider) ListRecords(ctx context.Context, s dns.Server, creds map[string]string, zone string) ([]dns.RRSet, error) {
	sh, err := shell(ctx, s, creds)
	if err != nil {
		return nil, err
	}
	defer sh.Close()
	var recs []record
	if err := runJSON(ctx, sh, recordsScript(dns.FQDN(zone)), &recs); err != nil {
		return nil, err
	}
	return toRRSets(zone, recs), nil
}

func relName(name, zone string) string {
	name, zone = dns.FQDN(name), dns.FQDN(zone)
	if name == zone {
		return "@"
	}
	return strings.TrimSuffix(name, "."+zone)
}

func host(s string) string { return strings.TrimSuffix(strings.TrimSpace(s), ".") }

// changeScript replaces or deletes one RRset: the old records go, then each new value is added.
func changeScript(zone string, ch dns.Change) (string, error) {
	typ := strings.ToUpper(ch.RRSet.Type)
	if typ == "SOA" {
		return "", errors.New("windows dns: change the SOA record in DNS Manager")
	}
	q := winps.Quote
	var b strings.Builder
	fmt.Fprintf(&b, "$z=%s;$n=%s\n", q(strings.TrimSuffix(dns.FQDN(zone), ".")), q(relName(ch.RRSet.Name, zone)))
	fmt.Fprintf(&b, "Get-DnsServerResourceRecord -ZoneName $z -Name $n -RRType %s -ErrorAction SilentlyContinue | Where-Object { $_.HostName -eq $n } | Remove-DnsServerResourceRecord -ZoneName $z -Force\n", typ)
	if ch.Op == dns.Delete {
		return b.String(), nil
	}
	fmt.Fprintf(&b, "$t=New-TimeSpan -Seconds %d\n", ch.RRSet.TTL)
	for _, v := range ch.RRSet.Records {
		f := strings.Fields(v)
		bad := fmt.Errorf("windows dns: %s record %q is not valid", typ, v)
		add := "Add-DnsServerResourceRecord -ZoneName $z -Name $n -TimeToLive $t "
		switch typ {
		case "A":
			b.WriteString(add + "-A -IPv4Address " + q(v))
		case "AAAA":
			b.WriteString(add + "-AAAA -IPv6Address " + q(v))
		case "CNAME":
			b.WriteString(add + "-CName -HostNameAlias " + q(host(v)))
		case "PTR":
			b.WriteString(add + "-Ptr -PtrDomainName " + q(host(v)))
		case "NS":
			b.WriteString(add + "-NS -NameServer " + q(host(v)))
		case "MX":
			if len(f) != 2 {
				return "", bad
			}
			if _, err := strconv.Atoi(f[0]); err != nil {
				return "", bad
			}
			b.WriteString(add + "-MX -Preference " + f[0] + " -MailExchange " + q(host(f[1])))
		case "SRV":
			if len(f) != 4 {
				return "", bad
			}
			for _, n := range f[:3] {
				if _, err := strconv.Atoi(n); err != nil {
					return "", bad
				}
			}
			b.WriteString(add + "-Srv -Priority " + f[0] + " -Weight " + f[1] + " -Port " + f[2] + " -DomainName " + q(host(f[3])))
		case "TXT":
			txt := strings.TrimSpace(v)
			if u, err := strconv.Unquote(txt); err == nil {
				txt = u
			}
			b.WriteString(add + "-Txt -DescriptiveText " + q(txt))
		default:
			return "", fmt.Errorf("windows dns: %s records are not supported", typ)
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

// Apply implements dns.Provider: one script per RRset, run in order over one connection. Every
// script is built before anything runs, so a bad value stops the change before it starts.
func (Provider) Apply(ctx context.Context, s dns.Server, creds map[string]string, zone string, changes []dns.Change) error {
	scripts := make([]string, 0, len(changes))
	for _, ch := range changes {
		sc, err := changeScript(zone, ch)
		if err != nil {
			return err
		}
		scripts = append(scripts, sc)
	}
	sh, err := shell(ctx, s, creds)
	if err != nil {
		return err
	}
	defer sh.Close()
	for i, sc := range scripts {
		if _, err := sh.Run(ctx, sc); err != nil {
			return fmt.Errorf("windows dns: %s %s: %w", changes[i].RRSet.Name, changes[i].RRSet.Type, err)
		}
	}
	return nil
}

// CreateZone implements dns.ZoneManager: an AD-integrated primary zone (or a file-backed one
// on a server that isn't a domain controller). Windows adds the SOA and NS records itself.
func (Provider) CreateZone(ctx context.Context, s dns.Server, creds map[string]string, spec dns.ZoneSpec) error {
	z := strings.TrimSuffix(dns.FQDN(spec.Name), ".")
	script := "Add-DnsServerPrimaryZone -Name " + winps.Quote(z) + " -DynamicUpdate Secure -ReplicationScope "
	switch s.Options[OptReplication] {
	case "Forest":
		script += "Forest"
	case "File":
		script = "Add-DnsServerPrimaryZone -Name " + winps.Quote(z) + " -ZoneFile " + winps.Quote(z+".dns")
	default:
		script += "Domain"
	}
	sh, err := shell(ctx, s, creds)
	if err != nil {
		return err
	}
	defer sh.Close()
	if _, err := sh.Run(ctx, script); err != nil {
		return fmt.Errorf("windows dns: create %s: %w", z, err)
	}
	return nil
}

// DeleteZone implements dns.ZoneManager.
func (Provider) DeleteZone(ctx context.Context, s dns.Server, creds map[string]string, zone string) error {
	sh, err := shell(ctx, s, creds)
	if err != nil {
		return err
	}
	defer sh.Close()
	if _, err := sh.Run(ctx, "Remove-DnsServerZone -Name "+winps.Quote(strings.TrimSuffix(dns.FQDN(zone), "."))+" -Force"); err != nil {
		return fmt.Errorf("windows dns: delete %s: %w", zone, err)
	}
	return nil
}
