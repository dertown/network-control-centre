// Package azuredns implements the NCC DNS provider for Azure DNS (public zones) and Azure
// Private DNS, signing in with a Microsoft Entra ID app registration (client credentials).
//
// Entra ID itself holds no DNS records: an organisation's cloud DNS lives in Azure DNS zones,
// and Entra ID is how a program is allowed to change them. Give the app registration the
// "DNS Zone Contributor" role (or "Private DNS Zone Contributor") on the resource group, or
// "Reader" to only read.
package azuredns

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dertown/network-control-centre/internal/catalog"
	"github.com/dertown/network-control-centre/internal/dns"
)

// Options and secrets.
const (
	OptTenant        = "tenant_id"
	OptClient        = "client_id"
	OptSubscription  = "subscription_id"
	OptResourceGroup = "resource_group"
	OptZoneType      = "zone_type" // public (default) or private
	OptAuthority     = "authority" // sign-in endpoint, default https://login.microsoftonline.com
	SecretClient     = "client_secret"

	publicAPI  = "2018-05-01"
	privateAPI = "2020-06-01"
)

func init() {
	dns.Register(Provider{}, catalog.Vendor{
		Label: "Microsoft Entra ID (Azure DNS)", Groups: []string{catalog.GroupDNS}, Order: 40,
		Summary: "Azure DNS and Azure Private DNS zones, signed in with an Entra ID app registration.",
		Help: "In the Entra admin centre register an app (App registrations → New registration), add a client secret, and note the " +
			"tenant and client ids. In the Azure portal give the app the DNS Zone Contributor role (Private DNS Zone Contributor for " +
			"private zones; Reader to only read) on the resource group that holds your zones. The secret is kept in the vault. " +
			"For Azure Government or Azure China change the two endpoints.",
		NameDefault: "azure-dns", AddressDefault: "https://management.azure.com", AddressLabel: "Azure Resource Manager endpoint",
		Fields: []catalog.Field{
			{Key: OptTenant, Label: "Tenant (directory) id", Type: catalog.Text, Store: catalog.StoreOption, Required: true, Placeholder: "00000000-0000-0000-0000-000000000000"},
			{Key: OptClient, Label: "Client (application) id", Type: catalog.Text, Store: catalog.StoreOption, Required: true},
			{Key: SecretClient, Label: "Client secret", Type: catalog.Token, Store: catalog.StoreSecret, Required: true},
			{Key: OptSubscription, Label: "Subscription id", Type: catalog.Text, Store: catalog.StoreOption, Required: true},
			{Key: OptResourceGroup, Label: "Resource group", Type: catalog.Text, Store: catalog.StoreOption, Required: true},
			{Key: OptZoneType, Label: "Zones", Type: catalog.Select, Store: catalog.StoreOption, Default: "public", Choices: []catalog.Choice{
				{Value: "public", Label: "Azure DNS (public zones)"}, {Value: "private", Label: "Azure Private DNS"}}},
			{Key: OptAuthority, Label: "Sign-in endpoint", Type: catalog.Text, Store: catalog.StoreOption, Default: "https://login.microsoftonline.com"},
		},
	})
}

// Provider implements dns.Provider for Azure DNS.
type Provider struct{}

// Kind implements dns.Provider.
func (Provider) Kind() string { return "azuredns" }

var httpClient = &http.Client{Timeout: 30 * time.Second}

type client struct {
	arm, authority           string
	tenant, clientID, secret string
	base                     string // .../resourceGroups/{rg}/providers/Microsoft.Network/{dnsZones|privateDnsZones}
	private                  bool
	api                      string
}

func newClient(s dns.Server, creds map[string]string) (*client, error) {
	o := s.Options
	c := &client{
		arm:       strings.TrimRight(strings.TrimSpace(s.Address), "/"),
		authority: strings.TrimRight(strings.TrimSpace(o[OptAuthority]), "/"),
		tenant:    strings.TrimSpace(o[OptTenant]), clientID: strings.TrimSpace(o[OptClient]),
		secret: creds[SecretClient], private: o[OptZoneType] == "private",
	}
	if c.arm == "" {
		c.arm = "https://management.azure.com"
	}
	if c.authority == "" {
		c.authority = "https://login.microsoftonline.com"
	}
	sub, rg := strings.TrimSpace(o[OptSubscription]), strings.TrimSpace(o[OptResourceGroup])
	switch {
	case c.tenant == "" || c.clientID == "":
		return nil, errors.New("azure dns: the tenant id and client id are required")
	case c.secret == "":
		return nil, errors.New("azure dns: no client secret saved in the vault")
	case sub == "" || rg == "":
		return nil, errors.New("azure dns: the subscription id and resource group are required")
	}
	kind, api := "dnsZones", publicAPI
	if c.private {
		kind, api = "privateDnsZones", privateAPI
	}
	c.api = api
	c.base = c.arm + "/subscriptions/" + url.PathEscape(sub) + "/resourceGroups/" + url.PathEscape(rg) + "/providers/Microsoft.Network/" + kind
	return c, nil
}

// ---- Entra ID sign-in: client credentials, tokens cached until shortly before they expire ----

type cachedToken struct {
	token string
	until time.Time
}

var (
	tokMu  sync.Mutex
	tokens = map[string]cachedToken{}
)

func (c *client) token(ctx context.Context) (string, error) {
	h := sha256.Sum256([]byte(c.authority + "|" + c.tenant + "|" + c.clientID + "|" + c.secret + "|" + c.arm))
	key := hex.EncodeToString(h[:])
	tokMu.Lock()
	if t, ok := tokens[key]; ok && time.Now().Before(t.until) {
		tokMu.Unlock()
		return t.token, nil
	}
	tokMu.Unlock()
	form := url.Values{
		"grant_type": {"client_credentials"}, "client_id": {c.clientID}, "client_secret": {c.secret},
		"scope": {c.arm + "/.default"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.authority+"/"+url.PathEscape(c.tenant)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("azure dns: sign in to Entra ID: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		msg := out.Description
		if i := strings.Index(msg, "\r\n"); i > 0 {
			msg = msg[:i]
		}
		if msg == "" {
			msg = resp.Status
		}
		return "", fmt.Errorf("azure dns: Entra ID refused the sign-in (%s): %s", out.Error, msg)
	}
	life := time.Duration(out.ExpiresIn) * time.Second
	if life <= 0 {
		life = time.Hour
	}
	tokMu.Lock()
	if len(tokens) > 64 {
		tokens = map[string]cachedToken{}
	}
	tokens[key] = cachedToken{out.AccessToken, time.Now().Add(life - 2*time.Minute)}
	tokMu.Unlock()
	return out.AccessToken, nil
}

func (c *client) do(ctx context.Context, method, u string, body, out any) error {
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("azure dns: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = json.Unmarshal(raw, &e)
		msg := e.Error.Message
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
		}
		return fmt.Errorf("azure dns: %s %s: HTTP %d %s: %s", method, strings.TrimPrefix(u, c.arm), resp.StatusCode, e.Error.Code, msg)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *client) url(path string) string {
	return c.base + path + "?api-version=" + c.api
}

// list follows nextLink pages.
func list[T any](ctx context.Context, c *client, u string) ([]T, error) {
	var all []T
	for u != "" {
		var page struct {
			Value    []T    `json:"value"`
			NextLink string `json:"nextLink"`
		}
		if err := c.do(ctx, http.MethodGet, u, nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Value...)
		u = page.NextLink
		if u != "" && !strings.HasPrefix(u, c.arm) { // never follow a link off the endpoint we trust with the token
			return nil, fmt.Errorf("azure dns: unexpected next page link %q", u)
		}
	}
	return all, nil
}

// ListZones implements dns.Provider.
func (Provider) ListZones(ctx context.Context, s dns.Server, creds map[string]string) ([]dns.Zone, error) {
	c, err := newClient(s, creds)
	if err != nil {
		return nil, err
	}
	zs, err := list[struct {
		Name string `json:"name"`
	}](ctx, c, c.url(""))
	if err != nil {
		return nil, err
	}
	kind := "Public"
	if c.private {
		kind = "Private"
	}
	out := make([]dns.Zone, 0, len(zs))
	for _, z := range zs {
		out = append(out, dns.Zone{Name: dns.FQDN(z.Name), Kind: kind})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// recordSet is an Azure record set. JSON field matching is case-insensitive, so the same
// struct reads public zones (ARecords, TTL) and private ones (aRecords, ttl).
type recordSet struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Properties props  `json:"properties"`
}

type props struct {
	TTL      int `json:"TTL"`
	ARecords []struct {
		IPv4Address string `json:"ipv4Address"`
	} `json:"ARecords"`
	AAAARecords []struct {
		IPv6Address string `json:"ipv6Address"`
	} `json:"AAAARecords"`
	CNAMERecord *struct {
		CNAME string `json:"cname"`
	} `json:"CNAMERecord"`
	MXRecords []struct {
		Preference int    `json:"preference"`
		Exchange   string `json:"exchange"`
	} `json:"MXRecords"`
	NSRecords []struct {
		NSDName string `json:"nsdname"`
	} `json:"NSRecords"`
	PTRRecords []struct {
		PTRDName string `json:"ptrdname"`
	} `json:"PTRRecords"`
	SRVRecords []struct {
		Priority int    `json:"priority"`
		Weight   int    `json:"weight"`
		Port     int    `json:"port"`
		Target   string `json:"target"`
	} `json:"SRVRecords"`
	TXTRecords []struct {
		Value []string `json:"value"`
	} `json:"TXTRecords"`
	CAARecords []struct {
		Flags int    `json:"flags"`
		Tag   string `json:"tag"`
		Value string `json:"value"`
	} `json:"caaRecords"`
	SOARecord *struct {
		Host         string `json:"host"`
		Email        string `json:"email"`
		SerialNumber int64  `json:"serialNumber"`
		RefreshTime  int64  `json:"refreshTime"`
		RetryTime    int64  `json:"retryTime"`
		ExpireTime   int64  `json:"expireTime"`
		MinimumTTL   int64  `json:"minimumTTL"`
	} `json:"SOARecord"`
}

func fq(n string) string { return dns.FQDN(n) }

// values turns an Azure record set into presentation-format values.
func (p props) values(typ string) []string {
	var out []string
	switch typ {
	case "A":
		for _, r := range p.ARecords {
			out = append(out, r.IPv4Address)
		}
	case "AAAA":
		for _, r := range p.AAAARecords {
			out = append(out, r.IPv6Address)
		}
	case "CNAME":
		if p.CNAMERecord != nil {
			out = append(out, fq(p.CNAMERecord.CNAME))
		}
	case "MX":
		for _, r := range p.MXRecords {
			out = append(out, fmt.Sprintf("%d %s", r.Preference, fq(r.Exchange)))
		}
	case "NS":
		for _, r := range p.NSRecords {
			out = append(out, fq(r.NSDName))
		}
	case "PTR":
		for _, r := range p.PTRRecords {
			out = append(out, fq(r.PTRDName))
		}
	case "SRV":
		for _, r := range p.SRVRecords {
			out = append(out, fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, fq(r.Target)))
		}
	case "TXT":
		for _, r := range p.TXTRecords {
			q := make([]string, len(r.Value))
			for i, v := range r.Value {
				q[i] = strconv.Quote(v)
			}
			out = append(out, strings.Join(q, " "))
		}
	case "CAA":
		for _, r := range p.CAARecords {
			out = append(out, fmt.Sprintf("%d %s %s", r.Flags, r.Tag, strconv.Quote(r.Value)))
		}
	case "SOA":
		if s := p.SOARecord; s != nil {
			out = append(out, fmt.Sprintf("%s %s %d %d %d %d %d", fq(s.Host), fq(s.Email), s.SerialNumber, s.RefreshTime, s.RetryTime, s.ExpireTime, s.MinimumTTL))
		}
	}
	return out
}

func recordType(azureType string) string {
	return strings.ToUpper(azureType[strings.LastIndex(azureType, "/")+1:])
}

// ListRecords implements dns.Provider.
func (Provider) ListRecords(ctx context.Context, s dns.Server, creds map[string]string, zone string) ([]dns.RRSet, error) {
	c, err := newClient(s, creds)
	if err != nil {
		return nil, err
	}
	zone = dns.FQDN(zone)
	seg := "/recordsets"
	if c.private {
		seg = "/ALL"
	}
	rs, err := list[recordSet](ctx, c, c.url("/"+url.PathEscape(strings.TrimSuffix(zone, "."))+seg))
	if err != nil {
		return nil, err
	}
	out := make([]dns.RRSet, 0, len(rs))
	for _, r := range rs {
		typ := recordType(r.Type)
		name := zone
		if r.Name != "@" && r.Name != "" {
			name = dns.FQDN(r.Name + "." + zone)
		}
		out = append(out, dns.RRSet{Name: name, Type: typ, TTL: r.Properties.TTL, Records: r.Properties.values(typ)})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Type < out[j].Type
	})
	return out, nil
}

// Check implements dns.Checker: sign in and list the zones.
func (p Provider) Check(ctx context.Context, s dns.Server, creds map[string]string) error {
	_, err := p.ListZones(ctx, s, creds)
	return err
}

// relName is name relative to zone, "@" at the apex.
func relName(name, zone string) string {
	name, zone = dns.FQDN(name), dns.FQDN(zone)
	if name == zone {
		return "@"
	}
	return strings.TrimSuffix(name, "."+zone)
}

// splitTXT reads a presentation-format TXT value ("a" "b", or unquoted text) into its strings.
func splitTXT(v string) []string {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, `"`) {
		return []string{v}
	}
	var out []string
	for len(v) > 0 {
		v = strings.TrimSpace(v)
		if !strings.HasPrefix(v, `"`) {
			break
		}
		s, err := strconv.QuotedPrefix(v)
		if err != nil {
			return []string{strings.Trim(v, `"`)}
		}
		u, _ := strconv.Unquote(s)
		out = append(out, u)
		v = v[len(s):]
	}
	return out
}

func host(s string) string { return strings.TrimSuffix(strings.TrimSpace(s), ".") }

// body builds the PUT body for an RRset. Private zones use lower camel case property names.
func body(r dns.RRSet, private bool) (map[string]any, error) {
	k := func(public, priv string) string {
		if private {
			return priv
		}
		return public
	}
	pr := map[string]any{k("TTL", "ttl"): r.TTL}
	var list []any
	for _, v := range r.Records {
		f := strings.Fields(v)
		bad := func() error { return fmt.Errorf("azure dns: %s record %q is not valid", r.Type, v) }
		switch strings.ToUpper(r.Type) {
		case "A":
			list = append(list, map[string]any{"ipv4Address": v})
		case "AAAA":
			list = append(list, map[string]any{"ipv6Address": v})
		case "CNAME":
			pr[k("CNAMERecord", "cnameRecord")] = map[string]any{"cname": host(v)}
		case "NS":
			list = append(list, map[string]any{"nsdname": host(v)})
		case "PTR":
			list = append(list, map[string]any{"ptrdname": host(v)})
		case "MX":
			if len(f) != 2 {
				return nil, bad()
			}
			pref, err := strconv.Atoi(f[0])
			if err != nil {
				return nil, bad()
			}
			list = append(list, map[string]any{"preference": pref, "exchange": host(f[1])})
		case "SRV":
			if len(f) != 4 {
				return nil, bad()
			}
			n := make([]int, 3)
			for i := range n {
				x, err := strconv.Atoi(f[i])
				if err != nil {
					return nil, bad()
				}
				n[i] = x
			}
			list = append(list, map[string]any{"priority": n[0], "weight": n[1], "port": n[2], "target": host(f[3])})
		case "TXT":
			list = append(list, map[string]any{"value": splitTXT(v)})
		case "CAA":
			if len(f) < 3 {
				return nil, bad()
			}
			flags, err := strconv.Atoi(f[0])
			if err != nil {
				return nil, bad()
			}
			val := strings.TrimSpace(strings.SplitN(v, f[1], 2)[1])
			list = append(list, map[string]any{"flags": flags, "tag": f[1], "value": strings.Trim(val, `"`)})
		case "SOA":
			if len(f) != 7 {
				return nil, bad()
			}
			nums := make([]int64, 5)
			for i := range nums {
				x, err := strconv.ParseInt(f[2+i], 10, 64)
				if err != nil {
					return nil, bad()
				}
				nums[i] = x
			}
			pr[k("SOARecord", "soaRecord")] = map[string]any{"host": host(f[0]), "email": host(f[1]), "serialNumber": nums[0],
				"refreshTime": nums[1], "retryTime": nums[2], "expireTime": nums[3], "minimumTTL": nums[4]}
		default:
			return nil, fmt.Errorf("azure dns: %s records are not supported", r.Type)
		}
	}
	if list != nil {
		names := map[string][2]string{"A": {"ARecords", "aRecords"}, "AAAA": {"AAAARecords", "aaaaRecords"}, "NS": {"NSRecords", "nsRecords"},
			"PTR": {"PTRRecords", "ptrRecords"}, "MX": {"MXRecords", "mxRecords"}, "SRV": {"SRVRecords", "srvRecords"},
			"TXT": {"TXTRecords", "txtRecords"}, "CAA": {"caaRecords", "caaRecords"}}
		n := names[strings.ToUpper(r.Type)]
		pr[k(n[0], n[1])] = list
	}
	return map[string]any{"properties": pr}, nil
}

// Apply implements dns.Provider. Azure has no batch: changes are applied one RRset at a time,
// and the first failure stops the rest.
func (Provider) Apply(ctx context.Context, s dns.Server, creds map[string]string, zone string, changes []dns.Change) error {
	c, err := newClient(s, creds)
	if err != nil {
		return err
	}
	z := url.PathEscape(strings.TrimSuffix(dns.FQDN(zone), "."))
	for _, ch := range changes {
		typ := strings.ToUpper(ch.RRSet.Type)
		u := c.url("/" + z + "/" + typ + "/" + url.PathEscape(relName(ch.RRSet.Name, zone)))
		if ch.Op == dns.Delete {
			if err := c.do(ctx, http.MethodDelete, u, nil, nil); err != nil {
				return err
			}
			continue
		}
		b, err := body(ch.RRSet, c.private)
		if err != nil {
			return err
		}
		if err := c.do(ctx, http.MethodPut, u, b, nil); err != nil {
			return err
		}
	}
	return nil
}
