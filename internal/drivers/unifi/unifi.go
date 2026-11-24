// Package unifi is the NCC device driver for UniFi Network controllers:
// UniFi OS consoles (Dream Router / Dream Router 7, Dream Machine, Cloud Gateway,
// Cloud Key) and self-hosted Network applications.
//
// It is read-only: it collects devices (with make and model), ports, uplinks,
// LLDP neighbours and clients, and builds the topology from them.
package unifi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dertown/network-control-centre/internal/catalog"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dertown/network-control-centre/internal/drivers"
	inv "github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/netutil"
	"github.com/dertown/network-control-centre/internal/vault"
)

func init() {
	drivers.Register(Driver{}, catalog.Vendor{
		Label: "Ubiquiti UniFi", Groups: []string{catalog.GroupRouter, catalog.GroupFirewall, catalog.GroupSwitch},
		Summary: "UniFi OS consoles (Dream Router, Dream Machine, Cloud Gateway) with their switches and access points.",
		Help: "For a Dream Router 7, use its LAN address and a local admin account (UniFi OS → Admins → add a local-access-only " +
			"user with a Network role of View Only). View Only is enough to read; VLAN, Wi-Fi and DNS domain changes need Site Admin. " +
			"Its self-signed certificate is pinned on first connection.",
		NameDefault: "dream-router", AddressDefault: "https://192.168.1.1", Order: 10,
		Fields: append([]catalog.Field{
			{Key: OptSite, Label: "Site", Type: catalog.Text, Store: catalog.StoreOption, Default: "default"},
			{Key: "auth", Label: "Sign in with", Type: catalog.Select, Store: catalog.StoreForm, Default: "password",
				Choices: []catalog.Choice{{Value: "password", Label: "Local username + password"}, {Value: "apikey", Label: "API key"}}},
			catalog.TLSField("pin"),
			{Key: "api_key", Label: "API key", Type: catalog.Token, Store: catalog.StoreSecret, Required: true, ShowIf: map[string]string{"auth": "apikey"}},
		}, catalog.UserPassword("", map[string]string{"auth": "password"})...),
	})
}

// Driver implements drivers.Driver for UniFi.
type Driver struct{}

// Kind implements drivers.Driver.
func (Driver) Kind() string { return "unifi" }

// Option keys understood by this driver.
const (
	OptSite        = "site"            // UniFi site name, default "default"
	OptController  = "controller"      // "unifios" (default) or "classic" (self-hosted Network app)
	OptTLS         = "tls"             // "pin" (default) or "verify"
	OptFingerprint = "tls_fingerprint" // pinned SHA-256 of the console's certificate
)

// ErrUnauthorized means the credentials were refused.
var ErrUnauthorized = errors.New("unifi: credentials refused (HTTP 401/403)")

// authError is a 401 or 403 answer. It matches ErrUnauthorized with errors.Is, and says
// which step was refused so a wrong password can be told apart from a missing permission.
type authError struct {
	method, path string
	code         int
	login        bool
	apiKey       bool
}

func (e *authError) Error() string {
	switch {
	case e.login:
		return fmt.Sprintf("unifi: the console refused the username or password (HTTP %d). Use a local UniFi OS admin "+
			"(Admins & Users, \"Restrict to local access only\"): UI.com cloud accounts and accounts with two-factor sign-in cannot log in from NCC", e.code)
	case e.apiKey:
		return fmt.Sprintf("unifi: the console refused the API key for %s %s (HTTP %d)", e.method, e.path, e.code)
	default:
		return fmt.Sprintf("unifi: logged in, but the console refused %s %s (HTTP %d). Check the site name "+
			"(the API uses the internal name, usually \"default\") and that the account has a Network role such as View Only", e.method, e.path, e.code)
	}
}

func (e *authError) Is(target error) bool { return target == ErrUnauthorized }

type client struct {
	base string
	site string
	// siteChecked is set once the console's site list was read; siteFixed when the
	// configured site was replaced by the console's internal name for it.
	siteChecked bool
	siteFixed   bool
	classic     bool
	apiKey      string
	csrf        string
	http        *http.Client
	pin         *netutil.Pinner
	targetID    int64
}

func newClient(t drivers.Target) (*client, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(t.Address), "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("unifi: address must be a URL like https://192.168.1.1, got %q", t.Address)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("unifi: address must start with https://")
	}
	mode := t.Options[OptTLS]
	if mode == "" {
		mode = "pin"
	}
	hc, pin := netutil.NewClient(mode, t.Options[OptFingerprint], 20*time.Second)
	jar, _ := cookiejar.New(nil)
	hc.Jar = jar
	site := t.Options[OptSite]
	if site == "" {
		site = "default"
	}
	return &client{base: u.String(), site: site, classic: t.Options[OptController] == "classic", http: hc, pin: pin}, nil
}

func (c *client) req(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	r, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	r.Header.Set("Accept", "application/json")
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		r.Header.Set("X-API-KEY", c.apiKey)
	}
	if c.csrf != "" && method != http.MethodGet {
		r.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.http.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if t := resp.Header.Get("X-Updated-Csrf-Token"); t != "" {
		c.csrf = t
	} else if t := resp.Header.Get("X-Csrf-Token"); t != "" {
		c.csrf = t
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return &authError{method: method, path: path, code: resp.StatusCode, apiKey: c.apiKey != ""}
	}
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("unifi: %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *client) login(ctx context.Context, creds vault.Secret) error {
	if k := creds["api_key"]; k != "" {
		c.apiKey = k
		return nil
	}
	user, pass := creds["username"], creds["password"]
	if user == "" || pass == "" {
		return errors.New("unifi: credentials need username + password, or api_key")
	}
	path := "/api/auth/login"
	if c.classic {
		path = "/api/login"
	}
	err := c.req(ctx, http.MethodPost, path, map[string]any{"username": user, "password": pass, "remember": false}, nil)
	var ae *authError
	if errors.As(err, &ae) {
		ae.login = true
	}
	return err
}

func (c *client) logout(ctx context.Context) {
	if c.apiKey != "" {
		return
	}
	path := "/api/auth/logout"
	if c.classic {
		path = "/api/logout"
	}
	_ = c.req(ctx, http.MethodPost, path, nil, nil)
}

func (c *client) apiPath(p string) string {
	if c.classic {
		return "/api/s/" + url.PathEscape(c.site) + "/" + p
	}
	return "/proxy/network/api/s/" + url.PathEscape(c.site) + "/" + p
}

type envelope[T any] struct {
	Meta struct {
		RC  string `json:"rc"`
		Msg string `json:"msg"`
	} `json:"meta"`
	Data []T `json:"data"`
}

func getList[T any](ctx context.Context, c *client, p string) ([]T, error) {
	var env envelope[T]
	if err := c.req(ctx, http.MethodGet, c.apiPath(p), nil, &env); err != nil {
		return nil, err
	}
	if env.Meta.RC != "" && env.Meta.RC != "ok" {
		return nil, fmt.Errorf("unifi: %s: %s", p, env.Meta.Msg)
	}
	return env.Data, nil
}

// ---- raw controller JSON (only the fields we use; everything else is ignored) ----

// flexFloat accepts numbers and numeric strings (UniFi sends poe_power as "2.34").
type flexFloat float64

func (f *flexFloat) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil // tolerate junk rather than fail the whole poll
	}
	*f = flexFloat(v)
	return nil
}

type rawPort struct {
	PortIdx   int       `json:"port_idx"`
	Name      string    `json:"name"`
	Up        bool      `json:"up"`
	Speed     int       `json:"speed"`
	PoEEnable bool      `json:"poe_enable"`
	PoEPower  flexFloat `json:"poe_power"`
	IsUplink  bool      `json:"is_uplink"`
	StpState  string    `json:"stp_state"` // forwarding | blocking | discarding | disabled ...
	// AggregatedBy is the port index of the link aggregation (LAG) this port belongs to,
	// false or 0 when it is not aggregated.
	AggregatedBy flexInt `json:"aggregated_by"`
	OpMode       string  `json:"op_mode"` // switch | mirror | aggregate

	PortconfID      string   `json:"portconf_id"`
	NativeNetworkID string   `json:"native_networkconf_id"`
	Forward         string   `json:"forward"`
	TaggedVLANMgmt  string   `json:"tagged_vlan_mgmt"`
	ExcludedIDs     []string `json:"excluded_networkconf_ids"`
}

type rawUplink struct {
	UplinkMAC        string `json:"uplink_mac"`
	UplinkRemotePort int    `json:"uplink_remote_port"`
	PortIdx          int    `json:"port_idx"`
	Type             string `json:"type"` // wire | wireless
	Speed            int    `json:"speed"`
	// Nameservers are the DNS servers a gateway uses upstream (gateways only).
	Nameservers []string `json:"nameservers"`
}

// rawWAN is a gateway's WAN status (wan1, wan2).
type rawWAN struct {
	DNS []string `json:"dns"` // DNS servers in use on this WAN
}

type rawLLDP struct {
	ChassisID     string `json:"chassis_id"`
	PortID        string `json:"port_id"`
	PortDescr     string `json:"port_descr"`
	SysName       string `json:"system_name"`
	SysName2      string `json:"sys_name"`
	ChassisDescr  string `json:"chassis_descr"`
	SysDescr      string `json:"system_descr"`
	SysDescr2     string `json:"sys_descr"`
	LocalPortIdx  int    `json:"local_port_idx"`
	LocalPortName string `json:"local_port_name"`
	IsWired       *bool  `json:"is_wired"`
}

func (l rawLLDP) name() string  { return firstNonEmpty(l.SysName, l.SysName2) }
func (l rawLLDP) descr() string { return firstNonEmpty(l.SysDescr, l.SysDescr2, l.ChassisDescr) }

type rawDevice struct {
	MAC       string    `json:"mac"`
	Name      string    `json:"name"`
	Model     string    `json:"model"`
	ModelName string    `json:"model_name"`
	Type      string    `json:"type"`
	IP        string    `json:"ip"`
	Version   string    `json:"version"`
	Serial    string    `json:"serial"`
	State     int       `json:"state"` // 1 = connected
	Adopted   *bool     `json:"adopted"`
	Uptime    int64     `json:"uptime"`
	NumSta    int       `json:"num_sta"`
	PortTable []rawPort `json:"port_table"`
	Uplink    rawUplink `json:"uplink"`
	LLDPTable []rawLLDP `json:"lldp_table"`

	PortOverrides []rawPortOverride `json:"port_overrides"`
	WAN1          *rawWAN           `json:"wan1"`

	// Access points (and routers with built-in Wi-Fi): radio settings and live radio stats.
	RadioTable      []rawRadio      `json:"radio_table"`
	RadioTableStats []rawRadioStats `json:"radio_table_stats"`
	// WLANOverrides switch Wi-Fi networks off (or rename them) on this access point only.
	WLANOverrides []rawWLANOverride `json:"wlan_overrides"`
}

type rawClient struct {
	MAC       string `json:"mac"`
	Name      string `json:"name"`
	Hostname  string `json:"hostname"`
	IP        string `json:"ip"`
	OUI       string `json:"oui"`
	IsWired   bool   `json:"is_wired"`
	SwMAC     string `json:"sw_mac"`
	SwPort    int    `json:"sw_port"`
	APMAC     string `json:"ap_mac"`
	Network   string `json:"network"`
	NetworkID string `json:"network_id"`
	VLAN      int    `json:"vlan"`
	ESSID     string `json:"essid"`
	Uptime    int64  `json:"uptime"`
	Signal    int    `json:"signal"`  // dBm, wireless only
	Radio     string `json:"radio"`   // ng | na | 6e, wireless only
	Channel   int    `json:"channel"` // wireless only

	RxBytes      int64     `json:"rx_bytes"`
	TxBytes      int64     `json:"tx_bytes"`
	WiredRxBytes int64     `json:"wired-rx_bytes"`
	WiredTxBytes int64     `json:"wired-tx_bytes"`
	RxRate       flexFloat `json:"rx_bytes-r"`
	TxRate       flexFloat `json:"tx_bytes-r"`
	WiredRxRate  flexFloat `json:"wired-rx_bytes-r"`
	WiredTxRate  flexFloat `json:"wired-tx_bytes-r"`
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ---- driver entry points ----

func (d Driver) open(ctx context.Context, t drivers.Target, creds vault.Secret) (*client, error) {
	c, err := newClient(t)
	if err != nil {
		return nil, err
	}
	if err := c.login(ctx, creds); err != nil {
		return c, err
	}
	return c, nil
}

func (c *client) optionUpdates(t drivers.Target) map[string]string {
	up := map[string]string{}
	mode := t.Options[OptTLS]
	if (mode == "" || mode == "pin") && t.Options[OptFingerprint] == "" && c.pin.Seen() != "" {
		up[OptFingerprint] = c.pin.Seen()
	}
	if c.siteFixed && c.site != t.Options[OptSite] {
		up[OptSite] = c.site
	}
	if len(up) == 0 {
		return nil
	}
	return up
}

type rawSite struct {
	Name string `json:"name"` // internal id used in API paths, e.g. "default"
	Desc string `json:"desc"` // the name shown in UniFi, e.g. "Home"
}

// resolveSite turns what the admin typed into the site's internal name. UniFi shows a
// site's description ("Home", "Default") but its API wants the internal name ("default"),
// and an unknown site answers 401, which looks like a credentials problem. Errors are
// ignored: the configured name is then used as it is.
func (c *client) resolveSite(ctx context.Context) {
	if c.siteChecked {
		return
	}
	path := "/proxy/network/api/self/sites"
	if c.classic {
		path = "/api/self/sites"
	}
	var env envelope[rawSite]
	if err := c.req(ctx, http.MethodGet, path, nil, &env); err != nil || len(env.Data) == 0 {
		return
	}
	c.siteChecked = true
	if s := pickSite(c.site, env.Data); s != "" && s != c.site {
		c.site, c.siteFixed = s, true
	}
}

// pickSite matches a configured site against the console's sites: by internal name, then
// by the name shown in UniFi, then the only site there is. "" means no match.
func pickSite(want string, sites []rawSite) string {
	for _, s := range sites {
		if s.Name == want {
			return s.Name
		}
	}
	for _, s := range sites {
		if strings.EqualFold(strings.TrimSpace(s.Desc), strings.TrimSpace(want)) || strings.EqualFold(s.Name, want) {
			return s.Name
		}
	}
	if len(sites) == 1 {
		return sites[0].Name
	}
	return ""
}

// Test implements drivers.Driver: log in and count devices.
func (d Driver) Test(ctx context.Context, t drivers.Target, creds vault.Secret) (*drivers.Result, error) {
	c, err := d.open(ctx, t, creds)
	if err != nil {
		return nil, err
	}
	defer c.logout(ctx)
	return d.collectWith(ctx, c, t)
}

// Sessions are reused between polls: UniFi OS rate-limits logins, so logging in every
// 30 seconds would eventually lock the account out. A session is dropped and rebuilt when
// the console answers 401 or when the target's address, options or credentials change.
var (
	sessMu   sync.Mutex
	sessions = map[string]*client{}
)

func sessionKey(t drivers.Target, creds vault.Secret) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d|%s|%s|%s|%s|%s|%s|%s", t.ID, t.Address, t.Options[OptSite], t.Options[OptController],
		t.Options[OptTLS], t.Options[OptFingerprint], creds["username"]+"\x00"+creds["password"], creds["api_key"])
	return hex.EncodeToString(h.Sum(nil))
}

// Collect implements drivers.Driver.
func (d Driver) Collect(ctx context.Context, t drivers.Target, creds vault.Secret) (*drivers.Result, error) {
	key := sessionKey(t, creds)
	sessMu.Lock()
	c := sessions[key]
	sessMu.Unlock()
	fresh := false
	if c == nil {
		var err error
		if c, err = d.open(ctx, t, creds); err != nil {
			return nil, err
		}
		fresh = true
	}
	res, err := d.collectWith(ctx, c, t)
	if errors.Is(err, ErrUnauthorized) && !fresh && c.apiKey == "" {
		// session expired: log in again once
		if c, err = d.open(ctx, t, creds); err != nil {
			d.forget(key)
			return nil, err
		}
		res, err = d.collectWith(ctx, c, t)
	}
	if err != nil {
		d.forget(key)
		return nil, err
	}
	sessMu.Lock()
	// keep one session per target id
	for k, old := range sessions {
		if old.targetID == t.ID && k != key {
			delete(sessions, k)
		}
	}
	c.targetID = t.ID
	sessions[key] = c
	sessMu.Unlock()
	return res, nil
}

func (Driver) forget(key string) {
	sessMu.Lock()
	delete(sessions, key)
	sessMu.Unlock()
}

func (d Driver) collectWith(ctx context.Context, c *client, t drivers.Target) (*drivers.Result, error) {
	c.resolveSite(ctx)
	devs, err := getList[rawDevice](ctx, c, "stat/device")
	if errors.Is(err, ErrUnauthorized) && c.apiKey != "" && !c.classic {
		// Some firmware only accepts API keys on the official Integration API.
		snap, ierr := collectIntegration(ctx, c, t.Name)
		if ierr != nil {
			return nil, fmt.Errorf("%v; integration API: %w", err, ierr)
		}
		traffic := &inv.TrafficReport{Target: t.Name, TakenAt: time.Now().UTC(), Clients: []inv.ClientTraffic{},
			DPINote: "this console is connected with an API key through the Integration API, which has no traffic data. " +
				"Use a local UniFi admin username and password for this target to see traffic."}
		return &drivers.Result{Snapshot: snap, OptionUpdates: c.optionUpdates(t), Traffic: traffic}, nil
	}
	if err != nil {
		return nil, err
	}
	clients, err := getList[rawClient](ctx, c, "stat/sta")
	if err != nil {
		return nil, err
	}
	cfg := collectSiteConfig(ctx, c)
	now := time.Now().UTC()
	snap := Build(t.Name, devs, clients, cfg, now)
	snap.Loops = DetectLoops(t.Name, devs, collectEvents(ctx, c), snap, now)
	snap.Firewall = BuildFirewall(t.Name, collectFirewall(ctx, c), cfg, clients)
	traffic := collectTraffic(ctx, c, t.Name, clients)
	return &drivers.Result{Snapshot: snap, OptionUpdates: c.optionUpdates(t), Traffic: traffic}, nil
}
