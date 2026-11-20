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
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dertown/network-control-centre/internal/drivers"
	"github.com/dertown/network-control-centre/internal/netutil"
	"github.com/dertown/network-control-centre/internal/vault"
)

func init() { drivers.Register(Driver{}) }

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

type client struct {
	base     string
	site     string
	classic  bool
	apiKey   string
	csrf     string
	http     *http.Client
	pin      *netutil.Pinner
	targetID int64
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
		return ErrUnauthorized
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
	return c.req(ctx, http.MethodPost, path, map[string]any{"username": user, "password": pass, "remember": false}, nil)
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
}

type rawUplink struct {
	UplinkMAC        string `json:"uplink_mac"`
	UplinkRemotePort int    `json:"uplink_remote_port"`
	PortIdx          int    `json:"port_idx"`
	Type             string `json:"type"` // wire | wireless
	Speed            int    `json:"speed"`
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
}

type rawClient struct {
	MAC      string `json:"mac"`
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	OUI      string `json:"oui"`
	IsWired  bool   `json:"is_wired"`
	SwMAC    string `json:"sw_mac"`
	SwPort   int    `json:"sw_port"`
	APMAC    string `json:"ap_mac"`
	Network  string `json:"network"`
	VLAN     int    `json:"vlan"`
	ESSID    string `json:"essid"`
	Uptime   int64  `json:"uptime"`

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
	mode := t.Options[OptTLS]
	if (mode == "" || mode == "pin") && t.Options[OptFingerprint] == "" && c.pin.Seen() != "" {
		return map[string]string{OptFingerprint: c.pin.Seen()}
	}
	return nil
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
	devs, err := getList[rawDevice](ctx, c, "stat/device")
	if errors.Is(err, ErrUnauthorized) && c.apiKey != "" && !c.classic {
		// Some firmware only accepts API keys on the official Integration API.
		snap, ierr := collectIntegration(ctx, c, t.Name)
		if ierr != nil {
			return nil, fmt.Errorf("%v; integration API: %w", err, ierr)
		}
		return &drivers.Result{Snapshot: snap, OptionUpdates: c.optionUpdates(t)}, nil
	}
	if err != nil {
		return nil, err
	}
	clients, err := getList[rawClient](ctx, c, "stat/sta")
	if err != nil {
		return nil, err
	}
	snap := Build(t.Name, devs, clients, time.Now().UTC())
	traffic := collectTraffic(ctx, c, t.Name, clients)
	return &drivers.Result{Snapshot: snap, OptionUpdates: c.optionUpdates(t), Traffic: traffic}, nil
}
