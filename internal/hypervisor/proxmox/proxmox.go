// Package proxmox is the NCC hypervisor provider for Proxmox VE. It reads nodes,
// virtual machines (QEMU) and containers (LXC) through the Proxmox VE API, and the
// guest IP addresses from the QEMU guest agent or the container's interfaces.
//
// It only reads. An API token with the PVEAuditor role on / is enough for the VM
// list; guest IP addresses also need VM.GuestAgent.Audit (Proxmox VE 9) or
// VM.Monitor (Proxmox VE 8).
package proxmox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dertown/network-control-centre/internal/catalog"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	hv "github.com/dertown/network-control-centre/internal/hypervisor"
	"github.com/dertown/network-control-centre/internal/netutil"
)

func init() {
	tok, pw := map[string]string{"auth": "token"}, map[string]string{"auth": "password"}
	hv.Register(Provider{}, catalog.Vendor{
		Label: "Proxmox VE", Groups: []string{catalog.GroupVirtualization}, Order: 10,
		Summary: "Proxmox VE nodes and clusters: VMs and LXC containers.",
		Help: "Use any node's address on port 8006; in a cluster one node lists every VM. To only read, a read-only API token is best. " +
			"On a node shell: pveum user add ncc@pve, pveum acl modify / --users ncc@pve --roles PVEAuditor, then " +
			"pveum user token add ncc@pve monitor --privsep 0 and paste the secret it prints (use PVEVMAdmin to start, stop and edit VMs). " +
			"Guest IP addresses need the QEMU guest agent in each VM. The node's self-signed certificate is pinned on first connection.",
		NameDefault: "proxmox", AddressDefault: "https://192.168.1.10:8006",
		Fields: []catalog.Field{
			{Key: "auth", Label: "Sign in with", Type: catalog.Select, Store: catalog.StoreForm, Default: "token",
				Choices: []catalog.Choice{{Value: "token", Label: "API token (recommended)"}, {Value: "password", Label: "Username + password"}}},
			catalog.TLSField("pin"),
			{Key: "token_id", Label: "Token id", Type: catalog.Token, Store: catalog.StoreSecret, Default: "ncc@pve!monitor", Placeholder: "ncc@pve!monitor", Required: true, ShowIf: tok},
			{Key: "token_secret", Label: "Token secret", Type: catalog.Token, Store: catalog.StoreSecret, Required: true, ShowIf: tok},
			{Key: "username", Label: "Username", Type: catalog.Text, Store: catalog.StoreSecret, Default: "root@pam", Placeholder: "root@pam", Required: true, ShowIf: pw},
			{Key: "password", Label: "Password", Type: catalog.Password, Store: catalog.StoreSecret, Required: true, ShowIf: pw},
		},
	})
}

// Provider implements hypervisor.Provider for Proxmox VE.
type Provider struct{}

// Kind implements hypervisor.Provider.
func (Provider) Kind() string { return "proxmox" }

// Option keys.
const (
	OptTLS         = "tls"             // "pin" (default) or "verify"
	OptFingerprint = "tls_fingerprint" // pinned SHA-256 of the node's certificate
	OptGuestIPs    = "guest_ips"       // "off" skips the per-VM guest agent calls
)

// ErrUnauthorized means the credentials were refused.
var ErrUnauthorized = errors.New("proxmox: credentials refused")

type client struct {
	base   string
	http   *http.Client
	pin    *netutil.Pinner
	token  string // "user@realm!tokenid=secret"
	ticket string
	csrf   string // CSRFPreventionToken, needed for writes with a ticket
}

// num reads a JSON number that Proxmox sometimes sends as a string.
type num float64

func (n *num) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		*n = 0
		return nil
	}
	*n = num(f)
	return nil
}

type httpError struct {
	path string
	code int
	msg  string
}

func (e *httpError) Error() string {
	if e.msg != "" {
		return fmt.Sprintf("proxmox: %s: HTTP %d: %s", e.path, e.code, e.msg)
	}
	return fmt.Sprintf("proxmox: %s: HTTP %d", e.path, e.code)
}

func newClient(t hv.Target, creds map[string]string) (*client, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(t.Address), "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("proxmox: address must be a URL like https://192.168.1.10:8006, got %q", t.Address)
	}
	if u.Port() == "" && u.Scheme == "https" {
		u.Host = net.JoinHostPort(u.Hostname(), "8006")
	}
	mode := t.Options[OptTLS]
	if mode == "" {
		mode = "pin"
	}
	hc, pin := netutil.NewClient(mode, t.Options[OptFingerprint], 20*time.Second)
	c := &client{base: u.String() + "/api2/json", http: hc, pin: pin}
	if id, sec := strings.TrimSpace(creds["token_id"]), strings.TrimSpace(creds["token_secret"]); id != "" && sec != "" {
		if !strings.Contains(id, "!") {
			return nil, errors.New("proxmox: the token id looks like user@realm!name, e.g. ncc@pve!monitor")
		}
		// accept the whole "user@realm!name=secret" pasted into the secret field
		if i := strings.LastIndex(sec, "="); i > 0 && strings.Contains(sec[:i], "!") {
			sec = sec[i+1:]
		}
		c.token = id + "=" + sec
	} else if creds["username"] == "" || creds["password"] == "" {
		return nil, errors.New("proxmox: give an API token (token_id and token_secret) or a username and password")
	}
	return c, nil
}

func (c *client) login(ctx context.Context, user, pass string) error {
	if !strings.Contains(user, "@") {
		user += "@pam"
	}
	form := url.Values{"username": {user}, "password": {pass}}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/access/ticket", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(r)
	if err != nil {
		return fmt.Errorf("proxmox: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return fmt.Errorf("%w: the username or password was refused (use user@pam or user@pve; accounts with two-factor sign-in need an API token instead)", ErrUnauthorized)
	}
	if resp.StatusCode != 200 {
		return &httpError{path: "/access/ticket", code: resp.StatusCode}
	}
	var out struct {
		Data struct {
			Ticket  string `json:"ticket"`
			CSRF    string `json:"CSRFPreventionToken"`
			NeedTFA num    `json:"NeedTFA"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return fmt.Errorf("proxmox: login: %w", err)
	}
	if out.Data.NeedTFA != 0 {
		return fmt.Errorf("%w: this account uses two-factor sign-in; create an API token for NCC instead", ErrUnauthorized)
	}
	if out.Data.Ticket == "" {
		return fmt.Errorf("%w: no ticket returned", ErrUnauthorized)
	}
	c.ticket = out.Data.Ticket
	c.csrf = out.Data.CSRF
	return nil
}

func (c *client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// do sends a request; form, when set, is sent as the body (POST/PUT) or query (DELETE).
func (c *client) do(ctx context.Context, method, path string, form url.Values, out any) error {
	var body io.Reader
	target := c.base + path
	if form != nil {
		if method == http.MethodDelete {
			target += "?" + form.Encode()
		} else {
			body = strings.NewReader(form.Encode())
		}
	}
	r, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return err
	}
	r.Header.Set("Accept", "application/json")
	if body != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c.token != "" {
		r.Header.Set("Authorization", "PVEAPIToken="+c.token)
	} else if c.ticket != "" {
		r.AddCookie(&http.Cookie{Name: "PVEAuthCookie", Value: c.ticket})
		if method != http.MethodGet {
			r.Header.Set("CSRFPreventionToken", c.csrf)
		}
	}
	resp, err := c.http.Do(r)
	if err != nil {
		return fmt.Errorf("proxmox: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode == 401 {
		if c.token != "" {
			return fmt.Errorf("%w (HTTP 401 on %s): Proxmox did not recognise the token. Check the token id is the full user@realm!name and the secret is the value printed when the token was made", ErrUnauthorized, path)
		}
		return fmt.Errorf("%w (HTTP 401 on %s)", ErrUnauthorized, path)
	}
	if resp.StatusCode != 200 {
		// Proxmox puts the reason in the status line, e.g. "500 QEMU guest agent is not running"
		msg := strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode)))
		// parameter errors come in the body: {"errors":{"memory":"value must be at least 16"}}
		var perr struct {
			Errors map[string]string `json:"errors"`
		}
		if json.Unmarshal(raw, &perr) == nil && len(perr.Errors) > 0 {
			keys := make([]string, 0, len(perr.Errors))
			for k := range perr.Errors {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				msg += "; " + k + ": " + strings.TrimSpace(perr.Errors[k])
			}
		}
		return &httpError{path: path, code: resp.StatusCode, msg: msg}
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("proxmox: %s: %w", path, err)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(env.Data, out)
}

type node struct {
	Node   string `json:"node"`
	Status string `json:"status"`
	CPU    num    `json:"cpu"`
	MaxCPU num    `json:"maxcpu"`
	Mem    num    `json:"mem"`
	MaxMem num    `json:"maxmem"`
	Uptime num    `json:"uptime"`
}

type resource struct {
	ID       string `json:"id"` // "qemu/101"
	Type     string `json:"type"`
	VMID     num    `json:"vmid"`
	Name     string `json:"name"`
	Node     string `json:"node"`
	Status   string `json:"status"`
	CPU      num    `json:"cpu"`
	MaxCPU   num    `json:"maxcpu"`
	Mem      num    `json:"mem"`
	MaxMem   num    `json:"maxmem"`
	Disk     num    `json:"disk"`
	MaxDisk  num    `json:"maxdisk"`
	Uptime   num    `json:"uptime"`
	Template num    `json:"template"`
	Tags     string `json:"tags"`
	HAState  string `json:"hastate"`
}

// Collect implements hypervisor.Provider.
func (Provider) Collect(ctx context.Context, t hv.Target, creds map[string]string) (*hv.Result, error) {
	c, err := newClient(t, creds)
	if err != nil {
		return nil, err
	}
	res := &hv.Result{}
	defer func() {
		if t.Options[OptTLS] != "verify" && t.Options[OptFingerprint] == "" && c.pin.Seen() != "" {
			res.OptionUpdates = map[string]string{OptFingerprint: c.pin.Seen()}
		}
	}()
	if c.token == "" {
		if err := c.login(ctx, creds["username"], creds["password"]); err != nil {
			return res, err
		}
	}
	inv := &hv.Inventory{Target: t.Name, Platform: "proxmox", TakenAt: time.Now().UTC()}
	res.Inventory = inv

	var ver struct {
		Version string `json:"version"`
		Release string `json:"release"`
	}
	if err := c.get(ctx, "/version", &ver); err != nil {
		return res, err
	}
	if ver.Version != "" {
		inv.Version = "Proxmox VE " + ver.Version
	}

	var nodes []node
	if err := c.get(ctx, "/nodes", &nodes); err != nil {
		return res, err
	}
	for _, n := range nodes {
		inv.Hosts = append(inv.Hosts, hv.Host{
			Name: n.Node, Online: n.Status == "online", CPUs: int(n.MaxCPU), CPUUsage: float64(n.CPU),
			MemBytes: int64(n.MaxMem), MemUsed: int64(n.Mem), UptimeS: int64(n.Uptime),
			Version: inv.Version, Target: t.Name, Platform: "proxmox",
		})
	}

	var rs []resource
	if err := c.get(ctx, "/cluster/resources?type=vm", &rs); err != nil {
		return res, err
	}
	for _, r := range rs {
		if r.Type != "qemu" && r.Type != "lxc" {
			continue
		}
		vm := hv.VM{
			ID: fmt.Sprintf("%s/%s/%d", t.Name, r.Type, int64(r.VMID)), Name: r.Name, Type: r.Type,
			State: state(r.Status), Host: r.Node, Template: r.Template != 0,
			CPUs: int(r.MaxCPU), CPUUsage: float64(r.CPU), MemBytes: int64(r.MaxMem), MemUsed: int64(r.Mem),
			DiskBytes: int64(r.MaxDisk), DiskUsed: int64(r.Disk), UptimeS: int64(r.Uptime),
			Target: t.Name, Platform: "proxmox",
		}
		if vm.Name == "" {
			vm.Name = fmt.Sprintf("%s %d", r.Type, int64(r.VMID))
		}
		for _, tag := range strings.FieldsFunc(r.Tags, func(r rune) bool { return r == ';' || r == ',' || r == ' ' }) {
			vm.Tags = append(vm.Tags, tag)
		}
		inv.VMs = append(inv.VMs, vm)
	}

	c.details(ctx, inv, rs, t.Options[OptGuestIPs] != "off")
	inv.Sort()
	return res, nil
}

func state(s string) string {
	switch s {
	case "running":
		return hv.StateRunning
	case "stopped":
		return hv.StateStopped
	case "paused", "suspended":
		return hv.StateSuspended
	}
	return hv.StateUnknown
}

// details fills OS, notes and guest IPs, a few VMs at a time. Failures only add a warning:
// a VM without the guest agent is normal.
func (c *client) details(ctx context.Context, inv *hv.Inventory, rs []resource, ips bool) {
	byID := map[string]resource{}
	for _, r := range rs {
		byID[r.Type+"/"+strconv.FormatInt(int64(r.VMID), 10)] = r
	}
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		denied   bool
		sem      = make(chan struct{}, 8)
		warnOnce = func() {
			mu.Lock()
			defer mu.Unlock()
			if !denied {
				denied = true
				inv.Warnings = append(inv.Warnings, "Guest details were refused (HTTP 403). Give the NCC token the PVEAuditor role on /, plus VM.GuestAgent.Audit (Proxmox VE 9) or VM.Monitor (Proxmox VE 8) to read guest IP addresses.")
			}
		}
	)
	for i := range inv.VMs {
		vm := &inv.VMs[i]
		r := byID[vm.Type+"/"+vm.ID[strings.LastIndex(vm.ID, "/")+1:]]
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			vctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			base := fmt.Sprintf("/nodes/%s/%s/%d", url.PathEscape(r.Node), r.Type, int64(r.VMID))
			var cfg struct {
				OSType      string `json:"ostype"`
				Agent       string `json:"agent"`
				Description string `json:"description"`
			}
			if err := c.get(vctx, base+"/config", &cfg); err != nil {
				if is403(err) {
					warnOnce()
				}
			}
			vm.OS = osName(r.Type, cfg.OSType)
			vm.Notes = strings.TrimSpace(cfg.Description)
			if len(vm.Notes) > 8192 {
				vm.Notes = vm.Notes[:8192]
			}
			agent := r.Type == "qemu" && agentEnabled(cfg.Agent)
			if r.Type == "qemu" {
				if agent {
					vm.GuestTools = "agent enabled"
				} else {
					vm.GuestTools = "no guest agent"
				}
			}
			if !ips || vm.State != hv.StateRunning {
				return
			}
			var got []string
			var err error
			switch {
			case r.Type == "lxc":
				got, err = c.lxcIPs(vctx, base)
			case agent:
				got, err = c.agentIPs(vctx, base)
				if err != nil && !is403(err) {
					vm.GuestTools = "agent not responding"
				} else if err == nil {
					vm.GuestTools = "agent running"
				}
			}
			if is403(err) {
				warnOnce()
			}
			vm.IPs = got
		}()
	}
	wg.Wait()
}

func is403(err error) bool {
	var he *httpError
	return errors.As(err, &he) && he.code == 403
}

func agentEnabled(s string) bool {
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "1" || part == "enabled=1" || part == "enabled=true" {
			return true
		}
	}
	return false
}

func (c *client) agentIPs(ctx context.Context, base string) ([]string, error) {
	var out struct {
		Result []struct {
			Name string `json:"name"`
			IPs  []struct {
				Addr string `json:"ip-address"`
			} `json:"ip-addresses"`
		} `json:"result"`
	}
	if err := c.get(ctx, base+"/agent/network-get-interfaces", &out); err != nil {
		return nil, err
	}
	var ips []string
	for _, ifc := range out.Result {
		if ifc.Name == "lo" || strings.HasPrefix(strings.ToLower(ifc.Name), "loopback") {
			continue
		}
		for _, a := range ifc.IPs {
			ips = appendIP(ips, a.Addr)
		}
	}
	return ips, nil
}

func (c *client) lxcIPs(ctx context.Context, base string) ([]string, error) {
	var out []struct {
		Name  string `json:"name"`
		Inet  string `json:"inet"`
		Inet6 string `json:"inet6"`
	}
	if err := c.get(ctx, base+"/interfaces", &out); err != nil {
		return nil, err
	}
	var ips []string
	for _, ifc := range out {
		if ifc.Name == "lo" {
			continue
		}
		for _, a := range []string{ifc.Inet, ifc.Inet6} {
			for _, one := range strings.Fields(strings.ReplaceAll(a, ",", " ")) {
				ips = appendIP(ips, one)
			}
		}
	}
	return ips, nil
}

// appendIP adds an address (optionally with /prefix), skipping loopback and link-local.
func appendIP(ips []string, s string) []string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return ips
	}
	for _, have := range ips {
		if have == ip.String() {
			return ips
		}
	}
	// IPv4 first
	if ip.To4() != nil {
		n := 0
		for n < len(ips) && net.ParseIP(ips[n]).To4() != nil {
			n++
		}
		return append(ips[:n], append([]string{ip.String()}, ips[n:]...)...)
	}
	return append(ips, ip.String())
}

var osNames = map[string]string{
	"l26": "Linux", "l24": "Linux 2.4", "win11": "Windows 11 / Server 2022+", "win10": "Windows 10 / Server 2016-2019",
	"win8": "Windows 8 / Server 2012", "win7": "Windows 7", "w2k8": "Windows Server 2008", "wvista": "Windows Vista",
	"w2k3": "Windows Server 2003", "wxp": "Windows XP", "w2k": "Windows 2000", "solaris": "Solaris", "other": "Other",
}

func osName(typ, ostype string) string {
	if typ == "lxc" {
		if ostype == "" {
			return "Linux container"
		}
		return strings.ToUpper(ostype[:1]) + ostype[1:] + " container"
	}
	if n, ok := osNames[ostype]; ok {
		return n
	}
	return ostype
}
