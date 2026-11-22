package api

// The "Fix" button on the router DNS check's "can't read the forwarders" and "refuses
// internet names" results: find the PowerDNS Recursor's API, or change the DNS server over
// SSH (turn the API on, or install the Recursor and make it the resolver on port 53),
// always through a preview of the exact changes. Admins only; every change is audited.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dertown/network-control-centre/internal/certdeploy"
	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/dns"
	"github.com/dertown/network-control-centre/internal/dnscheck"
	"github.com/dertown/network-control-centre/internal/recursorfix"
)

// Options and vault fields of a DNS connection used by the fix. The SSH login is kept so the
// next fix doesn't ask again; the password and key live in the connection's vault entry.
const (
	optSSHHost    = "ssh_host"
	optSSHPort    = "ssh_port"
	optSSHUser    = "ssh_user"
	optSSHSudo    = "ssh_sudo"
	optSSHHostKey = "ssh_host_key"
	secSSHPass    = "ssh_password"
	secSSHKey     = "ssh_private_key"
	secSSHPhrase  = "ssh_passphrase"
)

// fixDialSSH opens the SSH connection; tests replace it.
var fixDialSSH = func(ctx context.Context, o certdeploy.SSHOptions) (recursorfix.Conn, string, error) {
	c, seen, err := certdeploy.DialSSH(ctx, o)
	if err != nil {
		return nil, seen, err
	}
	return c, seen, nil
}

type pendingFix struct {
	target  int64
	plan    *recursorfix.Plan
	ssh     certdeploy.SSHOptions
	created time.Time
}

type fixState struct {
	mu    sync.Mutex
	plans map[string]*pendingFix
}

func (f *fixState) put(p *pendingFix) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.plans == nil {
		f.plans = map[string]*pendingFix{}
	}
	for id, x := range f.plans {
		if time.Since(x.created) > 20*time.Minute {
			delete(f.plans, id)
		}
	}
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	f.plans[id] = p
	return id
}

func (f *fixState) take(id string) *pendingFix {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.plans[id]
	delete(f.plans, id)
	if p != nil && time.Since(p.created) > 20*time.Minute {
		return nil
	}
	return p
}

var recursorFixes fixState

// fixTarget loads a DNS connection and its vault entry.
func (s *Server) fixTarget(r *http.Request) (*core.Target, map[string]string, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, nil, core.ErrNoTarget
	}
	t, err := s.Targets.Get(r.Context(), id)
	if err != nil {
		return nil, nil, err
	}
	if t.Category != core.CategoryDNS {
		return nil, nil, core.ErrNoTarget
	}
	creds, err := s.Vault.Get(r.Context(), t.SecretPath)
	if err != nil {
		return nil, nil, err
	}
	return t, creds, nil
}

// fixHosts are the addresses to look for the Recursor on: the Recursor URL's host, the
// addresses clients use and the connection's own host.
func fixHosts(t *core.Target) []string {
	seen := map[string]bool{}
	var out []string
	add := func(hs ...string) {
		for _, h := range hs {
			if h != "" && !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	look := func(h string) ([]string, error) { return net.DefaultResolver.LookupHost(context.Background(), h) }
	add(dnscheck.HostAddresses(t.Options[core.OptRecursorURL], look)...)
	for _, a := range dnscheck.SplitList(t.Options[core.OptResolverIPs]) {
		add(dnscheck.HostAddresses(a, look)...)
	}
	add(dnscheck.HostAddresses(t.Address, look)...)
	return out
}

func fixKeys(creds map[string]string) []string {
	return []string{creds["recursor_api_key"], creds["api_key"]}
}

type sshView struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	User        string `json:"user"`
	Sudo        bool   `json:"sudo"`
	HostKey     string `json:"host_key,omitempty"`
	HasPassword bool   `json:"has_password"`
	HasKey      bool   `json:"has_key"`
}

func savedSSH(t *core.Target, creds map[string]string, hosts []string) sshView {
	v := sshView{Host: t.Options[optSSHHost], User: t.Options[optSSHUser], Sudo: t.Options[optSSHSudo] == "yes",
		HostKey: t.Options[optSSHHostKey], HasPassword: creds[secSSHPass] != "", HasKey: creds[secSSHKey] != ""}
	v.Port, _ = strconv.Atoi(t.Options[optSSHPort])
	if v.Port == 0 {
		v.Port = 22
	}
	if v.Host == "" && len(hosts) > 0 {
		v.Host = hosts[0]
	}
	if v.User == "" {
		v.User, v.Sudo = "root", false
	}
	return v
}

// liveRefused reports whether the last live lookups found the server refusing internet names
// (an authoritative-only server), which is when installing a Recursor is the fix.
func liveRefused(ctx context.Context, s *Server, id int64) bool {
	rep, err := core.DNSChain(ctx, s.Store.DB, s.Targets)
	if err != nil {
		return false
	}
	for _, c := range rep.Checks {
		if c.Kind == dnscheck.KindLive && c.Target == id && strings.Contains(c.Title, "refuses internet names") {
			return true
		}
	}
	return false
}

func (s *Server) fixDiscover(w http.ResponseWriter, r *http.Request) {
	t, creds, err := s.fixTarget(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	hosts := fixHosts(t)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	d := recursorfix.Discover(ctx, hosts, fixKeys(creds), nil)
	writeJSON(w, 200, map[string]any{
		"discovery":     d,
		"current_url":   t.Options[core.OptRecursorURL],
		"ssh":           savedSSH(t, creds, hosts),
		"no_resolver":   liveRefused(r.Context(), s, t.ID),
		"needs_api_key": d.Found != nil && !d.Found.KeyOK,
	})
}

// fixUse saves a found Recursor URL (and key) after checking it answers.
func (s *Server) fixUse(w http.ResponseWriter, r *http.Request) {
	t, creds, err := s.fixTarget(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	var in struct {
		URL    string `json:"url"`
		APIKey string `json:"api_key"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	in.URL = strings.TrimRight(strings.TrimSpace(in.URL), "/")
	if !strings.HasPrefix(in.URL, "http://") && !strings.HasPrefix(in.URL, "https://") {
		writeErr(w, 400, "the URL must start with http:// or https://")
		return
	}
	keys := append([]string{in.APIKey}, fixKeys(creds)...)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	key, err := "", errors.New("no API key: enter the Recursor's api-key")
	for _, k := range keys {
		if k == "" {
			continue
		}
		if err = recursorfix.CheckAPI(ctx, in.URL, k, nil); err == nil {
			key = k
			break
		}
	}
	if err != nil {
		writeErr(w, 400, "The Recursor at "+in.URL+" didn't accept NCC: "+err.Error())
		return
	}
	if err := s.saveRecursor(r.Context(), t, creds, in.URL, key, nil); err != nil {
		s.fail(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "dns.recursor.use", "target/"+t.Name, map[string]string{"url": in.URL})
	writeJSON(w, 200, map[string]any{"ok": true, "url": in.URL})
}

// saveRecursor stores the Recursor URL and key on the connection (and the clean addresses
// clients use), then re-reads it so the check shows the result straight away.
func (s *Server) saveRecursor(ctx context.Context, t *core.Target, creds map[string]string, url, key string, extra map[string]string) error {
	opts := map[string]string{core.OptRecursorURL: url}
	// "Address clients use" must be addresses: drop a URL's scheme and port
	var clean []string
	for _, a := range dnscheck.SplitList(t.Options[core.OptResolverIPs]) {
		clean = append(clean, dnscheck.HostAddresses(a, nil)...)
	}
	if len(clean) == 0 {
		clean = dnscheck.HostAddresses(url, nil)
	}
	opts[core.OptResolverIPs] = strings.Join(clean, ", ")
	for k, v := range extra {
		opts[k] = v
	}
	if err := s.Targets.MergeOptions(ctx, t.ID, opts); err != nil {
		return err
	}
	if key != creds["recursor_api_key"] {
		sec := map[string]string{}
		for k, v := range creds {
			sec[k] = v
		}
		sec["recursor_api_key"] = key
		if _, err := s.Vault.Put(ctx, t.SecretPath, sec); err != nil {
			return err
		}
	}
	if s.Poller != nil {
		_, _ = s.Poller.PollOne(ctx, t.ID)
	}
	return nil
}

type fixSSHIn struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	User          string `json:"user"`
	Password      string `json:"password"`
	PrivateKey    string `json:"private_key"`
	Passphrase    string `json:"passphrase"`
	Sudo          bool   `json:"sudo"`
	AcceptHostKey string `json:"accept_host_key"`
	Remember      bool   `json:"remember"`
	// MakeResolver allows installing the Recursor and putting it on port 53.
	MakeResolver bool `json:"make_resolver"`
}

func (s *Server) fixPlan(w http.ResponseWriter, r *http.Request) {
	t, creds, err := s.fixTarget(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	var in fixSSHIn
	if !readJSON(w, r, &in) {
		return
	}
	saved := savedSSH(t, creds, fixHosts(t))
	o := certdeploy.SSHOptions{Host: strings.TrimSpace(in.Host), Port: in.Port, User: strings.TrimSpace(in.User),
		Password: in.Password, PrivateKey: in.PrivateKey, Passphrase: in.Passphrase, Sudo: in.Sudo,
		HostKey: t.Options[optSSHHostKey], AcceptHostKey: in.AcceptHostKey, Timeout: 15 * time.Second}
	if o.Host == "" {
		o.Host = saved.Host
	}
	if o.Port == 0 {
		o.Port = saved.Port
	}
	if o.User == "" {
		o.User = saved.User
	}
	if o.Password == "" && o.PrivateKey == "" {
		o.Password, o.PrivateKey, o.Passphrase = creds[secSSHPass], creds[secSSHKey], creds[secSSHPhrase]
	}
	if o.Host != t.Options[optSSHHost] {
		o.HostKey = "" // another machine: confirm its key again
	}
	if o.Host == "" || o.User == "" {
		writeErr(w, 400, "enter the DNS server's address and an SSH user")
		return
	}
	if o.Password == "" && strings.TrimSpace(o.PrivateKey) == "" {
		writeErr(w, 400, "enter the SSH password or a private key")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	conn, seen, err := fixDialSSH(ctx, o)
	if err != nil {
		var hk *certdeploy.ErrHostKeyUnknown
		if errors.As(err, &hk) {
			// not an error: the person checks the key and confirms it
			writeJSON(w, 200, map[string]string{"host": o.Host, "host_key_unknown": hk.Seen})
			return
		}
		writeErr(w, 502, "SSH to "+o.Host+": "+err.Error())
		return
	}
	if cl, ok := conn.(interface{ Close() error }); ok {
		defer cl.Close()
	}
	opts := recursorfix.Options{Host: o.Host, NCCAddress: sourceAddress(o.Host), MakeResolver: in.MakeResolver}
	if in.MakeResolver {
		if p, err := dns.Get(t.Kind); err == nil {
			zctx, zc := context.WithTimeout(ctx, 10*time.Second)
			if zs, err := p.ListZones(zctx, dns.Server{ID: t.ID, Name: t.Name, Kind: t.Kind, Address: t.Address, Options: t.Options}, creds); err == nil {
				for _, z := range zs {
					opts.AuthZones = append(opts.AuthZones, z.Name)
				}
			}
			zc()
		}
		if rep, err := core.DNSChain(ctx, s.Store.DB, s.Targets); err == nil {
			opts.ISP = rep.ISP
		}
	}
	plan, err := recursorfix.Inspect(ctx, conn, opts)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	// remember the login (and pin the host key) for the next fix
	if in.Remember {
		pin := seen
		if pin == "" {
			pin = o.HostKey
		}
		_ = s.Targets.MergeOptions(r.Context(), t.ID, map[string]string{optSSHHost: o.Host, optSSHPort: strconv.Itoa(o.Port),
			optSSHUser: o.User, optSSHSudo: map[bool]string{true: "yes", false: ""}[o.Sudo], optSSHHostKey: pin})
		if in.Password != "" || in.PrivateKey != "" {
			sec := map[string]string{}
			for k, v := range creds {
				sec[k] = v
			}
			sec[secSSHPass], sec[secSSHKey], sec[secSSHPhrase] = in.Password, in.PrivateKey, in.Passphrase
			_, _ = s.Vault.Put(r.Context(), t.SecretPath, sec)
		}
	}
	if o.HostKey == "" {
		o.HostKey = seen
	}
	o.AcceptHostKey = ""
	id := recursorFixes.put(&pendingFix{target: t.ID, plan: plan, ssh: o, created: time.Now()})
	writeJSON(w, 200, map[string]any{"plan_id": id, "plan": plan, "host_key": seen})
}

func (s *Server) fixApply(w http.ResponseWriter, r *http.Request) {
	t, creds, err := s.fixTarget(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	var in struct {
		PlanID string `json:"plan_id"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	pf := recursorFixes.take(in.PlanID)
	if pf == nil || pf.target != t.ID {
		writeErr(w, 409, "this preview has expired; press Fix again")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	conn, _, err := fixDialSSH(ctx, pf.ssh)
	if err != nil {
		writeErr(w, 502, "SSH to "+pf.ssh.Host+": "+err.Error())
		return
	}
	if cl, ok := conn.(interface{ Close() error }); ok {
		defer cl.Close()
	}
	_ = s.Audit.Record(r.Context(), actor(r), "dns.recursor.fix.start", "target/"+t.Name,
		map[string]any{"host": pf.plan.Host, "mode": pf.plan.Mode, "steps": pf.plan.Steps})
	res := recursorfix.Apply(ctx, conn, pf.plan, recursorfix.Checks{
		API: func(ctx context.Context, url, key string) error { return recursorfix.CheckAPI(ctx, url, key, nil) },
		DNS: func(ctx context.Context, host, zone string) error {
			l := dnscheck.ProbeServer(ctx, core.ProbeDNS, host, zone)
			if !l.InternetOK {
				return fmt.Errorf("%s: %s", l.Internet, l.InternetResult)
			}
			if l.Internal != "" && !l.InternalOK {
				return fmt.Errorf("%s: %s", l.Internal, l.InternalResult)
			}
			return nil
		},
	})
	if res.OK && pf.plan.URL != "" {
		if err := s.saveRecursor(r.Context(), t, creds, pf.plan.URL, pf.plan.Key(), nil); err != nil {
			res.OK, res.Error = false, "The server is fixed, but saving the URL in NCC failed: "+err.Error()
		}
	}
	_ = s.Audit.Record(r.Context(), actor(r), "dns.recursor.fix", "target/"+t.Name,
		map[string]any{"host": pf.plan.Host, "mode": pf.plan.Mode, "ok": res.OK, "rolled_back": res.RolledBack, "error": res.Error, "url": res.URL})
	writeJSON(w, 200, map[string]any{"result": res, "mode": pf.plan.Mode})
}

// sourceAddress is NCC's own address on the way to host (what the server sees connections
// come from). No packet is sent.
func sourceAddress(host string) string {
	c, err := net.Dial("udp", net.JoinHostPort(host, "53"))
	if err != nil {
		return ""
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
}
