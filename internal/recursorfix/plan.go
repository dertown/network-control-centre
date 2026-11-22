package recursorfix

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ---- step 2: change the server over SSH ----

// Conn runs commands and reads and writes files on the DNS server (certdeploy's SSH
// connection satisfies it). Run and the file calls run as root when sudo is set up.
type Conn interface {
	Run(ctx context.Context, cmd string) (string, error)
	ReadFile(ctx context.Context, path string) ([]byte, error)
	WriteFile(ctx context.Context, path string, data []byte, mode, owner string) error
}

// Plan modes.
const (
	// ModeAPI turns on the web server and API of a Recursor that already answers clients.
	ModeAPI = "api"
	// ModeInstall installs the PowerDNS Recursor package (and stops it until it is set up).
	ModeInstall = "install"
	// ModeResolver makes the Recursor the server's resolver on port 53: the authoritative
	// server moves to 127.0.0.1:<AuthPort>, the Recursor sends the internal zones to it and
	// everything else to the ISP, and its API is turned on.
	ModeResolver = "resolver"
)

// Facts are what NCC found on the server.
type Facts struct {
	OS         string `json:"os,omitempty"`
	Packages   string `json:"packages,omitempty"` // apt or dnf
	Binary     string `json:"binary,omitempty"`
	Version    string `json:"version,omitempty"`
	Unit       string `json:"unit,omitempty"`
	ConfigFile string `json:"config_file,omitempty"`
	Style      string `json:"style,omitempty"` // "conf" (key=value) or "yaml" (Recursor 5)
	IncludeDir string `json:"include_dir,omitempty"`
	// OnPort53 is what answers DNS on port 53: "recursor", "authoritative", another program or "".
	OnPort53  string   `json:"on_port_53,omitempty"`
	Listening []string `json:"listening,omitempty"` // what the Recursor listens on now
	Docker    string   `json:"docker,omitempty"`
	UFW       bool     `json:"ufw,omitempty"`
	// The authoritative server on the same machine, when there is one.
	AuthBinary string            `json:"auth_binary,omitempty"`
	AuthUnit   string            `json:"auth_unit,omitempty"`
	AuthConfig string            `json:"auth_config,omitempty"`
	Current    map[string]string `json:"current"` // the Recursor's settings now (api-key masked)
}

// Step is one change, shown exactly as it will run.
type Step struct {
	Title   string `json:"title"`
	Command string `json:"command,omitempty"`
	File    string `json:"file,omitempty"`
	// Diff is the change to File: "-" lines are commented out, "+" added, "~" set.
	Diff []string `json:"diff,omitempty"`
	Note string   `json:"note,omitempty"`
}

// Plan is what NCC will change on the server.
type Plan struct {
	Mode  string `json:"mode"`
	Host  string `json:"host"`
	Facts Facts  `json:"facts"`
	Steps []Step `json:"steps"`
	// URL is the Recursor API URL NCC saves once it answers ("" for ModeInstall).
	URL string `json:"url,omitempty"`
	// NewKey is set when NCC makes a new api-key (none was set, or it was stored hashed).
	NewKey   bool     `json:"new_key"`
	Warnings []string `json:"warnings"`
	// Blocked says why NCC can't make the change itself (and what to do instead).
	Blocked string `json:"blocked,omitempty"`
	// Next says a second preview follows once this plan has run (ModeInstall).
	Next string `json:"next,omitempty"`
	// Zone is the internal zone the result is tested with (ModeResolver).
	Zone string `json:"zone,omitempty"`

	key      string
	actions  []action
	rollback []string
}

// Key is the api-key the plan sets (or keeps).
func (p *Plan) Key() string { return p.key }

type action struct {
	title   string
	cmd     string // run
	file    string // write
	content []byte
	verify  string // "running:<unit>", "dns", "api"
	change  bool   // the server is changed from here on: undo on a later failure
}

// Options are the inputs to Inspect.
type Options struct {
	Host string // the DNS server's address, as NCC reaches it
	// NCCAddress is NCC's own address as the server sees it; it goes into webserver-allow-from.
	NCCAddress string
	// MakeResolver lets the plan install the Recursor and put it on port 53 when the server
	// only runs the authoritative server.
	MakeResolver bool
	// AuthZones are the zones on the authoritative server, sent to it by the Recursor.
	AuthZones []string
	// ISP are the internet provider's DNS servers the Recursor forwards everything else to;
	// empty means it resolves from the root servers itself.
	ISP []string
	// AuthPort is where the authoritative server moves to (default 5300).
	AuthPort string
	// Now stamps backups and comments (time.Now when zero).
	Now time.Time
	// Key, when set, is used as the api-key instead of a random one (tests).
	Key string
}

const masked = "•••• (kept in NCC's vault)"

// Inspect reads the server and builds the plan. It changes nothing.
func Inspect(ctx context.Context, c Conn, o Options) (*Plan, error) {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.AuthPort == "" {
		o.AuthPort = "5300"
	}
	p := &Plan{Host: o.Host, Warnings: []string{}, Steps: []Step{}, Facts: Facts{Current: map[string]string{}}}
	f := &p.Facts
	out, err := c.Run(ctx, factsScript)
	if err != nil {
		l := strings.ToLower(err.Error())
		if strings.Contains(l, "sudo") || strings.Contains(l, "password is required") || strings.Contains(l, "not in the sudoers") {
			return nil, fmt.Errorf("the SSH user can't run commands as root: tick “Use sudo” and give the password, or log in as root (%v)", err)
		}
		return nil, fmt.Errorf("reading the server: %w", err)
	}
	sec := sections(out)
	f.OS = firstLine(sec["os"])
	f.Packages = firstLine(sec["pkg"])
	f.Binary = firstLine(sec["bin"])
	if m := versionRe.FindString(firstLine(sec["version"])); m != "" {
		f.Version = m
	}
	f.Docker = strings.TrimSpace(sec["docker"])
	f.UFW = strings.Contains(strings.ToLower(sec["ufw"]), "status: active")
	f.Unit = pickUnit(strings.Fields(sec["units"]), "pdns-recursor.service")
	f.AuthBinary = firstLine(sec["authbin"])
	f.AuthUnit = pickUnit(strings.Fields(sec["authunits"]), "pdns.service")
	f.AuthConfig = firstLine(sec["authconf"])
	listen := parseListen(sec["listen"])
	for _, l := range listen {
		if isRecursorProc(l.proc) {
			f.Listening = append(f.Listening, l.addr)
		}
		if l.port == "53" && f.OnPort53 == "" {
			switch {
			case isRecursorProc(l.proc):
				f.OnPort53 = "recursor"
			case l.proc == "pdns_server" || strings.HasPrefix(l.proc, "pdns_server"):
				f.OnPort53 = "authoritative"
			default:
				f.OnPort53 = nonEmpty(l.proc, "another program")
			}
		}
	}
	for _, l := range listen { // the Recursor wins if both somehow show
		if l.port == "53" && isRecursorProc(l.proc) {
			f.OnPort53 = "recursor"
		}
	}
	setupHint := "webserver=yes, webserver-address=0.0.0.0, webserver-port=8082, webserver-allow-from=127.0.0.1,::1," + nonEmpty(o.NCCAddress, "<NCC's address>") + ", api-key=<a long random key>"

	// decide what to do
	resolverMode := o.MakeResolver && f.OnPort53 != "recursor"
	switch {
	case f.Binary == "" && f.Docker != "":
		p.Blocked = "PowerDNS Recursor runs in Docker here (" + f.Docker + "), so NCC won't edit it. Add these to the container's recursor settings and recreate it: " + setupHint + "; publish port 8082, then enter the URL and key in Settings."
		return p, nil
	case f.Binary == "" && !o.MakeResolver:
		p.Blocked = "PowerDNS Recursor isn't installed on " + o.Host + (map[bool]string{true: ", which only runs the authoritative server", false: ""}[f.OnPort53 == "authoritative"]) + ". There is no Recursor API to read. Install a resolver there, or point the DNS connection at the machine that answers your clients' lookups."
		return p, nil
	case f.Binary == "":
		return planInstall(p, o)
	case resolverMode && f.OnPort53 != "" && f.OnPort53 != "authoritative":
		p.Blocked = f.OnPort53 + " already answers on port 53 of " + o.Host + ", so NCC won't move things around. Stop it or set the Recursor up by hand."
		return p, nil
	case resolverMode && f.OnPort53 == "authoritative" && (f.AuthConfig == "" || f.AuthBinary == ""):
		p.Blocked = "The authoritative server answers on port 53, but NCC didn't find its pdns.conf to move it off the port."
		return p, nil
	}

	// the Recursor's configuration
	confDir := ""
	if f.Unit != "" {
		if es, err := c.Run(ctx, "systemctl show -p ExecStart --value "+shQuote(f.Unit)+" 2>/dev/null; true"); err == nil {
			if m := configDirRe.FindStringSubmatch(es); m != nil {
				confDir = m[1]
			}
		}
	}
	f.ConfigFile = pickConfig(strings.Fields(sec["files"]), confDir)
	if confDir != "" && f.ConfigFile == "" {
		if out, err := c.Run(ctx, "for f in "+shQuote(path.Join(confDir, "recursor.yml"))+" "+shQuote(path.Join(confDir, "recursor.conf"))+"; do [ -f \"$f\" ] && echo \"$f\"; done; true"); err == nil {
			f.ConfigFile = pickConfig(strings.Fields(out), confDir)
		}
	}
	if f.ConfigFile == "" {
		p.Blocked = "NCC found pdns_recursor but not its configuration file (looked in /etc/powerdns and /etc/pdns-recursor). Turn the web server on by hand: " + setupHint + ", then enter the URL and key in Settings."
		return p, nil
	}
	raw, err := c.ReadFile(ctx, f.ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", f.ConfigFile, err)
	}
	// Recursor 5 packages (Ubuntu 24.10+, Debian 13) ship recursor.conf in YAML, so the
	// format comes from the content, not the file name.
	f.Style = "conf"
	if strings.HasSuffix(f.ConfigFile, ".yml") || isYAMLConfig(raw) {
		f.Style = "yaml"
	}
	var cur settings
	if f.Style == "yaml" {
		cur, err = readYAML(raw)
	} else {
		cur = readConf(raw)
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", f.ConfigFile, err)
	}
	f.IncludeDir = cur.includeDir
	for k, v := range cur.values {
		if k == "api-key" && v != "" {
			v = "set"
			if strings.HasPrefix(cur.values[k], "$scrypt$") {
				v = "set (stored hashed)"
			}
		}
		f.Current[k] = v
	}

	w := desired(cur, listen, o)
	p.key, p.NewKey = w.key, w.newKey
	if w.newKey && cur.values["api-key"] != "" {
		p.Warnings = append(p.Warnings, "The current api-key is stored hashed, so NCC can't read it. NCC sets a new random key; anything else that uses the Recursor's API with the old key has to be given the new one.")
	}
	if w.portMoved != "" {
		p.Warnings = append(p.Warnings, w.portMoved)
	}
	p.URL = "http://" + net.JoinHostPort(o.Host, w.port)
	stamp := o.Now.UTC().Format("20060102T150405Z")
	recUnit := nonEmpty(f.Unit, "pdns-recursor")

	vals := w.apiValues()
	p.Mode = ModeAPI
	if resolverMode {
		p.Mode = ModeResolver
		if len(o.AuthZones) == 0 {
			p.Blocked = "NCC doesn't know which zones the authoritative server holds, so it can't tell the Recursor where to send them. Check the DNS connection in Settings first."
			return p, nil
		}
		p.Zone = shortestZone(o.AuthZones)
		vals = append(resolverValues(cur, o), vals...)
		if len(o.ISP) == 0 {
			p.Warnings = append(p.Warnings, "NCC doesn't know your ISP's DNS servers, so the Recursor will look internet names up from the root servers itself. Fill in “ISP DNS servers” in Settings to forward to your ISP instead.")
		}
	}

	var diff []string
	var content []byte
	if f.Style == "yaml" {
		content, diff, err = editYAML(raw, vals)
		if err != nil {
			return nil, fmt.Errorf("editing %s: %w", f.ConfigFile, err)
		}
	} else {
		content, diff = editConf(raw, vals, o.Now, "PowerDNS Recursor settings for Network Control Centre")
	}
	recChanged := string(content) != string(raw)
	restartRec := recChanged

	// 1. the Recursor's own file, checked before anything is restarted
	if recChanged {
		bak := f.ConfigFile + ".ncc-bak-" + stamp
		title := "Turn on the web server and API"
		if resolverMode {
			title = "Make the Recursor answer on port 53 and turn on its API"
		}
		p.Steps = append(p.Steps,
			Step{Title: "Back up " + path.Base(f.ConfigFile), Command: "cp -p " + shQuote(f.ConfigFile) + " " + shQuote(bak)},
			Step{Title: title, File: f.ConfigFile, Diff: diff, Note: "Existing lines for these settings are commented out, not deleted."})
		p.actions = append(p.actions,
			action{title: "Back up " + path.Base(f.ConfigFile), cmd: "cp -p " + shQuote(f.ConfigFile) + " " + shQuote(bak)},
			action{title: title, file: f.ConfigFile, content: content, change: true})
		p.rollback = append([]string{"cp -p " + shQuote(bak) + " " + shQuote(f.ConfigFile)}, p.rollback...)
		if check := configCheck(*f); check != "" {
			p.Steps = append(p.Steps, Step{Title: "Check the new configuration is valid", Command: check,
				Note: "Nothing is restarted if the Recursor rejects it; the old file is put back."})
			p.actions = append(p.actions, action{title: "Check the new configuration is valid", cmd: check})
		}
	}
	// 2. the authoritative server leaves port 53 (resolver mode)
	if resolverMode && f.OnPort53 == "authoritative" {
		araw, err := c.ReadFile(ctx, f.AuthConfig)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f.AuthConfig, err)
		}
		for _, l := range listen {
			if l.port == o.AuthPort {
				p.Blocked = "Port " + o.AuthPort + " is already used by " + nonEmpty(l.proc, "another program") + " on " + o.Host + ", so the authoritative server can't move there."
				return p, nil
			}
		}
		acur := readConf(araw)
		authVals := []kv{{"local-address", "127.0.0.1"}, {"local-port", o.AuthPort}}
		acontent, adiff := editConf(araw, authVals, o.Now, "Network Control Centre: the authoritative server answers the Recursor only")
		abak := f.AuthConfig + ".ncc-bak-" + stamp
		authUnit := nonEmpty(f.AuthUnit, "pdns")
		p.Steps = append(p.Steps,
			Step{Title: "Back up " + path.Base(f.AuthConfig), Command: "cp -p " + shQuote(f.AuthConfig) + " " + shQuote(abak)},
			Step{Title: "Move the authoritative server to 127.0.0.1:" + o.AuthPort, File: f.AuthConfig, Diff: adiff,
				Note: "It keeps all its zones and its API (port 8081 is not touched). Only the Recursor on this machine talks to it; secondary servers or anything else that queries it directly on port 53 must use port " + o.AuthPort + " or go through the Recursor."})
		p.actions = append(p.actions,
			action{title: "Back up " + path.Base(f.AuthConfig), cmd: "cp -p " + shQuote(f.AuthConfig) + " " + shQuote(abak)},
			action{title: "Move the authoritative server to 127.0.0.1:" + o.AuthPort, file: f.AuthConfig, content: acontent, change: true})
		p.rollback = append(p.rollback, "cp -p "+shQuote(abak)+" "+shQuote(f.AuthConfig))
		p.addIncludeFixes(ctx, c, acur.includeDir, f.AuthConfig, []string{"local-address", "local-port", "local-ipv6"}, stamp)
		p.Steps = append(p.Steps, Step{Title: "Restart the authoritative server", Command: "systemctl restart " + shQuote(authUnit),
			Note: "From here until the Recursor starts (a second or two) nothing answers on port 53; clients use their fallback DNS server."})
		p.actions = append(p.actions, action{title: "Restart the authoritative server", cmd: "systemctl restart " + shQuote(authUnit), change: true},
			action{title: "Check the authoritative server is running", verify: "running:" + authUnit})
		p.rollbackTail(recUnit, authUnit)
		restartRec = true
	}

	if f.Style == "conf" {
		keys := managedAPI
		if resolverMode {
			keys = append(append([]string{}, managedAPI...), managedResolver...)
		}
		p.addIncludeFixes(ctx, c, cur.includeDir, f.ConfigFile, keys, stamp)
	}
	if f.UFW && o.NCCAddress != "" {
		cmd := "ufw allow proto tcp from " + o.NCCAddress + " to any port " + w.port + " comment 'NCC: PowerDNS Recursor API'"
		p.Steps = append(p.Steps, Step{Title: "Let NCC reach the API through the firewall (ufw is on)", Command: cmd})
		p.actions = append(p.actions, action{title: "Let NCC through the firewall", cmd: cmd})
		if resolverMode {
			cmd := "ufw allow 53 comment 'DNS'"
			p.Steps = append(p.Steps, Step{Title: "Allow DNS (port 53) through the firewall", Command: cmd})
			p.actions = append(p.actions, action{title: "Allow DNS through the firewall", cmd: cmd})
		}
	}
	if restartRec {
		start := "systemctl restart " + shQuote(recUnit)
		if resolverMode {
			start = "systemctl enable " + shQuote(recUnit) + " && systemctl restart " + shQuote(recUnit)
		}
		p.Steps = append(p.Steps,
			Step{Title: "Restart the Recursor", Command: start,
				Note: "If it doesn't come back up and answer, NCC puts the old files back and restarts the services as they were."},
			Step{Title: "Check it's running", Command: "systemctl is-active " + shQuote(recUnit)})
		p.actions = append(p.actions, action{title: "Restart the Recursor", cmd: start, change: true},
			action{title: "Check the Recursor is running", verify: "running:" + recUnit})
		if len(p.rollback) > 0 && !resolverMode {
			p.rollback = append(p.rollback, "systemctl restart "+shQuote(recUnit))
		}
	}
	if resolverMode {
		p.Steps = append(p.Steps, Step{Title: "Check " + o.Host + " now answers internet and internal names",
			Command: "dig @" + o.Host + " " + "www.google.com A; dig @" + o.Host + " " + p.Zone + " SOA"})
		p.actions = append(p.actions, action{title: "Check " + o.Host + " answers internet and internal names", verify: "dns"})
	}
	p.Steps = append(p.Steps, Step{Title: "Check the API answers NCC, then save the URL and key in NCC", Command: "GET " + p.URL + "/api/v1/servers/localhost"})
	p.actions = append(p.actions, action{title: "Check the API answers NCC", verify: "api"})
	if f.Unit == "" {
		p.Warnings = append(p.Warnings, "NCC didn't find a pdns-recursor systemd service; it will use “systemctl restart pdns-recursor”.")
	}
	return p, nil
}

func planInstall(p *Plan, o Options) (*Plan, error) {
	f := p.Facts
	p.Mode = ModeInstall
	var cmd string
	switch f.Packages {
	case "apt":
		cmd = "DEBIAN_FRONTEND=noninteractive apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q pdns-recursor"
	case "dnf", "yum":
		cmd = f.Packages + " install -y pdns-recursor"
	default:
		p.Blocked = "NCC can only install PowerDNS Recursor with apt or dnf. Install the pdns-recursor package on " + o.Host + " yourself, then press Fix again."
		return p, nil
	}
	p.Steps = []Step{
		{Title: "Install PowerDNS Recursor", Command: cmd, Note: "Nothing else changes yet. The authoritative server keeps answering on port 53."},
		{Title: "Keep the new Recursor stopped until it is set up", Command: "systemctl disable --now pdns-recursor; true"},
	}
	p.actions = []action{{title: "Install PowerDNS Recursor", cmd: cmd}, {title: "Keep it stopped for now", cmd: "systemctl disable --now pdns-recursor 2>/dev/null; true"}}
	p.Next = "Once it is installed NCC reads the new Recursor's configuration and shows a second preview: moving the authoritative server to 127.0.0.1:" + o.AuthPort + " and putting the Recursor on port 53. Nothing moves until you confirm that one too."
	if f.OnPort53 == "authoritative" {
		p.Warnings = append(p.Warnings, o.Host+" only runs the PowerDNS authoritative server, which refuses internet lookups. That is why clients handed this server can't resolve internet names through it.")
	}
	return p, nil
}

// addIncludeFixes comments the given settings out of include-dir files, which are read
// after the main file and would override it.
func (p *Plan) addIncludeFixes(ctx context.Context, c Conn, dir, mainFile string, keys []string, stamp string) {
	if dir == "" {
		return
	}
	if !strings.HasPrefix(dir, "/") {
		dir = path.Join(path.Dir(mainFile), dir)
	}
	alt := strings.Join(keys, "|")
	out, err := c.Run(ctx, "grep -lE "+shQuote(`^[[:space:]]*(`+alt+`)[[:space:]]*\+?=`)+" "+shQuote(dir)+"/*.conf 2>/dev/null; true")
	if err != nil {
		return
	}
	for _, fl := range strings.Fields(out) {
		cmd := "sed -i.ncc-bak-" + stamp + " -E " + shQuote(`s/^([[:space:]]*(`+alt+`)[[:space:]]*\+?=)/# disabled by NCC: \1/`) + " " + shQuote(fl)
		p.Steps = append(p.Steps, Step{Title: "Comment out the same settings in " + fl, Command: cmd,
			Note: "Files in " + dir + " are read after " + path.Base(mainFile) + " and would override it."})
		p.actions = append(p.actions, action{title: "Comment out the same settings in " + fl, cmd: cmd, change: true})
		p.rollback = append(p.rollback, "cp -p "+shQuote(fl+".ncc-bak-"+stamp)+" "+shQuote(fl))
	}
}

// isYAMLConfig reports whether a Recursor configuration file is YAML (Recursor 5): it parses
// as a YAML mapping and has no old-style key=value lines.
func isYAMLConfig(b []byte) bool {
	for _, l := range strings.Split(string(b), "\n") {
		if _, _, _, ok := confLine(l); ok {
			return false
		}
	}
	var m map[string]any
	return yaml.Unmarshal(b, &m) == nil && len(m) > 0
}

// configCheck is the command that validates the Recursor's configuration without starting
// it (Recursor 5's --config=check), or "" when the installed version has none.
func configCheck(f Facts) string {
	major, _ := strconv.Atoi(strings.SplitN(f.Version, ".", 2)[0])
	if major < 5 {
		return ""
	}
	bin := nonEmpty(f.Binary, "pdns_recursor")
	return shQuote(bin) + " --config-dir=" + shQuote(path.Dir(f.ConfigFile)) + " --config=check"
}

// rollbackTail finishes the undo list for resolver mode: stop the Recursor so the
// authoritative server can take port 53 back, restart it on its old settings, and start the
// Recursor again only if it was running before.
func (p *Plan) rollbackTail(recUnit, authUnit string) {
	p.rollback = append(p.rollback, "{ systemctl disable --now "+shQuote(recUnit)+" 2>/dev/null; true; }", "systemctl restart "+shQuote(authUnit))
}

// StepResult is how one step went.
type StepResult struct {
	Title  string `json:"title"`
	OK     bool   `json:"ok"`
	Output string `json:"output,omitempty"`
}

// Result is how applying a plan went.
type Result struct {
	OK    bool         `json:"ok"`
	Steps []StepResult `json:"steps"`
	URL   string       `json:"url,omitempty"`
	Error string       `json:"error,omitempty"`
	// RolledBack is set when the server was put back as it was.
	RolledBack bool `json:"rolled_back,omitempty"`
}

// Checks verify a change from NCC's side.
type Checks struct {
	// API returns nil when url answers as a PowerDNS Recursor with key.
	API func(ctx context.Context, url, key string) error
	// DNS returns nil when host answers an internet name and zone.
	DNS func(ctx context.Context, host, zone string) error
	// Wait is the pause between retries (default 1s).
	Wait time.Duration
}

// Apply carries out a plan, undoing it when a step after the first change fails.
func Apply(ctx context.Context, c Conn, p *Plan, chk Checks) Result {
	r := Result{URL: p.URL, Steps: []StepResult{}}
	if p.Blocked != "" {
		r.Error = p.Blocked
		return r
	}
	if chk.Wait == 0 {
		chk.Wait = time.Second
	}
	changed := false
	retry := func(fn func() error) error {
		var err error
		for i := 0; i < 6; i++ {
			if err = fn(); err == nil {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(chk.Wait):
			}
		}
		return err
	}
	for _, a := range p.actions {
		var out string
		var err error
		switch {
		case a.file != "":
			err = c.WriteFile(ctx, a.file, a.content, "", "")
		case a.cmd != "":
			out, err = c.Run(ctx, a.cmd)
		case strings.HasPrefix(a.verify, "running:"):
			unit := strings.TrimPrefix(a.verify, "running:")
			err = retry(func() error {
				st, e := c.Run(ctx, "systemctl is-active "+shQuote(unit))
				out = strings.TrimSpace(st)
				if out == "active" {
					return nil
				}
				if e == nil {
					e = errors.New("not running: " + out)
				}
				return e
			})
			if err != nil {
				if log, _ := c.Run(ctx, "journalctl -u "+shQuote(unit)+" -n 15 --no-pager 2>/dev/null; true"); strings.TrimSpace(log) != "" {
					out = strings.TrimSpace(log)
				}
			}
		case a.verify == "dns":
			err = retry(func() error { return chk.DNS(ctx, p.Host, p.Zone) })
		case a.verify == "api":
			err = retry(func() error { return chk.API(ctx, p.URL, p.key) })
		}
		sr := StepResult{Title: a.title, OK: err == nil, Output: strings.TrimSpace(out)}
		if err != nil {
			sr.Output = strings.TrimSpace(sr.Output + "\n" + err.Error())
		}
		r.Steps = append(r.Steps, sr)
		if a.change && err == nil {
			changed = true
		}
		if err == nil {
			continue
		}
		r.Error = a.title + ": " + err.Error()
		if a.verify == "api" {
			// DNS works and the Recursor runs; only NCC can't reach its API: keep the change
			r.Error = "The Recursor is running with the new settings, but NCC still can't reach " + p.URL + " (" + err.Error() + "). A firewall between NCC and the server may be blocking the port."
			return r
		}
		if (changed || a.change) && len(p.rollback) > 0 {
			undo := strings.Join(p.rollback, " && ")
			out, err := c.Run(ctx, undo)
			sr := StepResult{Title: "Put everything back as it was", OK: err == nil, Output: strings.TrimSpace(out)}
			if err != nil {
				sr.Output = strings.TrimSpace(sr.Output + "\n" + err.Error())
			}
			r.Steps = append(r.Steps, sr)
			r.RolledBack = err == nil
		}
		return r
	}
	r.OK = true
	return r
}

// ---- reading the server ----

const factsScript = `echo "@os"; . /etc/os-release 2>/dev/null && echo "$PRETTY_NAME"
echo "@pkg"; if command -v apt-get >/dev/null 2>&1; then echo apt; elif command -v dnf >/dev/null 2>&1; then echo dnf; elif command -v yum >/dev/null 2>&1; then echo yum; fi
echo "@bin"; command -v pdns_recursor 2>/dev/null || for b in /usr/sbin/pdns_recursor /usr/local/sbin/pdns_recursor; do [ -x "$b" ] && echo "$b" && break; done
echo "@version"; v=$(command -v pdns_recursor || echo /usr/sbin/pdns_recursor); [ -x "$v" ] && "$v" --version 2>&1 | grep -m1 -i 'recursor'
echo "@units"; systemctl list-unit-files --no-legend 'pdns-recursor*' 2>/dev/null | awk '{print $1}' | grep -v '@'
echo "@files"; for d in /etc/powerdns /etc/pdns-recursor /etc/pdns /usr/local/etc/powerdns; do for f in recursor.yml recursor.conf; do [ -f "$d/$f" ] && echo "$d/$f"; done; done
echo "@authbin"; command -v pdns_server 2>/dev/null || for b in /usr/sbin/pdns_server /usr/local/sbin/pdns_server; do [ -x "$b" ] && echo "$b" && break; done
echo "@authunits"; systemctl list-unit-files --no-legend 'pdns.service' 'pdns-server*' 2>/dev/null | awk '{print $1}' | grep -v '@'
echo "@authconf"; for f in /etc/powerdns/pdns.conf /etc/pdns/pdns.conf /usr/local/etc/powerdns/pdns.conf; do [ -f "$f" ] && echo "$f"; done
echo "@listen"; (ss -ltnpH 2>/dev/null || netstat -ltnp 2>/dev/null)
echo "@ufw"; command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -n 1
echo "@docker"; command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}} ({{.Image}})' 2>/dev/null | grep -iE 'pdns|powerdns|recursor'
echo "@end"; true`

var versionRe = regexp.MustCompile(`\d+\.\d+(\.\d+)?[\w.-]*`)

var configDirRe = regexp.MustCompile(`--config-dir[= ]([^\s;]+)`)

func sections(out string) map[string]string {
	m := map[string]string{}
	cur := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "@") {
			cur = strings.TrimSpace(l[1:])
			continue
		}
		if cur != "" {
			m[cur] += l + "\n"
		}
	}
	return m
}

func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}

func pickUnit(units []string, prefer string) string {
	for _, u := range units {
		if u == prefer {
			return u
		}
	}
	if len(units) > 0 {
		return units[0]
	}
	return ""
}

// pickConfig chooses the file the Recursor reads: recursor.yml wins over recursor.conf in
// the same folder (Recursor 5), and the service's --config-dir wins over the usual places.
func pickConfig(files []string, dir string) string {
	dirs := []string{}
	if dir != "" {
		dirs = append(dirs, dir)
	}
	for _, f := range files {
		dirs = append(dirs, path.Dir(f))
	}
	for _, d := range dirs {
		for _, name := range []string{"recursor.yml", "recursor.conf"} {
			for _, f := range files {
				if f == path.Join(d, name) {
					return f
				}
			}
		}
	}
	return ""
}

func isRecursorProc(p string) bool {
	return p == "pdns_recursor" || p == "pdns-recursor" || strings.HasPrefix(p, "pdns_recursor")
}

type listener struct {
	addr string // "0.0.0.0:8082"
	port string
	proc string
}

var procRe = regexp.MustCompile(`users:\(\("([^"]+)"`)

// parseListen reads `ss -ltnpH` (or netstat -ltnp) output.
func parseListen(s string) []listener {
	var out []listener
	for _, l := range strings.Split(s, "\n") {
		fs := strings.Fields(l)
		if len(fs) < 4 {
			continue
		}
		var addr, proc string
		switch {
		case fs[0] == "LISTEN" && len(fs) >= 5: // ss: State Recv-Q Send-Q Local Peer [Process]
			addr = fs[3]
			if m := procRe.FindStringSubmatch(l); m != nil {
				proc = m[1]
			}
		case strings.HasPrefix(fs[0], "tcp") && len(fs) >= 7: // netstat: Proto Recv Send Local Foreign State PID/Program
			addr = fs[3]
			if i := strings.Index(fs[6], "/"); i >= 0 {
				proc = fs[6][i+1:]
			}
		default:
			continue
		}
		i := strings.LastIndex(addr, ":")
		if i < 0 {
			continue
		}
		out = append(out, listener{addr: addr, port: addr[i+1:], proc: proc})
	}
	return out
}

// ---- the settings ----

// managedAPI and managedResolver are the settings NCC sets, old-style (recursor.conf) names.
var (
	managedAPI      = []string{"webserver", "webserver-address", "webserver-port", "webserver-allow-from", "api-key"}
	managedResolver = []string{"local-address", "local-port", "forward-zones", "forward-zones-recurse"}
)

type settings struct {
	values     map[string]string // old-style names
	includeDir string
}

type want struct {
	address, port, allowFrom, key string
	newKey                        bool
	portMoved                     string
}

type kv struct{ k, v string }

func desired(cur settings, listen []listener, o Options) want {
	w := want{}
	v := cur.values
	w.port = nonEmpty(v["webserver-port"], "8082")
	// something else on the port (the authoritative server's API, say) means a clash
	for _, l := range listen {
		if l.port == w.port && l.proc != "" && !isRecursorProc(l.proc) {
			used := map[string]bool{}
			for _, l2 := range listen {
				used[l2.port] = true
			}
			old := w.port
			for p := 8082; p < 8100; p++ {
				if !used[strconv.Itoa(p)] {
					w.port = strconv.Itoa(p)
					break
				}
			}
			w.portMoved = fmt.Sprintf("Port %s is taken by %s, so the Recursor's web server goes on port %s.", old, l.proc, w.port)
			break
		}
	}
	switch a := strings.TrimSpace(v["webserver-address"]); a {
	case "0.0.0.0", "::", "[::]":
		w.address = a
	default:
		if a != "" && a == o.Host {
			w.address = a
		} else {
			w.address = "0.0.0.0" // 127.0.0.1 (the default) can't be reached from NCC
		}
	}
	allow := splitList(nonEmpty(v["webserver-allow-from"], "127.0.0.1,::1"))
	if o.NCCAddress != "" && !allowed(allow, o.NCCAddress) {
		allow = append(allow, o.NCCAddress)
	}
	w.allowFrom = strings.Join(allow, ",")
	switch k := v["api-key"]; {
	case o.Key != "":
		w.key, w.newKey = o.Key, k != o.Key
	case k != "" && !strings.HasPrefix(k, "$scrypt$"):
		w.key = k
	default:
		w.key, w.newKey = randomKey(), true
	}
	return w
}

func (w want) apiValues() []kv {
	return []kv{{"webserver", "yes"}, {"webserver-address", w.address}, {"webserver-port", w.port},
		{"webserver-allow-from", w.allowFrom}, {"api-key", w.key}}
}

// resolverValues put the Recursor on port 53, sending the internal zones to the
// authoritative server and the rest to the ISP. Forward zones already there for other
// zones are kept.
func resolverValues(cur settings, o Options) []kv {
	auth := "127.0.0.1:" + o.AuthPort
	fz := parseForwardZones(cur.values["forward-zones"])
	for _, z := range o.AuthZones {
		fz[strings.TrimSuffix(z, ".")] = []string{auth}
	}
	out := []kv{{"local-address", "0.0.0.0"}, {"local-port", "53"}, {"forward-zones", formatForwardZones(fz)}}
	fr := parseForwardZones(cur.values["forward-zones-recurse"])
	if len(o.ISP) > 0 {
		fr["."] = o.ISP
	}
	if len(fr) > 0 {
		out = append(out, kv{"forward-zones-recurse", formatForwardZones(fr)})
	}
	return out
}

// parseForwardZones reads "a.lan=10.0.0.1;10.0.0.2, b.lan=10.0.0.3" (a leading + is dropped).
func parseForwardZones(s string) map[string][]string {
	m := map[string][]string{}
	for _, e := range strings.Split(s, ",") {
		e = strings.TrimPrefix(strings.TrimSpace(e), "+")
		z, srv, ok := strings.Cut(e, "=")
		if !ok || strings.TrimSpace(z) == "" {
			continue
		}
		z = strings.TrimSpace(z)
		if z != "." {
			z = strings.TrimSuffix(z, ".")
		}
		var ss []string
		for _, x := range strings.Split(srv, ";") {
			if x = strings.TrimSpace(x); x != "" {
				ss = append(ss, x)
			}
		}
		m[z] = ss
	}
	return m
}

func formatForwardZones(m map[string][]string) string {
	zs := make([]string, 0, len(m))
	for z := range m {
		zs = append(zs, z)
	}
	sort.Strings(zs)
	parts := make([]string, 0, len(zs))
	for _, z := range zs {
		parts = append(parts, z+"="+strings.Join(m[z], ";"))
	}
	return strings.Join(parts, ", ")
}

func shortestZone(zs []string) string {
	best := ""
	for _, z := range zs {
		z = strings.TrimSuffix(z, ".")
		if z == "" || strings.HasSuffix(z, ".arpa") {
			continue
		}
		if best == "" || len(z) < len(best) {
			best = z
		}
	}
	return best
}

func allowed(list []string, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, e := range list {
		if p, err := netip.ParsePrefix(e); err == nil && p.Contains(a) {
			return true
		}
		if b, err := netip.ParseAddr(e); err == nil && b == a {
			return true
		}
	}
	return false
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// readConf reads old-style key=value configuration (# comments, += appends).
func readConf(b []byte) settings {
	s := settings{values: map[string]string{}}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, add, ok := confLine(l)
		if !ok {
			continue
		}
		if k == "include-dir" {
			s.includeDir = v
		}
		if add && s.values[k] != "" {
			s.values[k] += "," + v
		} else {
			s.values[k] = v
		}
	}
	return s
}

func confLine(l string) (key, val string, add, ok bool) {
	t := strings.TrimSpace(l)
	if t == "" || strings.HasPrefix(t, "#") {
		return "", "", false, false
	}
	i := strings.Index(t, "=")
	if i <= 0 {
		return "", "", false, false
	}
	key = strings.TrimSpace(t[:i])
	if strings.HasSuffix(key, "+") {
		add, key = true, strings.TrimSpace(strings.TrimSuffix(key, "+"))
	}
	val = strings.TrimSpace(t[i+1:])
	if j := strings.Index(val, " #"); j >= 0 {
		val = strings.TrimSpace(val[:j])
	}
	return key, val, add, true
}

// editConf comments out the lines that set any of vals and appends them in one block.
func editConf(b []byte, vals []kv, now time.Time, heading string) ([]byte, []string) {
	set := map[string]bool{}
	for _, x := range vals {
		set[x.k] = true
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	var diff []string
	for i, l := range lines {
		if k, _, _, ok := confLine(l); ok && set[k] {
			lines[i] = "# disabled by NCC: " + l
			diff = append(diff, "- "+maskLine(l))
		}
	}
	block := []string{"", "# " + heading + " (" + now.Format("2006-01-02") + ")"}
	for _, x := range vals {
		block = append(block, x.k+"="+x.v)
		if x.k == "api-key" {
			diff = append(diff, "+ api-key="+masked)
		} else {
			diff = append(diff, "+ "+x.k+"="+x.v)
		}
	}
	return []byte(strings.Join(append(lines, block...), "\n") + "\n"), diff
}

func maskLine(l string) string {
	if k, _, _, ok := confLine(l); ok && k == "api-key" {
		return "api-key=••••"
	}
	return l
}

// yamlPaths maps old-style names to Recursor 5 YAML section and key.
var yamlPaths = map[string][2]string{
	"webserver": {"webservice", "webserver"}, "webserver-address": {"webservice", "address"}, "webserver-port": {"webservice", "port"},
	"webserver-allow-from": {"webservice", "allow_from"}, "api-key": {"webservice", "api_key"},
	"local-address": {"incoming", "listen"}, "local-port": {"incoming", "port"},
	"forward-zones": {"recursor", "forward_zones"}, "forward-zones-recurse": {"recursor", "forward_zones_recurse"},
}

func readYAML(b []byte) (settings, error) {
	s := settings{values: map[string]string{}}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return s, err
	}
	if rec, ok := doc["recursor"].(map[string]any); ok {
		if d, ok := rec["include_dir"].(string); ok {
			s.includeDir = d
		}
	}
	for old, yp := range yamlPaths {
		sec, _ := doc[yp[0]].(map[string]any)
		v, ok := sec[yp[1]]
		if !ok {
			continue
		}
		switch x := v.(type) {
		case []any:
			var parts []string
			for _, e := range x {
				if m, ok := e.(map[string]any); ok { // forward zone {zone, forwarders}
					var fw []string
					if l, ok := m["forwarders"].([]any); ok {
						for _, f := range l {
							fw = append(fw, fmt.Sprint(f))
						}
					}
					parts = append(parts, fmt.Sprint(m["zone"])+"="+strings.Join(fw, ";"))
					continue
				}
				parts = append(parts, fmt.Sprint(e))
			}
			s.values[old] = strings.Join(parts, ",")
		case bool:
			s.values[old] = map[bool]string{true: "yes", false: "no"}[x]
		default:
			s.values[old] = fmt.Sprint(x)
		}
	}
	return s, nil
}

// editYAML sets vals in a Recursor 5 recursor.yml, keeping the rest of the file.
func editYAML(b []byte, vals []kv) ([]byte, []string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, nil, err
	}
	if len(doc.Content) == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, nil, errors.New("recursor.yml is not a mapping")
	}
	section := func(name string) *yaml.Node {
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value == name && root.Content[i+1].Kind == yaml.MappingNode {
				return root.Content[i+1]
			}
		}
		n := &yaml.Node{Kind: yaml.MappingNode}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: name}, n)
		return n
	}
	var diff []string
	scalar := func(v, tag string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Value: v, Tag: tag} }
	list := func(items []string) *yaml.Node {
		seq := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
		for _, a := range items {
			seq.Content = append(seq.Content, scalar(a, "!!str"))
		}
		return seq
	}
	for _, x := range vals {
		yp := yamlPaths[x.k]
		sec := section(yp[0])
		var node *yaml.Node
		show := x.v
		switch x.k {
		case "webserver":
			node = scalar("true", "!!bool")
			show = "true"
		case "webserver-port", "local-port":
			node = scalar(x.v, "!!int")
		case "webserver-allow-from", "local-address":
			node = list(splitList(x.v))
			show = "[" + strings.Join(splitList(x.v), ", ") + "]"
		case "forward-zones", "forward-zones-recurse":
			fz := parseForwardZones(x.v)
			node = &yaml.Node{Kind: yaml.SequenceNode}
			zs := make([]string, 0, len(fz))
			for z := range fz {
				zs = append(zs, z)
			}
			sort.Strings(zs)
			for _, z := range zs {
				node.Content = append(node.Content, &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
					scalar("zone", "!!str"), scalar(z, "!!str"), scalar("forwarders", "!!str"), list(fz[z])}})
			}
		case "api-key":
			node = scalar(x.v, "!!str")
			show = masked
		default:
			node = scalar(x.v, "!!str")
		}
		key := yp[0] + "." + yp[1]
		done := false
		for i := 0; i+1 < len(sec.Content); i += 2 {
			if sec.Content[i].Value == yp[1] {
				sec.Content[i+1] = node
				diff = append(diff, "~ "+key+": "+show)
				done = true
			}
		}
		if !done {
			sec.Content = append(sec.Content, scalar(yp[1], "!!str"), node)
			diff = append(diff, "+ "+key+": "+show)
		}
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, nil, err
	}
	return out, diff, nil
}

func randomKey() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
