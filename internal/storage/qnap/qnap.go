// Package qnap is the NCC storage provider for QNAP NAS devices running QTS or QuTS hero.
//
// It reads through the same CGI endpoints the QTS web interface uses: system information,
// health, temperatures and fans (management/manaRequest.cgi), volume capacity and per-share
// use (management/chartReq.cgi), per-disk SMART health and temperature (disk/qsmart.cgi),
// firmware updates (sys/sysRequest.cgi) and the shared folder list (File Station
// filemanager/utilRequest.cgi).
//
// QNAP's HTTP API does not report RAID or volume state (degraded, rebuilding), so when an
// SNMP community or SNMPv3 user is saved with the connection NCC also reads QNAP's NAS-MIB
// for volume and disk status.
//
// Sign in with a local administrator account; QTS only answers most of these calls for
// administrators. Accounts with two-step verification can't sign in through the API.
package qnap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/netutil"
	"github.com/dertown/network-control-centre/internal/storage"
	"github.com/dertown/network-control-centre/internal/storage/snmpnas"
)

func init() { storage.Register(Provider{}) }

// Provider implements storage.Provider and storage.Controller for QNAP.
type Provider struct{}

// Kind implements storage.Provider.
func (Provider) Kind() string { return "qnap" }

// Option keys.
const (
	OptTLS         = "tls"             // "pin" (default) or "verify"
	OptFingerprint = "tls_fingerprint" // pinned SHA-256 of the NAS certificate
)

// ErrUnauthorized means the NAS refused the login.
var ErrUnauthorized = errors.New("qnap: login refused")

type client struct {
	base string // https://nas:443/cgi-bin/
	http *http.Client
	pin  *netutil.Pinner
	sid  string
}

func newClient(t storage.Target) (*client, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(t.Address), "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("qnap: address must be a URL like https://192.168.1.20 or http://192.168.1.20:8080, got %q", t.Address)
	}
	if u.Port() == "" && u.Scheme == "http" {
		u.Host = net.JoinHostPort(u.Hostname(), "8080")
	}
	mode := t.Options[OptTLS]
	if mode == "" {
		mode = "pin"
	}
	hc, pin := netutil.NewClient(mode, t.Options[OptFingerprint], 30*time.Second)
	u.Path = "/cgi-bin/"
	return &client{base: u.String(), http: hc, pin: pin}, nil
}

func (c *client) login(ctx context.Context, creds map[string]string) error {
	user, pass := strings.TrimSpace(creds["username"]), creds["password"]
	if user == "" || pass == "" {
		return errors.New("qnap: give the NAS admin username and password")
	}
	form := url.Values{"user": {user}, "pwd": {base64.StdEncoding.EncodeToString([]byte(pass))}, "serviceKey": {"1"}}
	root, err := c.call(ctx, http.MethodPost, "authLogin.cgi", form, false)
	if err != nil {
		return err
	}
	if root.S("need_2sv") == "1" {
		return fmt.Errorf("%w: this account uses two-step verification; make a separate admin account for NCC without it", ErrUnauthorized)
	}
	if root.S("authPassed") != "1" || root.S("authSid") == "" {
		return fmt.Errorf("%w: check the username and password (it must be an administrator)", ErrUnauthorized)
	}
	c.sid = root.S("authSid")
	return nil
}

func (c *client) logout(ctx context.Context) {
	if c.sid != "" {
		_, _ = c.call(ctx, http.MethodGet, "authLogout.cgi?logout=1", nil, true)
	}
}

// call runs a CGI that answers in XML (<QDocRoot>).
func (c *client) call(ctx context.Context, method, path string, form url.Values, withSID bool) (*storage.Node, error) {
	raw, err := c.raw(ctx, method, path, form, withSID)
	if err != nil {
		return nil, err
	}
	root, err := storage.ParseXML(strings.NewReader(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("qnap: %s: unreadable answer: %w", cgiName(path), err)
	}
	if withSID && root.S("authPassed") == "0" {
		return nil, fmt.Errorf("%w: the session was refused on %s (the account may not be an administrator)", ErrUnauthorized, cgiName(path))
	}
	return root, nil
}

func (c *client) raw(ctx context.Context, method, path string, form url.Values, withSID bool) ([]byte, error) {
	target := c.base + path
	var body io.Reader
	if withSID {
		if method == http.MethodPost {
			if form == nil {
				form = url.Values{}
			}
			form.Set("sid", c.sid)
		} else {
			sep := "?"
			if strings.Contains(target, "?") {
				sep = "&"
			}
			target += sep + "sid=" + url.QueryEscape(c.sid)
		}
	}
	if method == http.MethodPost && form != nil {
		body = strings.NewReader(form.Encode())
	}
	r, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.http.Do(r)
	if err != nil {
		return nil, fmt.Errorf("qnap: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("qnap: %s: HTTP %d", cgiName(path), resp.StatusCode)
	}
	return raw, nil
}

func cgiName(path string) string {
	p, _, _ := strings.Cut(path, "?")
	return p
}

func atoi(s string) int {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "%"))
	if i, err := strconv.Atoi(s); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return int(f)
	}
	return 0
}

func atof(s string) float64 {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "%"))
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

func atoi64(s string) int64 {
	i, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return i
}

// Collect implements storage.Provider.
func (Provider) Collect(ctx context.Context, t storage.Target, creds map[string]string) (*storage.Result, error) {
	c, err := newClient(t)
	if err != nil {
		return nil, err
	}
	res := &storage.Result{}
	defer func() {
		if t.Options[OptTLS] != "verify" && t.Options[OptFingerprint] == "" && c.pin.Seen() != "" {
			res.OptionUpdates = map[string]string{OptFingerprint: c.pin.Seen()}
		}
	}()
	if err := c.login(ctx, creds); err != nil {
		return res, err
	}
	defer c.logout(context.WithoutCancel(ctx))

	inv := &storage.Inventory{Target: t.Name, Kind: "qnap", TakenAt: time.Now().UTC(),
		Capabilities: []string{storage.CapRestart, storage.CapShutdown, storage.CapFolderCreate}}
	inv.System.Vendor = "QNAP"
	inv.System.CPUUsage = -1
	res.Inventory = inv

	root, err := c.call(ctx, http.MethodGet, "management/manaRequest.cgi?subfunc=sysinfo&hd=no&multicpu=1", nil, true)
	if err != nil {
		return res, err
	}
	parseSysinfo(root, &inv.System)

	if h, err := c.call(ctx, http.MethodGet, "management/manaRequest.cgi?subfunc=sysinfo&sysHealth=1", nil, true); err == nil {
		if s := h.S("func/ownContent/sysHealth/status"); s != "" {
			inv.System.Health = storage.HealthWord(s)
		}
	}
	if v, err := c.call(ctx, http.MethodGet, "management/chartReq.cgi?chart_func=disk_usage&disk_select=all&include=all", nil, true); err == nil {
		parseVolumes(v, inv)
	} else {
		inv.Warnings = append(inv.Warnings, "Volumes: "+err.Error())
	}
	if d, err := c.call(ctx, http.MethodGet, "disk/qsmart.cgi?func=all_hd_data", nil, true); err == nil {
		parseDisks(d, inv)
	} else {
		inv.Warnings = append(inv.Warnings, "Disks: "+err.Error())
	}
	if f, err := c.call(ctx, http.MethodGet, "sys/sysRequest.cgi?subfunc=firm_update", nil, true); err == nil {
		inv.System.Update = f.S("func/ownContent/newVersion")
	}
	if raw, err := c.raw(ctx, http.MethodGet, "filemanager/utilRequest.cgi?func=get_tree&is_iso=0&node=share_root", nil, true); err == nil {
		mergeShares(raw, inv)
	} else {
		inv.Warnings = append(inv.Warnings, "Shared folders: "+err.Error())
	}

	if cfg, ok := snmpnas.FromCreds(t.Address, creds); ok {
		sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		si, err := snmpnas.Read(sctx, cfg)
		cancel()
		if err != nil {
			inv.Warnings = append(inv.Warnings, "SNMP (volume and RAID state): "+err.Error())
		} else {
			mergeSNMP(si, inv)
		}
	}
	inv.Finish()
	return res, nil
}

func parseSysinfo(root *storage.Node, s *storage.System) {
	r := root.Get("func/ownContent/root")
	s.Model = root.S("model/displayModelName")
	if s.Model == "" {
		s.Model = root.S("model/modelName")
	}
	ver := root.S("firmware/version")
	if b := root.S("firmware/build"); b != "" {
		ver += " build " + b
	}
	s.Firmware = ver
	s.OS = "QTS"
	if strings.HasPrefix(strings.ToLower(root.S("firmware/version")), "h") {
		s.OS = "QuTS hero"
	}
	if r == nil {
		return
	}
	s.Name = r.S("server_name")
	s.Serial = r.S("serial_number")
	s.TempC = atoi(r.S("sys_tempc"))
	s.CPUTempC = atoi(r.S("cpu_tempc"))
	if u := r.S("cpu_usage"); u != "" {
		s.CPUUsage = atof(u) / 100
	}
	// memory is in MB
	total, free := atof(r.S("total_memory")), atof(r.S("free_memory"))
	if total > 0 {
		s.MemBytes = int64(total * (1 << 20))
		s.MemUsed = int64((total - free) * (1 << 20))
	}
	s.UptimeS = int64(atoi(r.S("uptime_day")))*86400 + int64(atoi(r.S("uptime_hour")))*3600 +
		int64(atoi(r.S("uptime_min")))*60 + int64(atoi(r.S("uptime_sec")))
	for i := 1; i <= atoi(r.S("sysfan_count")); i++ {
		n := strconv.Itoa(i)
		if r.Get("sysfan"+n) == nil {
			continue
		}
		s.Fans = append(s.Fans, storage.Fan{Name: "Fan " + n, RPM: atoi(r.S("sysfan" + n)), OK: r.S("sysfan"+n+"_stat") != "-1"})
	}
	for i := 1; i <= atoi(r.S("nic_cnt")); i++ {
		n := strconv.Itoa(i)
		if r.Get("eth_status"+n) == nil {
			continue
		}
		name := r.S("dname" + n)
		if name == "" {
			name = "Adapter " + n
		}
		s.NICs = append(s.NICs, storage.NIC{Name: name, Up: r.S("eth_status"+n) == "1", SpeedMbps: atoi(r.S("eth_max_speed" + n)),
			IP: r.S("eth_ip" + n), MAC: r.S("eth_mac" + n)})
	}
}

func parseVolumes(root *storage.Node, inv *storage.Inventory) {
	labels := map[string]string{}
	for _, v := range root.Get("volumeList").All("volume") {
		id := v.S("volumeValue")
		label := v.S("volumeLabel")
		if label == "" {
			label = "Volume " + id
		}
		labels[id] = label
	}
	shares := map[string]int{}
	for _, u := range root.Get("volumeUseList").All("volumeUse") {
		id := u.S("volumeValue")
		label, ok := labels[id]
		if !ok {
			continue // system reserved
		}
		total, free := atoi64(u.S("total_size")), atoi64(u.S("free_size"))
		inv.Volumes = append(inv.Volumes, storage.Volume{ID: id, Name: label, Status: "", Health: storage.HealthUnknown, Total: total, Used: total - free})
		for _, f := range u.All("folder_element") {
			name := f.S("sharename")
			if name == "" {
				continue
			}
			shares[name] = len(inv.Shares)
			inv.Shares = append(inv.Shares, storage.Share{Name: name, Path: "/" + name, Volume: label, Used: atoi64(f.S("used_size")),
				Protocols: []string{"SMB"}})
		}
	}
}

func parseDisks(root *storage.Node, inv *storage.Inventory) {
	for _, d := range root.Get("Disk_Info").All("entry") {
		model := d.S("Model")
		if model == "" {
			continue // empty bay
		}
		no := d.S("HDNo")
		typ := "hdd"
		if d.S("hd_is_ssd") == "1" {
			typ = "ssd"
		}
		smart := d.S("Health")
		disk := storage.Disk{ID: no, Slot: "Disk " + no, Model: model, Serial: d.S("Serial"), Type: typ, Size: storage.ParseSize(d.S("Capacity")),
			TempC: atoi(d.S("Temperature/oC")), SMART: smart, Health: storage.HealthWord(smart)}
		inv.Disks = append(inv.Disks, disk)
	}
}

// mergeShares adds shares from File Station's share tree that the usage chart didn't list
// (empty shares, or ones on external drives).
func mergeShares(raw []byte, inv *storage.Inventory) {
	var tree []struct {
		Text string `json:"text"`
		ID   string `json:"id"`
		Cls  string `json:"cls"`
	}
	if json.Unmarshal(raw, &tree) != nil {
		return
	}
	have := map[string]bool{}
	for _, s := range inv.Shares {
		have[strings.ToLower(s.Name)] = true
	}
	for _, n := range tree {
		name := strings.TrimPrefix(n.ID, "/")
		if name == "" {
			name = n.Text
		}
		if name == "" || have[strings.ToLower(name)] {
			continue
		}
		have[strings.ToLower(name)] = true
		inv.Shares = append(inv.Shares, storage.Share{Name: name, Path: "/" + name, Protocols: []string{"SMB"}})
	}
}

// mergeSNMP fills in volume, disk and pool state from QNAP's NAS-MIB.
func mergeSNMP(si *storage.Inventory, inv *storage.Inventory) {
	for _, sv := range si.Volumes {
		matched := false
		for i := range inv.Volumes {
			v := &inv.Volumes[i]
			if strings.EqualFold(v.Name, sv.Name) || strings.Contains(strings.ToLower(sv.Name), strings.ToLower(v.Name)+",") ||
				strings.HasPrefix(strings.ToLower(sv.Name), strings.ToLower(v.Name)+" ") {
				v.Status, v.Health = sv.Status, sv.Health
				if v.FS == "" {
					v.FS = sv.FS
				}
				matched = true
			}
		}
		if !matched && len(inv.Volumes) == 0 {
			inv.Volumes = append(inv.Volumes, sv)
		}
	}
	if len(si.Pools) > 0 && len(inv.Pools) == 0 {
		inv.Pools = si.Pools
	}
	for _, sd := range si.Disks {
		for i := range inv.Disks {
			d := &inv.Disks[i]
			if d.ID == sd.ID || (sd.Serial != "" && d.Serial == sd.Serial) {
				if sd.Status != "" {
					d.Status = sd.Status
				}
				if sd.Health == storage.HealthCritical || (d.Health == storage.HealthUnknown && sd.Health != "") {
					d.Health = sd.Health
				}
			}
		}
	}
	if len(inv.Disks) == 0 {
		inv.Disks = si.Disks
	}
}

// ---- control ----

func (c *client) open(ctx context.Context, creds map[string]string) error { return c.login(ctx, creds) }

// Power implements storage.Controller. QTS restarts or shuts down a few seconds after answering.
func (Provider) Power(ctx context.Context, t storage.Target, creds map[string]string, action string) error {
	if action != "restart" && action != "shutdown" {
		return storage.ErrUnsupported
	}
	c, err := newClient(t)
	if err != nil {
		return err
	}
	if err := c.open(ctx, creds); err != nil {
		return err
	}
	root, err := c.call(ctx, http.MethodGet, "sys/sysRequest.cgi?subfunc=power_mgmt&count="+strconv.FormatInt(time.Now().Unix()%100000, 10)+"&apply="+action, nil, true)
	if err != nil {
		return err
	}
	if r := root.S("result"); r != "" && r != "0" && r != "1" && !strings.EqualFold(r, "ok") {
		return fmt.Errorf("qnap: the NAS refused to %s (result %s)", action, r)
	}
	return nil
}

// fileStatus maps File Station status codes to messages (File Station API v4.1).
var fileStatus = map[int]string{
	0: "failed", 2: "a file or folder with that name already exists", 3: "the session expired", 4: "permission denied",
	5: "the folder does not exist", 6: "the folder name is not allowed", 33: "a folder with that name already exists",
}

// CreateFolder implements storage.Controller with File Station's createdir.
func (Provider) CreateFolder(ctx context.Context, t storage.Target, creds map[string]string, share, path string) error {
	if err := storage.ValidFolder(path); err != nil {
		return err
	}
	c, err := newClient(t)
	if err != nil {
		return err
	}
	if err := c.open(ctx, creds); err != nil {
		return err
	}
	defer c.logout(context.WithoutCancel(ctx))
	parts := strings.Split(strings.Trim(path, "/"), "/")
	parent := "/" + share
	for _, p := range parts {
		q := url.Values{"func": {"createdir"}, "dest_folder": {p}, "dest_path": {parent}}
		raw, err := c.raw(ctx, http.MethodGet, "filemanager/utilRequest.cgi?"+q.Encode(), nil, true)
		if err != nil {
			return err
		}
		var out struct {
			Status int `json:"status"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return fmt.Errorf("qnap: createdir: unreadable answer")
		}
		last := p == parts[len(parts)-1]
		if out.Status != 1 && !(!last && (out.Status == 2 || out.Status == 33)) {
			msg := fileStatus[out.Status]
			if msg == "" {
				msg = "status " + strconv.Itoa(out.Status)
			}
			return fmt.Errorf("qnap: could not create %s/%s: %s", parent, p, msg)
		}
		parent += "/" + p
	}
	return nil
}

// CreateShare implements storage.Controller. QNAP's public API has no shared folder creation.
func (Provider) CreateShare(context.Context, storage.Target, map[string]string, storage.ShareSpec) error {
	return fmt.Errorf("%w: QNAP's API can't create shared folders; use Control Panel > Shared Folders", storage.ErrUnsupported)
}

// CreateSnapshot implements storage.Controller. QNAP's public API has no snapshot calls.
func (Provider) CreateSnapshot(context.Context, storage.Target, map[string]string, string, string) error {
	return fmt.Errorf("%w: QNAP's API has no snapshot calls; use Storage & Snapshots", storage.ErrUnsupported)
}

// DeleteSnapshot implements storage.Controller.
func (Provider) DeleteSnapshot(context.Context, storage.Target, map[string]string, string, string) error {
	return fmt.Errorf("%w: QNAP's API has no snapshot calls; use Storage & Snapshots", storage.ErrUnsupported)
}
