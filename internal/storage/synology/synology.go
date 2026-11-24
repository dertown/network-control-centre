// Package synology is the NCC storage provider for Synology NAS devices running DSM 7
// (DSM 6.2 works for most calls). It uses the DSM Web API (webapi/entry.cgi): system
// information and utilisation, storage pools, volumes and disks with SMART state and
// temperatures, shared folders, and Btrfs share snapshots.
//
// Monitoring works with any administrator account. Creating shares, taking and deleting
// snapshots, restarting and shutting down also need an administrator. Accounts with
// two-factor sign-in can't sign in through the API; make a separate account for NCC.
package synology

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
	"strconv"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/netutil"
	"github.com/dertown/network-control-centre/internal/storage"
)

func init() {
	storage.Register(Provider{}, catalog.Vendor{
		Label: "Synology", Groups: []string{catalog.GroupStorage}, Order: 20,
		Summary: "Synology DSM: pools, volumes, disks, shares and Btrfs snapshots.",
		Help: "Use the DSM address (HTTPS is port 5001). Make a DSM user for NCC in the administrators group without two-factor sign-in. " +
			"NCC reads pools, volumes, disks, shares and Btrfs snapshots, and can create shares and snapshots, and restart or shut down " +
			"the NAS when you ask.",
		NameDefault: "synology", AddressDefault: "https://192.168.1.60:5001",
		Fields: append(catalog.UserPassword("", nil), catalog.TLSField("pin")),
	})
}

// Provider implements storage.Provider and storage.Controller for Synology DSM.
type Provider struct{}

// Kind implements storage.Provider.
func (Provider) Kind() string { return "synology" }

// Option keys.
const (
	OptTLS         = "tls"
	OptFingerprint = "tls_fingerprint"
)

// ErrUnauthorized means DSM refused the login.
var ErrUnauthorized = errors.New("synology: login refused")

type client struct {
	base string // https://nas:5001/webapi/entry.cgi
	http *http.Client
	pin  *netutil.Pinner
	sid  string
}

func newClient(t storage.Target) (*client, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(t.Address), "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("synology: address must be a URL like https://192.168.1.30:5001, got %q", t.Address)
	}
	if u.Port() == "" {
		port := "5001"
		if u.Scheme == "http" {
			port = "5000"
		}
		u.Host = net.JoinHostPort(u.Hostname(), port)
	}
	mode := t.Options[OptTLS]
	if mode == "" {
		mode = "pin"
	}
	hc, pin := netutil.NewClient(mode, t.Options[OptFingerprint], 30*time.Second)
	u.Path = "/webapi/entry.cgi"
	return &client{base: u.String(), http: hc, pin: pin}, nil
}

// dsmErrors are the common DSM API error codes.
var dsmErrors = map[int]string{
	100: "unknown error", 101: "bad request", 102: "the API does not exist on this DSM", 103: "the method does not exist",
	104: "this DSM version does not support the call", 105: "the account lacks permission (it must be an administrator)",
	106: "session timed out", 107: "session interrupted by a duplicate login", 119: "session id not found",
	400: "the username or password is wrong", 401: "the account is disabled", 402: "permission denied", 403: "two-step verification is required; make an account for NCC without it",
	404: "two-step verification failed", 406: "two-step verification must be set up first", 407: "the IP address is blocked", 408: "the password has expired",
	3300: "a shared folder with that name already exists", 3301: "the shared folder name is not allowed", 3302: "the shared folder name is reserved",
	3309: "the volume does not exist", 3319: "the volume is not ready",
}

type apiError struct {
	api  string
	code int
}

func (e *apiError) Error() string {
	msg := dsmErrors[e.code]
	if msg == "" {
		msg = "error " + strconv.Itoa(e.code)
	}
	return fmt.Sprintf("synology: %s: %s", e.api, msg)
}

// call runs one Web API method and decodes "data" into out.
func (c *client) call(ctx context.Context, api string, version int, method string, params url.Values, out any) error {
	if params == nil {
		params = url.Values{}
	}
	params.Set("api", api)
	params.Set("version", strconv.Itoa(version))
	params.Set("method", method)
	if c.sid != "" {
		params.Set("_sid", c.sid)
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(r)
	if err != nil {
		return fmt.Errorf("synology: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("synology: %s: HTTP %d", api, resp.StatusCode)
	}
	var env struct {
		Success bool            `json:"success"`
		Data    json.RawMessage `json:"data"`
		Error   struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("synology: %s: unreadable answer", api)
	}
	if !env.Success {
		e := &apiError{api: api, code: env.Error.Code}
		if api == "SYNO.API.Auth" || e.code == 105 || e.code == 119 {
			return fmt.Errorf("%w: %s", ErrUnauthorized, e.Error())
		}
		return e
	}
	if out == nil || len(env.Data) == 0 {
		return nil
	}
	return json.Unmarshal(env.Data, out)
}

func (c *client) login(ctx context.Context, creds map[string]string) error {
	user, pass := strings.TrimSpace(creds["username"]), creds["password"]
	if user == "" || pass == "" {
		return errors.New("synology: give the DSM username and password")
	}
	var out struct {
		SID string `json:"sid"`
	}
	if err := c.call(ctx, "SYNO.API.Auth", 6, "login", url.Values{"account": {user}, "passwd": {pass}, "session": {"NCC"}, "format": {"sid"}}, &out); err != nil {
		return err
	}
	if out.SID == "" {
		return fmt.Errorf("%w: no session returned", ErrUnauthorized)
	}
	c.sid = out.SID
	return nil
}

func (c *client) logout(ctx context.Context) {
	if c.sid != "" {
		_ = c.call(ctx, "SYNO.API.Auth", 6, "logout", url.Values{"session": {"NCC"}}, nil)
	}
}

// flex reads a JSON number that DSM sometimes sends as a string.
type flex float64

func (f *flex) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		*f = 0
		return nil
	}
	*f = flex(v)
	return nil
}

type sysInfo struct {
	Model       string `json:"model"`
	Serial      string `json:"serial"`
	Firmware    string `json:"firmware_ver"`
	RAM         flex   `json:"ram_size"` // MB
	SysTemp     flex   `json:"sys_temp"`
	TempWarn    bool   `json:"temperature_warning"`
	UpTime      string `json:"up_time"` // "123:45:06"
	CPUFamily   string `json:"cpu_family"`
	CPUSeries   string `json:"cpu_series"`
	SysTempWarn bool   `json:"sys_tempwarn"`
}

type utilisation struct {
	CPU struct {
		User   flex `json:"user_load"`
		System flex `json:"system_load"`
		Other  flex `json:"other_load"`
	} `json:"cpu"`
	Memory struct {
		Total     flex `json:"total_real"` // KB
		Available flex `json:"avail_real"`
		Cached    flex `json:"cached"`
		Buffer    flex `json:"buffer"`
		RealUsage flex `json:"real_usage"` // %
		Size      flex `json:"memory_size"`
	} `json:"memory"`
}

type sizePair struct {
	Total flex `json:"total"`
	Used  flex `json:"used"`
}

type storageInfo struct {
	Disks []struct {
		ID          string `json:"id"`
		Name        string `json:"name"` // "Drive 1"
		LongName    string `json:"longName"`
		Model       string `json:"model"`
		Serial      string `json:"serial"`
		Vendor      string `json:"vendor"`
		SizeTotal   flex   `json:"size_total"`
		Temp        flex   `json:"temp"`
		Status      string `json:"status"`       // normal, crashed...
		SmartStatus string `json:"smart_status"` // normal, warning, failing...
		IsSSD       bool   `json:"isSsd"`
		DiskType    string `json:"diskType"`
		Container   struct {
			Str string `json:"str"`
		} `json:"container"`
		UsedBy string `json:"used_by"`
	} `json:"disks"`
	Pools []struct {
		ID       string   `json:"id"`
		NumID    flex     `json:"num_id"`
		Desc     string   `json:"desc"`
		Status   string   `json:"status"`
		RAIDType string   `json:"device_type"` // shr_without_disk_protect, raid_5...
		Size     sizePair `json:"size"`
		Disks    []string `json:"disks"`
	} `json:"storagePools"`
	Volumes []struct {
		ID       string   `json:"id"`
		NumID    flex     `json:"num_id"`
		Desc     string   `json:"desc"`
		VolPath  string   `json:"vol_path"`
		Status   string   `json:"status"`
		FSType   string   `json:"fs_type"`
		PoolPath string   `json:"pool_path"`
		Size     sizePair `json:"size"`
	} `json:"volumes"`
}

type shareList struct {
	Shares []struct {
		Name       string `json:"name"`
		VolPath    string `json:"vol_path"`
		Desc       string `json:"desc"`
		Hidden     bool   `json:"hidden"`
		Encryption flex   `json:"encryption"`
		Additional struct {
			QuotaUsed flex `json:"share_quota_used"` // MB
			Quota     flex `json:"share_quota"`      // MB
			Snapshot  bool `json:"is_support_snapshot"`
		} `json:"additional"`
		IsSupportSnapshot bool `json:"is_support_snapshot"`
	} `json:"shares"`
}

type snapshotList struct {
	Snapshots []struct {
		Time string `json:"time"` // GMT+01-2024.05.01-02.00.00
		Desc string `json:"desc"`
		Lock bool   `json:"lock"`
	} `json:"snapshots"`
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

	inv := &storage.Inventory{Target: t.Name, Kind: "synology", TakenAt: time.Now().UTC(), Capabilities: []string{
		storage.CapRestart, storage.CapShutdown, storage.CapShareCreate, storage.CapFolderCreate}}
	inv.System.Vendor, inv.System.OS, inv.System.CPUUsage = "Synology", "DSM", -1
	res.Inventory = inv

	var si sysInfo
	if err := c.call(ctx, "SYNO.Core.System", 1, "info", nil, &si); err != nil {
		return res, err
	}
	inv.System.Model, inv.System.Serial, inv.System.Firmware = si.Model, si.Serial, si.Firmware
	inv.System.TempC = int(si.SysTemp)
	inv.System.UptimeS = parseUptime(si.UpTime)
	inv.System.MemBytes = int64(si.RAM) << 20

	var name struct {
		Hostname   string `json:"server_name"`
		ServerName string `json:"hostname"`
	}
	if c.call(ctx, "SYNO.Core.System", 1, "info", url.Values{"type": {"network"}}, &name) == nil {
		inv.System.Name = firstOf(name.Hostname, name.ServerName)
	}
	var u utilisation
	if c.call(ctx, "SYNO.Core.System.Utilization", 1, "get", nil, &u) == nil {
		inv.System.CPUUsage = float64(u.CPU.User+u.CPU.System+u.CPU.Other) / 100
		if u.Memory.Total > 0 {
			inv.System.MemBytes = int64(u.Memory.Total) << 10
			inv.System.MemUsed = int64(float64(u.Memory.Total)*float64(u.Memory.RealUsage)/100) << 10
		}
	}
	var st storageInfo
	if err := c.call(ctx, "SYNO.Storage.CGI.Storage", 1, "load_info", nil, &st); err == nil {
		applyStorage(&st, inv)
	} else {
		inv.Warnings = append(inv.Warnings, "Storage: "+err.Error())
	}
	var sl shareList
	if err := c.call(ctx, "SYNO.Core.Share", 1, "list", url.Values{"additional": {`["vol_path","share_quota","share_quota_used","encryption","hidden","is_support_snapshot"]`}}, &sl); err == nil {
		vols := map[string]string{}
		for _, v := range inv.Volumes {
			vols[v.ID] = v.Name
		}
		snapable := false
		for _, s := range sl.Shares {
			sh := storage.Share{Name: s.Name, Path: s.VolPath + "/" + s.Name, Volume: firstOf(vols[s.VolPath], s.VolPath), Comment: s.Desc,
				Protocols: []string{"SMB"}, Used: int64(s.Additional.QuotaUsed) << 20, Hidden: s.Hidden, Encrypted: s.Encryption > 0}
			if s.Additional.Quota > 0 {
				sh.Total = int64(s.Additional.Quota) << 20
			}
			inv.Shares = append(inv.Shares, sh)
			if s.Additional.Snapshot || s.IsSupportSnapshot {
				snapable = true
				var snaps snapshotList
				if err := c.call(ctx, "SYNO.Core.Share.Snapshot", 1, "list", url.Values{"name": {strconv.Quote(s.Name)}, "additional": {`["desc","lock"]`}}, &snaps); err == nil {
					for _, sn := range snaps.Snapshots {
						inv.Snapshots = append(inv.Snapshots, storage.Snapshot{ID: sn.Time, Share: s.Name, Name: sn.Time, Created: parseSnapTime(sn.Time),
							Comment: sn.Desc, Locked: sn.Lock})
					}
				}
			}
		}
		if snapable {
			inv.Capabilities = append(inv.Capabilities, storage.CapSnapshotList, storage.CapSnapshotCreate, storage.CapSnapshotDelete)
		}
	} else {
		inv.Warnings = append(inv.Warnings, "Shared folders: "+err.Error())
	}
	var upd struct {
		Available bool   `json:"available"`
		Version   string `json:"version"`
	}
	if c.call(ctx, "SYNO.Core.Upgrade.Server", 1, "check", nil, &upd) == nil && upd.Available {
		inv.System.Update = firstOf(upd.Version, "a DSM update")
	}
	inv.Finish()
	return res, nil
}

func applyStorage(st *storageInfo, inv *storage.Inventory) {
	for _, p := range st.Pools {
		name := firstOf(p.Desc, fmt.Sprintf("Storage Pool %d", int(p.NumID)))
		inv.Pools = append(inv.Pools, storage.Pool{ID: p.ID, Name: name, RAID: raidName(p.RAIDType), Status: p.Status, Health: storage.HealthWord(p.Status),
			Total: int64(p.Size.Total), Used: int64(p.Size.Used), Disks: p.Disks})
	}
	poolName := map[string]string{}
	for _, p := range inv.Pools {
		poolName[p.ID] = p.Name
	}
	for _, v := range st.Volumes {
		name := firstOf(v.Desc, fmt.Sprintf("Volume %d", int(v.NumID)))
		pool := strings.TrimPrefix(v.PoolPath, "reuse_")
		inv.Volumes = append(inv.Volumes, storage.Volume{ID: v.VolPath, Name: name, Pool: firstOf(poolName[pool], poolName[v.PoolPath]), FS: v.FSType, Status: v.Status,
			Health: storage.HealthWord(v.Status), Total: int64(v.Size.Total), Used: int64(v.Size.Used)})
	}
	diskPool := map[string]string{}
	for _, p := range inv.Pools {
		for _, d := range p.Disks {
			diskPool[d] = p.Name
		}
	}
	for _, d := range st.Disks {
		typ := "hdd"
		if d.IsSSD || strings.EqualFold(d.DiskType, "SSD") {
			typ = "ssd"
		}
		h := storage.HealthWord(d.SmartStatus)
		if hs := storage.HealthWord(d.Status); hs == storage.HealthCritical || h == storage.HealthUnknown {
			h = hs
		}
		inv.Disks = append(inv.Disks, storage.Disk{ID: d.ID, Slot: firstOf(d.Name, d.LongName, d.ID), Model: strings.TrimSpace(d.Vendor + " " + d.Model),
			Serial: d.Serial, Type: typ, Size: int64(d.SizeTotal), TempC: int(d.Temp), Status: d.Status, SMART: d.SmartStatus, Health: h, Pool: diskPool[d.ID]})
	}
}

func raidName(t string) string {
	t = strings.ToLower(t)
	switch {
	case strings.HasPrefix(t, "shr_without"):
		return "SHR (no protection)"
	case strings.HasPrefix(t, "shr_2"), t == "shr2":
		return "SHR-2"
	case strings.HasPrefix(t, "shr"):
		return "SHR"
	case strings.HasPrefix(t, "raid_"):
		return "RAID " + strings.TrimPrefix(t, "raid_")
	case t == "basic":
		return "Basic"
	}
	return t
}

func parseUptime(s string) int64 {
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return 0
	}
	h, _ := strconv.Atoi(parts[0])
	m, _ := strconv.Atoi(parts[1])
	sec, _ := strconv.Atoi(parts[2])
	return int64(h*3600 + m*60 + sec)
}

// parseSnapTime reads DSM snapshot names such as "GMT+01-2024.05.01-02.00.00".
func parseSnapTime(s string) time.Time {
	if !strings.HasPrefix(s, "GMT") || len(s) < 26 {
		return time.Time{}
	}
	z := s[3:]
	if z == "" || (z[0] != '+' && z[0] != '-') {
		return time.Time{}
	}
	i := strings.Index(z[1:], "-")
	if i < 0 {
		return time.Time{}
	}
	zone, rest := z[:i+1], z[i+2:]
	off := 0
	if len(zone) >= 3 {
		h, _ := strconv.Atoi(zone[1:3])
		mm := 0
		if len(zone) >= 5 {
			mm, _ = strconv.Atoi(strings.TrimPrefix(zone[3:], ":"))
		}
		off = h*3600 + mm*60
		if zone[0] == '-' {
			off = -off
		}
	}
	t, err := time.ParseInLocation("2006.01.02-15.04.05", rest, time.FixedZone("", off))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func firstOf(s ...string) string {
	for _, x := range s {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}

// ---- control ----

func (Provider) session(ctx context.Context, t storage.Target, creds map[string]string) (*client, error) {
	c, err := newClient(t)
	if err != nil {
		return nil, err
	}
	return c, c.login(ctx, creds)
}

// Power implements storage.Controller.
func (p Provider) Power(ctx context.Context, t storage.Target, creds map[string]string, action string) error {
	method := map[string]string{"restart": "reboot", "shutdown": "shutdown"}[action]
	if method == "" {
		return storage.ErrUnsupported
	}
	c, err := p.session(ctx, t, creds)
	if err != nil {
		return err
	}
	return c.call(ctx, "SYNO.Core.System", 1, method, url.Values{"force": {"false"}, "local": {"true"}}, nil)
}

// CreateShare implements storage.Controller.
func (p Provider) CreateShare(ctx context.Context, t storage.Target, creds map[string]string, s storage.ShareSpec) error {
	if err := s.Validate(); err != nil {
		return err
	}
	c, err := p.session(ctx, t, creds)
	if err != nil {
		return err
	}
	defer c.logout(context.WithoutCancel(ctx))
	info, _ := json.Marshal(map[string]any{"name": s.Name, "vol_path": s.Volume, "desc": s.Comment, "hidden": false,
		"enable_recycle_bin": true, "recycle_bin_admin_only": true})
	return c.call(ctx, "SYNO.Core.Share", 1, "create", url.Values{"name": {strconv.Quote(s.Name)}, "shareinfo": {string(info)}}, nil)
}

// CreateFolder implements storage.Controller with File Station.
func (p Provider) CreateFolder(ctx context.Context, t storage.Target, creds map[string]string, share, path string) error {
	if err := storage.ValidFolder(path); err != nil {
		return err
	}
	c, err := p.session(ctx, t, creds)
	if err != nil {
		return err
	}
	defer c.logout(context.WithoutCancel(ctx))
	return c.call(ctx, "SYNO.FileStation.CreateFolder", 2, "create", url.Values{
		"folder_path": {strconv.Quote("/" + share)}, "name": {strconv.Quote(strings.Trim(path, "/"))}, "force_parent": {"true"}}, nil)
}

// CreateSnapshot implements storage.Controller (Btrfs volumes only).
func (p Provider) CreateSnapshot(ctx context.Context, t storage.Target, creds map[string]string, share, comment string) error {
	c, err := p.session(ctx, t, creds)
	if err != nil {
		return err
	}
	defer c.logout(context.WithoutCancel(ctx))
	info, _ := json.Marshal(map[string]any{"desc": comment, "lock": false})
	return c.call(ctx, "SYNO.Core.Share.Snapshot", 1, "create", url.Values{"name": {strconv.Quote(share)}, "snapinfo": {string(info)}}, nil)
}

// DeleteSnapshot implements storage.Controller.
func (p Provider) DeleteSnapshot(ctx context.Context, t storage.Target, creds map[string]string, share, id string) error {
	c, err := p.session(ctx, t, creds)
	if err != nil {
		return err
	}
	defer c.logout(context.WithoutCancel(ctx))
	ids, _ := json.Marshal([]string{id})
	return c.call(ctx, "SYNO.Core.Share.Snapshot", 1, "delete", url.Values{"name": {strconv.Quote(share)}, "snapshots": {string(ids)}}, nil)
}
