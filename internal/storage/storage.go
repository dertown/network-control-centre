// Package storage defines the network storage interface (QNAP, Synology, SNMP, SMB and NFS
// servers) and the inventory NCC collects from them: system health, pools, volumes, disks
// with SMART and temperatures, shares, snapshots and alerts.
package storage

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Health values, normalised across vendors.
const (
	HealthGood     = "good"
	HealthWarning  = "warning"
	HealthCritical = "critical"
	HealthUnknown  = "unknown"
)

// System is the storage device itself.
type System struct {
	Name     string  `json:"name"`
	Vendor   string  `json:"vendor"` // QNAP, Synology, Windows / Samba, ...
	Model    string  `json:"model,omitempty"`
	Serial   string  `json:"serial,omitempty"`
	Firmware string  `json:"firmware,omitempty"`
	OS       string  `json:"os,omitempty"` // QTS, QuTS hero, DSM, ...
	Health   string  `json:"health"`
	UptimeS  int64   `json:"uptime_s,omitempty"`
	CPUUsage float64 `json:"cpu_usage"` // 0..1, -1 when unknown
	MemBytes int64   `json:"mem_bytes,omitempty"`
	MemUsed  int64   `json:"mem_used,omitempty"`
	TempC    int     `json:"temp_c,omitempty"` // system temperature
	CPUTempC int     `json:"cpu_temp_c,omitempty"`
	Fans     []Fan   `json:"fans,omitempty"`
	NICs     []NIC   `json:"nics,omitempty"`
	Update   string  `json:"update,omitempty"` // newer firmware on offer
}

// Fan is one system fan.
type Fan struct {
	Name string `json:"name"`
	RPM  int    `json:"rpm"`
	OK   bool   `json:"ok"`
}

// NIC is one network port of the device.
type NIC struct {
	Name      string `json:"name"`
	Up        bool   `json:"up"`
	SpeedMbps int    `json:"speed_mbps,omitempty"`
	IP        string `json:"ip,omitempty"`
	MAC       string `json:"mac,omitempty"`
}

// Pool is a storage pool or RAID group.
type Pool struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	RAID   string   `json:"raid,omitempty"` // "RAID 5", "SHR", ...
	Status string   `json:"status"`         // vendor's word: Ready, normal, degraded...
	Health string   `json:"health"`
	Total  int64    `json:"total"`
	Used   int64    `json:"used"`
	Disks  []string `json:"disks,omitempty"` // disk ids
}

// Volume is a volume (or a SMB share / NFS export on plain file servers) with a capacity.
type Volume struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Pool   string `json:"pool,omitempty"`
	FS     string `json:"fs,omitempty"`
	Status string `json:"status"`
	Health string `json:"health"`
	Total  int64  `json:"total"`
	Used   int64  `json:"used"`
}

// Disk is one physical drive.
type Disk struct {
	ID       string `json:"id"`
	Slot     string `json:"slot"` // "Disk 1", "Drive 3"
	Model    string `json:"model,omitempty"`
	Serial   string `json:"serial,omitempty"`
	Type     string `json:"type,omitempty"` // hdd | ssd
	Size     int64  `json:"size,omitempty"`
	TempC    int    `json:"temp_c,omitempty"`
	Status   string `json:"status,omitempty"` // vendor's word
	SMART    string `json:"smart,omitempty"`  // vendor's SMART summary, e.g. GOOD, normal
	Health   string `json:"health"`
	Pool     string `json:"pool,omitempty"`
	PowerOnH int    `json:"power_on_hours,omitempty"`
}

// Share is a shared folder (SMB, NFS, AFP...).
type Share struct {
	Name      string   `json:"name"`
	Path      string   `json:"path,omitempty"`   // volume path or export path
	Volume    string   `json:"volume,omitempty"` // volume name
	Protocols []string `json:"protocols,omitempty"`
	Comment   string   `json:"comment,omitempty"`
	Used      int64    `json:"used,omitempty"`
	Total     int64    `json:"total,omitempty"` // quota or the file system size, when known
	Free      int64    `json:"free,omitempty"`
	Clients   []string `json:"clients,omitempty"` // NFS: who may mount it
	Snapshots int      `json:"snapshots,omitempty"`
	Hidden    bool     `json:"hidden,omitempty"`
	Encrypted bool     `json:"encrypted,omitempty"`
}

// Snapshot is a point-in-time copy of a share or volume.
type Snapshot struct {
	ID      string    `json:"id"`    // vendor id, used to delete it
	Share   string    `json:"share"` // share or volume it belongs to
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Comment string    `json:"comment,omitempty"`
	Locked  bool      `json:"locked,omitempty"` // kept by retention, can't be deleted
	Size    int64     `json:"size,omitempty"`
}

// Alert is something about the device that needs attention.
type Alert struct {
	Level   string `json:"level"` // warning | critical
	Subject string `json:"subject"`
	Message string `json:"message"`
}

// Capabilities a provider offers on a connection.
const (
	CapRestart        = "restart"
	CapShutdown       = "shutdown"
	CapShareCreate    = "share.create"
	CapFolderCreate   = "folder.create"
	CapSnapshotList   = "snapshot.list"
	CapSnapshotCreate = "snapshot.create"
	CapSnapshotDelete = "snapshot.delete"
)

// Inventory is what one collection from one storage device returns.
type Inventory struct {
	Target       string     `json:"target"`
	Kind         string     `json:"kind"`
	TakenAt      time.Time  `json:"taken_at"`
	System       System     `json:"system"`
	Pools        []Pool     `json:"pools"`
	Volumes      []Volume   `json:"volumes"`
	Disks        []Disk     `json:"disks"`
	Shares       []Share    `json:"shares"`
	Snapshots    []Snapshot `json:"snapshots"`
	Alerts       []Alert    `json:"alerts"`
	Capabilities []string   `json:"capabilities"`
	Warnings     []string   `json:"warnings,omitempty"` // parts that could not be read
}

// Target is a configured storage connection.
type Target struct {
	ID      int64
	Name    string
	Kind    string
	Address string
	Options map[string]string
}

// Result is a collection plus option values to save back, e.g. a pinned certificate.
type Result struct {
	Inventory     *Inventory
	OptionUpdates map[string]string
}

// Provider talks to one kind of storage device.
type Provider interface {
	Kind() string
	Collect(ctx context.Context, t Target, creds map[string]string) (*Result, error)
}

// ShareSpec describes a new shared folder.
type ShareSpec struct {
	Name    string `json:"name"`
	Volume  string `json:"volume"` // volume id from the inventory
	Comment string `json:"comment,omitempty"`
}

var shareNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)

// Validate checks the share name is safe on every vendor.
func (s ShareSpec) Validate() error {
	if !shareNameRe.MatchString(s.Name) || strings.HasSuffix(s.Name, ".") || strings.HasSuffix(s.Name, " ") {
		return fmt.Errorf("share names use letters, digits, space, dot, dash and underscore (1 to 64), and can't end in a dot or space")
	}
	if s.Volume == "" {
		return fmt.Errorf("choose a volume for the share")
	}
	if len(s.Comment) > 256 {
		return fmt.Errorf("the description is limited to 256 characters")
	}
	return nil
}

// ValidFolder checks a new folder path inside a share: "a" or "a/b", no "..".
func ValidFolder(p string) error {
	p = strings.Trim(p, "/")
	if p == "" || len(p) > 255 {
		return fmt.Errorf("give a folder name")
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, `\:*?"<>|`) {
			return fmt.Errorf("folder names can't be empty, \".\" or \"..\", or use \\ : * ? \" < > |")
		}
	}
	return nil
}

// Controller is implemented by providers that can change something. Each method only runs
// when the inventory lists the matching capability.
type Controller interface {
	// Power restarts ("restart") or shuts down ("shutdown") the whole device.
	Power(ctx context.Context, t Target, creds map[string]string, action string) error
	CreateShare(ctx context.Context, t Target, creds map[string]string, s ShareSpec) error
	CreateFolder(ctx context.Context, t Target, creds map[string]string, share, path string) error
	CreateSnapshot(ctx context.Context, t Target, creds map[string]string, share, comment string) error
	DeleteSnapshot(ctx context.Context, t Target, creds map[string]string, share, id string) error
}

// ErrUnsupported is returned by controllers for actions a device can't do.
var ErrUnsupported = fmt.Errorf("this storage device does not support that action")

var (
	mu        sync.RWMutex
	providers = map[string]Provider{}
)

// Register adds a provider. Providers call it from init.
func Register(p Provider) {
	mu.Lock()
	defer mu.Unlock()
	providers[p.Kind()] = p
}

// Get returns a registered provider.
func Get(kind string) (Provider, error) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := providers[kind]
	if !ok {
		return nil, fmt.Errorf("no storage provider %q", kind)
	}
	return p, nil
}

// Kinds lists registered providers.
func Kinds() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(providers))
	for k := range providers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Has reports whether the inventory offers a capability.
func (inv *Inventory) Has(c string) bool {
	for _, x := range inv.Capabilities {
		if x == c {
			return true
		}
	}
	return false
}

// Thresholds for derived alerts.
const (
	DiskWarnC   = 50
	DiskCritC   = 60
	SysWarnC    = 60
	SysCritC    = 75
	CPUWarnC    = 80
	FullWarn    = 0.85
	FullCrit    = 0.95
	defaultName = "storage"
)

// Finish sorts the inventory, fills in health and derives alerts from what was read.
// Providers call it at the end of Collect.
func (inv *Inventory) Finish() {
	sort.SliceStable(inv.Disks, func(i, j int) bool { return natLess(inv.Disks[i].Slot, inv.Disks[j].Slot) })
	sort.SliceStable(inv.Volumes, func(i, j int) bool { return natLess(inv.Volumes[i].Name, inv.Volumes[j].Name) })
	sort.SliceStable(inv.Pools, func(i, j int) bool { return natLess(inv.Pools[i].Name, inv.Pools[j].Name) })
	sort.SliceStable(inv.Shares, func(i, j int) bool { return strings.ToLower(inv.Shares[i].Name) < strings.ToLower(inv.Shares[j].Name) })
	sort.SliceStable(inv.Snapshots, func(i, j int) bool { return inv.Snapshots[i].Created.After(inv.Snapshots[j].Created) })
	if inv.Pools == nil {
		inv.Pools = []Pool{}
	}
	if inv.Volumes == nil {
		inv.Volumes = []Volume{}
	}
	if inv.Disks == nil {
		inv.Disks = []Disk{}
	}
	if inv.Shares == nil {
		inv.Shares = []Share{}
	}
	if inv.Snapshots == nil {
		inv.Snapshots = []Snapshot{}
	}
	if inv.Capabilities == nil {
		inv.Capabilities = []string{}
	}
	snaps := map[string]int{}
	for _, s := range inv.Snapshots {
		snaps[s.Share]++
	}
	for i := range inv.Shares {
		if n := snaps[inv.Shares[i].Name]; n > 0 {
			inv.Shares[i].Snapshots = n
		}
	}

	add := func(level, subject, msg string) {
		for _, a := range inv.Alerts {
			if a.Subject == subject && a.Message == msg {
				return
			}
		}
		inv.Alerts = append(inv.Alerts, Alert{Level: level, Subject: subject, Message: msg})
	}
	for i := range inv.Disks {
		d := &inv.Disks[i]
		if d.Health == "" {
			d.Health = HealthUnknown
		}
		switch {
		case d.Health == HealthCritical:
			add(HealthCritical, d.Slot, fmt.Sprintf("SMART status is %s. Back up and replace this disk soon.", first(d.SMART, d.Status, "bad")))
		case d.Health == HealthWarning:
			add(HealthWarning, d.Slot, fmt.Sprintf("SMART status is %s. Check the disk's SMART details on the NAS.", first(d.SMART, d.Status, "warning")))
		}
		limWarn, limCrit := DiskWarnC, DiskCritC
		if d.Type == "ssd" {
			limWarn, limCrit = 65, 75
		}
		switch {
		case d.TempC >= limCrit:
			add(HealthCritical, d.Slot, fmt.Sprintf("Disk is at %d °C.", d.TempC))
			d.Health = worse(d.Health, HealthWarning)
		case d.TempC >= limWarn:
			add(HealthWarning, d.Slot, fmt.Sprintf("Disk is running warm at %d °C.", d.TempC))
		}
	}
	for i := range inv.Pools {
		p := &inv.Pools[i]
		if p.Health == "" {
			p.Health = HealthUnknown
		}
		if p.Health != HealthGood && p.Health != HealthUnknown {
			add(p.Health, p.Name, fmt.Sprintf("Storage pool is %s.", strings.ToLower(first(p.Status, p.Health))))
		}
	}
	for i := range inv.Volumes {
		v := &inv.Volumes[i]
		if v.Health == "" {
			v.Health = HealthUnknown
		}
		if v.Health != HealthGood && v.Health != HealthUnknown {
			add(v.Health, v.Name, fmt.Sprintf("Volume is %s.", strings.ToLower(first(v.Status, v.Health))))
		}
		if v.Total > 0 {
			f := float64(v.Used) / float64(v.Total)
			switch {
			case f >= FullCrit:
				add(HealthCritical, v.Name, fmt.Sprintf("Volume is %d%% full.", int(f*100)))
			case f >= FullWarn:
				add(HealthWarning, v.Name, fmt.Sprintf("Volume is %d%% full.", int(f*100)))
			}
		}
	}
	s := &inv.System
	switch {
	case s.TempC >= SysCritC:
		add(HealthCritical, "System", fmt.Sprintf("System temperature is %d °C.", s.TempC))
	case s.TempC >= SysWarnC:
		add(HealthWarning, "System", fmt.Sprintf("System temperature is %d °C.", s.TempC))
	}
	if s.CPUTempC >= CPUWarnC {
		add(HealthWarning, "System", fmt.Sprintf("CPU temperature is %d °C.", s.CPUTempC))
	}
	for _, f := range s.Fans {
		if !f.OK {
			add(HealthCritical, f.Name, "Fan has stopped or reports a fault.")
		}
	}
	if s.Update != "" {
		add(HealthWarning, "Firmware", "Firmware "+s.Update+" is available.")
	}
	// overall health is the worst of everything
	h := s.Health
	if h == "" {
		h = HealthGood
	}
	for _, a := range inv.Alerts {
		h = worse(h, a.Level)
	}
	s.Health = h
	sort.SliceStable(inv.Alerts, func(i, j int) bool { return rank(inv.Alerts[i].Level) > rank(inv.Alerts[j].Level) })
	if inv.Alerts == nil {
		inv.Alerts = []Alert{}
	}
}

func rank(h string) int {
	switch h {
	case HealthCritical:
		return 3
	case HealthWarning:
		return 2
	case HealthUnknown:
		return 1
	}
	return 0
}

func worse(a, b string) string {
	if rank(b) > rank(a) && b != HealthUnknown {
		return b
	}
	return a
}

func first(s ...string) string {
	for _, x := range s {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}

// natLess orders "Disk 2" before "Disk 10".
func natLess(a, b string) bool {
	ra, rb := []rune(strings.ToLower(a)), []rune(strings.ToLower(b))
	i, j := 0, 0
	for i < len(ra) && j < len(rb) {
		if isDigit(ra[i]) && isDigit(rb[j]) {
			si := i
			for i < len(ra) && isDigit(ra[i]) {
				i++
			}
			sj := j
			for j < len(rb) && isDigit(rb[j]) {
				j++
			}
			na, nb := strings.TrimLeft(string(ra[si:i]), "0"), strings.TrimLeft(string(rb[sj:j]), "0")
			if len(na) != len(nb) {
				return len(na) < len(nb)
			}
			if na != nb {
				return na < nb
			}
			continue
		}
		if ra[i] != rb[j] {
			return ra[i] < rb[j]
		}
		i++
		j++
	}
	return len(ra)-i < len(rb)-j
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

// HealthWord maps a vendor status word to a health value.
func HealthWord(s string) string {
	w := strings.ToLower(strings.TrimSpace(s))
	switch {
	case w == "":
		return HealthUnknown
	case strings.Contains(w, "crash"), strings.Contains(w, "fail"), strings.Contains(w, "abnormal"), strings.Contains(w, "bad"),
		strings.Contains(w, "error"), strings.Contains(w, "not active"), strings.Contains(w, "removed"), w == "critical", w == "unmounted":
		return HealthCritical
	case strings.Contains(w, "degrad"), strings.Contains(w, "warn"), strings.Contains(w, "rebuild"), strings.Contains(w, "sync"),
		strings.Contains(w, "repair"), strings.Contains(w, "check"), strings.Contains(w, "migrat"), strings.Contains(w, "expand"):
		return HealthWarning
	case w == "good", w == "ready", w == "normal", w == "ok", w == "healthy", w == "online", w == "active", strings.HasPrefix(w, "initialized"):
		return HealthGood
	}
	return HealthUnknown
}

// ParseSize reads "3.58 TB", "931.51 GB", "1,000 MB" or a plain byte count. Units are binary
// (1 KB = 1024 bytes), as NAS firmware reports them.
func ParseSize(s string) int64 {
	s = strings.TrimSpace(strings.ReplaceAll(s, ",", ""))
	if s == "" {
		return 0
	}
	i := 0
	for i < len(s) && (isDigit(rune(s[i])) || s[i] == '.') {
		i++
	}
	var f float64
	if _, err := fmt.Sscanf(s[:i], "%g", &f); err != nil {
		return 0
	}
	unit := strings.ToUpper(strings.TrimSpace(s[i:]))
	unit = strings.TrimSuffix(strings.TrimSuffix(unit, "YTES"), "B")
	unit = strings.TrimSuffix(unit, "I")
	mult := map[string]float64{"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40, "P": 1 << 50}[unit]
	if mult == 0 {
		mult = 1
	}
	return int64(f * mult)
}

// Name returns a display name for the device.
func (inv *Inventory) Name() string {
	return first(inv.System.Name, inv.Target, defaultName)
}
