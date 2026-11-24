// Package snmpnas reads NAS health over SNMP. It understands QNAP's NAS-MIB
// (enterprise 24681), Synology's MIB (enterprise 6574) and, for anything else, the
// standard HOST-RESOURCES-MIB storage table. It is the "SNMP" storage provider (read
// only), and the QNAP provider uses it for the volume and RAID state QNAP's HTTP API
// does not report.
//
// SNMPv2c with a community or SNMPv3 (SHA/SHA-256 auth, AES/DES privacy) are supported.
package snmpnas

import (
	"context"
	"errors"
	"fmt"
	"github.com/dertown/network-control-centre/internal/catalog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/dertown/network-control-centre/internal/storage"
)

func init() {
	storage.Register(Provider{}, catalog.Vendor{
		Label: "Storage over SNMP", Groups: []string{catalog.GroupStorage}, Order: 50,
		Summary: "TrueNAS, Unraid, ASUSTOR and anything else that speaks SNMP.",
		Help: "For storage NCC has no API driver for (TrueNAS, Unraid, ASUSTOR…) or when you'd rather not give NCC an admin login. " +
			"QNAP's and Synology's own MIBs give disk temperatures, SMART and RAID state; other devices show their file systems. Read only.",
		NameDefault: "nas-snmp", AddressKind: catalog.AddressHost, AddressDefault: "192.168.1.50",
		Fields: catalog.SNMPFields("", ""),
	})
}

// Config is how to reach a device over SNMP.
type Config struct {
	Host      string
	Port      uint16
	Community string // v2c
	User      string // v3
	AuthProto string // SHA, SHA256, SHA512, MD5
	AuthPass  string
	PrivProto string // AES, AES256, DES, or "" for none
	PrivPass  string
}

// FromCreds builds a Config from a connection address and vault secret. ok is false when
// the secret has no SNMP community or user.
func FromCreds(address string, creds map[string]string) (Config, bool) {
	cfg := Config{Host: hostOf(address), Port: 161, Community: strings.TrimSpace(creds["snmp_community"]),
		User: strings.TrimSpace(creds["snmp_user"]), AuthProto: creds["snmp_auth_proto"], AuthPass: creds["snmp_auth_pass"],
		PrivProto: creds["snmp_priv_proto"], PrivPass: creds["snmp_priv_pass"]}
	if p, err := strconv.Atoi(creds["snmp_port"]); err == nil && p > 0 && p < 65536 {
		cfg.Port = uint16(p)
	}
	if u, err := url.Parse(address); err == nil && u.Scheme == "snmp" && u.Port() != "" {
		if p, err := strconv.Atoi(u.Port()); err == nil {
			cfg.Port = uint16(p)
		}
	}
	return cfg, cfg.Host != "" && (cfg.Community != "" || cfg.User != "")
}

func hostOf(address string) string {
	a := strings.TrimSpace(address)
	if strings.Contains(a, "://") {
		if u, err := url.Parse(a); err == nil {
			return u.Hostname()
		}
		return ""
	}
	if h, _, err := net.SplitHostPort(a); err == nil {
		return h
	}
	return a
}

// Session is what the readers need from an SNMP connection; tests fake it.
type Session interface {
	Get(oids []string) (map[string]gosnmp.SnmpPDU, error)
	Walk(root string) ([]gosnmp.SnmpPDU, error)
}

type live struct{ g *gosnmp.GoSNMP }

func (l live) Get(oids []string) (map[string]gosnmp.SnmpPDU, error) {
	out := map[string]gosnmp.SnmpPDU{}
	for i := 0; i < len(oids); i += 20 {
		j := min(i+20, len(oids))
		p, err := l.g.Get(oids[i:j])
		if err != nil {
			return nil, err
		}
		for _, v := range p.Variables {
			if v.Type == gosnmp.NoSuchObject || v.Type == gosnmp.NoSuchInstance || v.Type == gosnmp.Null {
				continue
			}
			out[strings.TrimPrefix(v.Name, ".")] = v
		}
	}
	return out, nil
}

func (l live) Walk(root string) ([]gosnmp.SnmpPDU, error) { return l.g.BulkWalkAll(root) }

// Dial opens an SNMP session.
func Dial(ctx context.Context, cfg Config) (Session, func(), error) {
	g := &gosnmp.GoSNMP{Target: cfg.Host, Port: cfg.Port, Timeout: 4 * time.Second, Retries: 1, Context: ctx, MaxRepetitions: 25,
		ExponentialTimeout: false}
	if cfg.User != "" {
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		usm := &gosnmp.UsmSecurityParameters{UserName: cfg.User}
		g.MsgFlags = gosnmp.NoAuthNoPriv
		if cfg.AuthPass != "" {
			g.MsgFlags = gosnmp.AuthNoPriv
			usm.AuthenticationPassphrase = cfg.AuthPass
			switch strings.ToUpper(cfg.AuthProto) {
			case "MD5":
				usm.AuthenticationProtocol = gosnmp.MD5
			case "SHA256", "SHA-256":
				usm.AuthenticationProtocol = gosnmp.SHA256
			case "SHA512", "SHA-512":
				usm.AuthenticationProtocol = gosnmp.SHA512
			default:
				usm.AuthenticationProtocol = gosnmp.SHA
			}
			if cfg.PrivPass != "" {
				g.MsgFlags = gosnmp.AuthPriv
				usm.PrivacyPassphrase = cfg.PrivPass
				switch strings.ToUpper(cfg.PrivProto) {
				case "DES":
					usm.PrivacyProtocol = gosnmp.DES
				case "AES256":
					usm.PrivacyProtocol = gosnmp.AES256
				default:
					usm.PrivacyProtocol = gosnmp.AES
				}
			}
		}
		g.SecurityParameters = usm
	} else {
		g.Version = gosnmp.Version2c
		g.Community = cfg.Community
	}
	if err := g.Connect(); err != nil {
		return nil, nil, fmt.Errorf("snmp: %w", err)
	}
	return live{g}, func() { _ = g.Conn.Close() }, nil
}

// Read reads one device.
func Read(ctx context.Context, cfg Config) (*storage.Inventory, error) {
	s, closer, err := Dial(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer closer()
	return ReadSession(s)
}

// OIDs.
const (
	sysDescr    = "1.3.6.1.2.1.1.1.0"
	sysUpTime   = "1.3.6.1.2.1.1.3.0"
	sysName     = "1.3.6.1.2.1.1.5.0"
	hrStorage   = "1.3.6.1.2.1.25.2.3.1"
	hrFixedDisk = "1.3.6.1.2.1.25.2.1.4"
	hrNetDisk   = "1.3.6.1.2.1.25.2.1.10"

	qnapSys    = "1.3.6.1.4.1.24681.1.2"
	qnapModel  = qnapSys + ".12.0"
	qnapHost   = qnapSys + ".13.0"
	qnapCPU    = qnapSys + ".1.0"
	qnapMemT   = qnapSys + ".2.0"
	qnapMemF   = qnapSys + ".3.0"
	qnapCPUT   = qnapSys + ".5.0"
	qnapSysT   = qnapSys + ".6.0"
	qnapDisks  = qnapSys + ".11.1"
	qnapFans   = qnapSys + ".15.1"
	qnapVols   = qnapSys + ".17.1"
	qnapSerial = "1.3.6.1.4.1.24681.1.4.1.1.1.1.1.1.0" // not on every model

	synoSys    = "1.3.6.1.4.1.6574.1"
	synoStatus = synoSys + ".1.0"
	synoTemp   = synoSys + ".2.0"
	synoPower  = synoSys + ".3.0"
	synoModel  = synoSys + ".5.1.0"
	synoSerial = synoSys + ".5.2.0"
	synoVer    = synoSys + ".5.3.0"
	synoUpdate = synoSys + ".5.4.0" // 1 available, 2 unavailable
	synoFanSys = synoSys + ".4.1.0"
	synoFanCPU = synoSys + ".4.2.0"
	synoDisks  = "1.3.6.1.4.1.6574.2.1.1"
	synoRAID   = "1.3.6.1.4.1.6574.3.1.1"
)

// ReadSession reads a device through an open session.
func ReadSession(s Session) (*storage.Inventory, error) {
	inv := &storage.Inventory{Kind: "snmp", TakenAt: time.Now().UTC()}
	inv.System.CPUUsage = -1
	base, err := s.Get([]string{sysDescr, sysUpTime, sysName, qnapModel, synoModel})
	if err != nil {
		return nil, err
	}
	if len(base) == 0 {
		return nil, errors.New("snmp: the device answered but returned nothing (check the community or user has read access)")
	}
	inv.System.Name = str(base[sysName])
	inv.System.OS = firstLine(str(base[sysDescr]))
	inv.System.UptimeS = int64(num(base[sysUpTime]) / 100)
	switch {
	case str(base[qnapModel]) != "":
		readQNAP(s, inv)
	case str(base[synoModel]) != "":
		readSynology(s, inv)
	default:
		inv.System.Vendor = vendorFromDescr(inv.System.OS)
	}
	if len(inv.Volumes) == 0 {
		readHostResources(s, inv)
	}
	return inv, nil
}

func readQNAP(s Session, inv *storage.Inventory) {
	v, _ := s.Get([]string{qnapModel, qnapHost, qnapCPU, qnapMemT, qnapMemF, qnapCPUT, qnapSysT, qnapSerial})
	sys := &inv.System
	sys.Vendor, sys.Model = "QNAP", str(v[qnapModel])
	if h := str(v[qnapHost]); h != "" {
		sys.Name = h
	}
	sys.Serial = str(v[qnapSerial])
	if c := str(v[qnapCPU]); c != "" {
		sys.CPUUsage = leadingFloat(c) / 100
	}
	if t := storage.ParseSize(str(v[qnapMemT])); t > 0 {
		sys.MemBytes = t
		sys.MemUsed = t - storage.ParseSize(str(v[qnapMemF]))
	}
	sys.CPUTempC = int(leadingFloat(str(v[qnapCPUT])))
	sys.TempC = int(leadingFloat(str(v[qnapSysT])))
	if strings.Contains(strings.ToLower(sys.OS), "quts") {
		sys.OS = "QuTS hero"
	}
	for idx, row := range table(s, qnapDisks) {
		model := strings.TrimSpace(str(row[5]))
		status := int(num(row[4]))
		if model == "" || model == "--" || status == -5 { // -5: no disk
			continue
		}
		smart := str(row[7])
		d := storage.Disk{ID: idx, Slot: firstNonEmpty(str(row[2]), "Disk "+idx), Model: model, Size: storage.ParseSize(str(row[6])),
			TempC: int(leadingFloat(str(row[3]))), SMART: smart, Status: qnapDiskStatus(status)}
		d.Health = storage.HealthWord(smart)
		if status < 0 && status != -5 {
			d.Health = storage.HealthCritical
		}
		inv.Disks = append(inv.Disks, d)
	}
	for idx, row := range table(s, qnapFans) {
		rpm := int(leadingFloat(str(row[3])))
		inv.System.Fans = append(inv.System.Fans, storage.Fan{Name: firstNonEmpty(str(row[2]), "Fan "+idx), RPM: rpm, OK: rpm > 0})
	}
	for idx, row := range table(s, qnapVols) {
		total, free := storage.ParseSize(str(row[4])), storage.ParseSize(str(row[5]))
		status := str(row[6])
		inv.Volumes = append(inv.Volumes, storage.Volume{ID: idx, Name: firstNonEmpty(str(row[2]), "Volume "+idx), FS: str(row[3]),
			Status: status, Health: storage.HealthWord(status), Total: total, Used: total - free})
	}
}

func qnapDiskStatus(s int) string {
	switch s {
	case 0:
		return "Ready"
	case -4:
		return "Unknown"
	case -6:
		return "Invalid"
	case -9:
		return "Read/write error"
	}
	if s < 0 {
		return "Error " + strconv.Itoa(s)
	}
	return ""
}

var synoDiskStatus = map[int]string{1: "Normal", 2: "Initialized", 3: "Not initialized", 4: "System partition failed", 5: "Crashed"}
var synoRAIDStatus = map[int]string{
	1: "Normal", 2: "Repairing", 3: "Migrating", 4: "Expanding", 5: "Deleting", 6: "Creating", 7: "RAID syncing",
	8: "RAID parity checking", 9: "RAID assembling", 10: "Canceling", 11: "Degraded", 12: "Crashed", 13: "Data scrubbing",
	14: "RAID deploying", 15: "RAID undeploying", 16: "RAID mount cache", 17: "RAID unmount cache", 18: "RAID expanding unfinished SHR",
	19: "RAID convert SHR to pool", 20: "RAID migrate SHR1 to SHR2", 21: "RAID unknown status",
}

func readSynology(s Session, inv *storage.Inventory) {
	v, _ := s.Get([]string{synoStatus, synoTemp, synoPower, synoModel, synoSerial, synoVer, synoUpdate, synoFanSys, synoFanCPU})
	sys := &inv.System
	sys.Vendor, sys.Model, sys.Serial, sys.Firmware = "Synology", str(v[synoModel]), str(v[synoSerial]), str(v[synoVer])
	sys.OS = "DSM"
	sys.TempC = int(num(v[synoTemp]))
	if num(v[synoStatus]) == 2 {
		sys.Health = storage.HealthCritical
	}
	if num(v[synoPower]) == 2 {
		inv.Alerts = append(inv.Alerts, storage.Alert{Level: storage.HealthCritical, Subject: "Power", Message: "A power supply has failed."})
	}
	if num(v[synoUpdate]) == 1 {
		sys.Update = "a DSM update"
	}
	for _, f := range []struct{ oid, name string }{{synoFanSys, "System fan"}, {synoFanCPU, "CPU fan"}} {
		if pdu, ok := v[f.oid]; ok {
			sys.Fans = append(sys.Fans, storage.Fan{Name: f.name, OK: num(pdu) == 1})
		}
	}
	for idx, row := range table(s, synoDisks) {
		st := int(num(row[5]))
		d := storage.Disk{ID: idx, Slot: firstNonEmpty(str(row[2]), "Disk "+idx), Model: strings.TrimSpace(str(row[3])),
			Type: strings.ToLower(str(row[4])), TempC: int(num(row[6])), Status: synoDiskStatus[st]}
		if strings.Contains(d.Type, "ssd") {
			d.Type = "ssd"
		} else if d.Type != "" {
			d.Type = "hdd"
		}
		switch st {
		case 1, 2:
			d.Health = storage.HealthGood
		case 3:
			d.Health = storage.HealthGood
		case 4, 5:
			d.Health = storage.HealthCritical
		}
		inv.Disks = append(inv.Disks, d)
	}
	for idx, row := range table(s, synoRAID) {
		st := int(num(row[3]))
		total, free := int64(num(row[5])), int64(num(row[4]))
		status := synoRAIDStatus[st]
		h := storage.HealthWord(status)
		if st == 1 {
			h = storage.HealthGood
		}
		name := firstNonEmpty(str(row[2]), "RAID "+idx)
		if strings.HasPrefix(strings.ToLower(name), "storage pool") || strings.HasPrefix(strings.ToLower(name), "volume") {
			inv.Pools = append(inv.Pools, storage.Pool{ID: idx, Name: name, Status: status, Health: h, Total: total, Used: total - free})
		}
		if strings.HasPrefix(strings.ToLower(name), "volume") || len(inv.Pools) == 0 {
			inv.Volumes = append(inv.Volumes, storage.Volume{ID: idx, Name: name, Status: status, Health: h, Total: total, Used: total - free})
		}
	}
}

// readHostResources lists fixed and network disks from HOST-RESOURCES-MIB. Pseudo file
// systems (/proc, /run, tmpfs...) and tiny ones are skipped.
func readHostResources(s Session, inv *storage.Inventory) {
	for idx, row := range table(s, hrStorage) {
		typ := strings.TrimPrefix(oidStr(row[2]), ".")
		if typ != hrFixedDisk && typ != hrNetDisk {
			continue
		}
		descr := str(row[3])
		unit, size, used := int64(num(row[4])), int64(num(row[5])), int64(num(row[6]))
		if unit <= 0 || size <= 0 || skipMount(descr) {
			continue
		}
		total := unit * size
		if total < 1<<30 {
			continue
		}
		inv.Volumes = append(inv.Volumes, storage.Volume{ID: idx, Name: descr, Status: "mounted", Health: storage.HealthGood, Total: total, Used: unit * used})
	}
}

func skipMount(d string) bool {
	for _, p := range []string{"/proc", "/sys", "/dev", "/run", "/boot", "/tmp", "/mnt/boot_config", "/mnt/HDA_ROOT", "/mnt/ext", "/share/CACHEDEV1_DATA/.", "/var", "/snap/"} {
		if strings.HasPrefix(d, p) {
			return true
		}
	}
	return strings.Contains(d, "tmpfs") || d == "Physical memory" || d == "Virtual memory" || d == "Swap space"
}

// table walks an SNMP table and groups values by row index, then column number.
func table(s Session, base string) map[string]map[int]gosnmp.SnmpPDU {
	pdus, err := s.Walk(base)
	if err != nil {
		return nil
	}
	out := map[string]map[int]gosnmp.SnmpPDU{}
	for _, p := range pdus {
		rest := strings.TrimPrefix(strings.TrimPrefix(p.Name, "."), base+".")
		col, idx, ok := strings.Cut(rest, ".")
		if !ok {
			continue
		}
		c, err := strconv.Atoi(col)
		if err != nil {
			continue
		}
		if out[idx] == nil {
			out[idx] = map[int]gosnmp.SnmpPDU{}
		}
		out[idx][c] = p
	}
	return out
}

func str(p gosnmp.SnmpPDU) string {
	switch v := p.Value.(type) {
	case []byte:
		return strings.TrimSpace(strings.TrimRight(string(v), "\x00"))
	case string:
		return strings.TrimSpace(v)
	case nil:
		return ""
	}
	return fmt.Sprint(p.Value)
}

func oidStr(p gosnmp.SnmpPDU) string {
	if s, ok := p.Value.(string); ok {
		return s
	}
	return str(p)
}

func num(p gosnmp.SnmpPDU) float64 {
	if p.Value == nil {
		return 0
	}
	if b, ok := p.Value.([]byte); ok {
		return leadingFloat(string(b))
	}
	if s, ok := p.Value.(string); ok {
		return leadingFloat(s)
	}
	bi := gosnmp.ToBigInt(p.Value)
	f, _ := bi.Float64()
	return f
}

func leadingFloat(s string) float64 {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) && (s[i] == '-' || s[i] == '.' || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	f, _ := strconv.ParseFloat(s[:i], 64)
	return f
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return strings.TrimSpace(s)
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if strings.TrimSpace(x) != "" {
			return strings.TrimSpace(x)
		}
	}
	return ""
}

func vendorFromDescr(d string) string {
	l := strings.ToLower(d)
	switch {
	case strings.Contains(l, "truenas"), strings.Contains(l, "freenas"):
		return "TrueNAS"
	case strings.Contains(l, "unraid"):
		return "Unraid"
	case strings.Contains(l, "windows"):
		return "Windows"
	case strings.Contains(l, "asustor"), strings.Contains(l, "adm"):
		return "ASUSTOR"
	case strings.Contains(l, "linux"):
		return "Linux"
	}
	return "SNMP device"
}

// Provider is the read-only "snmp" storage provider.
type Provider struct{}

// Kind implements storage.Provider.
func (Provider) Kind() string { return "snmp" }

// Collect implements storage.Provider.
func (Provider) Collect(ctx context.Context, t storage.Target, creds map[string]string) (*storage.Result, error) {
	cfg, ok := FromCreds(t.Address, creds)
	if !ok {
		return nil, errors.New("snmp: give the device address and an SNMP community (v2c) or SNMPv3 user")
	}
	inv, err := Read(ctx, cfg)
	if err != nil {
		return nil, err
	}
	inv.Target = t.Name
	if inv.System.Name == "" {
		inv.System.Name = t.Name
	}
	inv.Finish()
	return &storage.Result{Inventory: inv}, nil
}
