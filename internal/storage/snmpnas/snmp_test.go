package snmpnas

import (
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"

	"github.com/dertown/network-control-centre/internal/storage"
)

type fake map[string]any

func (f fake) pdu(oid string) gosnmp.SnmpPDU {
	v := f[oid]
	if s, ok := v.(string); ok && !strings.HasPrefix(s, ".1.") {
		v = []byte(s)
	}
	return gosnmp.SnmpPDU{Name: "." + oid, Value: v}
}

func (f fake) Get(oids []string) (map[string]gosnmp.SnmpPDU, error) {
	out := map[string]gosnmp.SnmpPDU{}
	for _, o := range oids {
		if _, ok := f[o]; ok {
			out[o] = f.pdu(o)
		}
	}
	return out, nil
}

func (f fake) Walk(root string) ([]gosnmp.SnmpPDU, error) {
	var out []gosnmp.SnmpPDU
	for o := range f {
		if strings.HasPrefix(o, root+".") {
			out = append(out, f.pdu(o))
		}
	}
	return out, nil
}

func TestQNAP(t *testing.T) {
	f := fake{
		sysName: "nas", sysDescr: "Linux TS-464 5.10.60-qnap", sysUpTime: uint32(360000),
		qnapModel: "TS-464", qnapCPU: "7.0 %", qnapMemT: "7.6 GB", qnapMemF: "2.8 GB", qnapCPUT: "49 C/120 F", qnapSysT: "41 C/105 F",
		qnapDisks + ".2.1": "HDD1", qnapDisks + ".3.1": "38 C/100 F", qnapDisks + ".4.1": 0, qnapDisks + ".5.1": "WD40EFPX", qnapDisks + ".6.1": "3.64 TB", qnapDisks + ".7.1": "GOOD",
		qnapDisks + ".2.2": "HDD2", qnapDisks + ".3.2": "--", qnapDisks + ".4.2": -5, qnapDisks + ".5.2": "--", qnapDisks + ".6.2": "--", qnapDisks + ".7.2": "--",
		qnapDisks + ".2.3": "HDD3", qnapDisks + ".3.3": "40 C/104 F", qnapDisks + ".4.3": -9, qnapDisks + ".5.3": "ST4000", qnapDisks + ".6.3": "3.64 TB", qnapDisks + ".7.3": "Normal",
		qnapVols + ".2.1": "DataVol1, RAID 5, 4 disks", qnapVols + ".3.1": "EXT4", qnapVols + ".4.1": "5.34 TB", qnapVols + ".5.1": "1.00 TB", qnapVols + ".6.1": "Degraded",
		qnapFans + ".2.1": "System FAN 1", qnapFans + ".3.1": "1045 RPM",
	}
	inv, err := ReadSession(f)
	if err != nil {
		t.Fatal(err)
	}
	inv.Finish()
	if inv.System.Vendor != "QNAP" || inv.System.TempC != 41 || inv.System.CPUTempC != 49 || inv.System.UptimeS != 3600 || inv.System.MemUsed <= 0 {
		t.Fatalf("system %+v", inv.System)
	}
	if len(inv.Disks) != 2 || inv.Disks[1].Health != storage.HealthCritical || inv.Disks[0].TempC != 38 {
		t.Fatalf("disks %+v", inv.Disks)
	}
	if len(inv.Volumes) != 1 || inv.Volumes[0].Health != storage.HealthWarning || inv.Volumes[0].Used != storage.ParseSize("5.34 TB")-storage.ParseSize("1.00 TB") {
		t.Fatalf("volumes %+v", inv.Volumes)
	}
	if len(inv.System.Fans) != 1 || inv.System.Fans[0].RPM != 1045 {
		t.Fatalf("fans %+v", inv.System.Fans)
	}
}

func TestSynology(t *testing.T) {
	f := fake{
		sysName: "ds", synoModel: "DS920+", synoStatus: 1, synoTemp: 44, synoPower: 1, synoSerial: "2080", synoVer: "DSM 7.2", synoUpdate: 2, synoFanSys: 1,
		synoDisks + ".2.0": "Disk 1", synoDisks + ".3.0": "HAT5300", synoDisks + ".4.0": "SATA", synoDisks + ".5.0": 1, synoDisks + ".6.0": 36,
		synoDisks + ".2.1": "Disk 2", synoDisks + ".3.1": "HAT5300", synoDisks + ".4.1": "SATA", synoDisks + ".5.1": 5, synoDisks + ".6.1": 37,
		synoRAID + ".2.0": "Volume 1", synoRAID + ".3.0": 11, synoRAID + ".4.0": uint64(4 << 40), synoRAID + ".5.0": uint64(14 << 40),
	}
	inv, err := ReadSession(f)
	if err != nil {
		t.Fatal(err)
	}
	inv.Finish()
	if inv.System.Vendor != "Synology" || inv.System.Model != "DS920+" || inv.System.TempC != 44 {
		t.Fatalf("system %+v", inv.System)
	}
	if len(inv.Disks) != 2 || inv.Disks[1].Health != storage.HealthCritical || inv.Disks[1].Status != "Crashed" {
		t.Fatalf("disks %+v", inv.Disks)
	}
	if len(inv.Volumes) != 1 || inv.Volumes[0].Status != "Degraded" || inv.Volumes[0].Used != 10<<40 {
		t.Fatalf("volumes %+v", inv.Volumes)
	}
	if inv.System.Health != storage.HealthCritical {
		t.Fatalf("health %s", inv.System.Health)
	}
}

func TestHostResources(t *testing.T) {
	f := fake{
		sysName: "truenas", sysDescr: "TrueNAS-SCALE 24.04 Linux",
		hrStorage + ".2.1": "." + hrFixedDisk, hrStorage + ".3.1": "/mnt/tank", hrStorage + ".4.1": 4096, hrStorage + ".5.1": 1 << 30, hrStorage + ".6.1": 1 << 29,
		hrStorage + ".2.2": "." + hrFixedDisk, hrStorage + ".3.2": "/run", hrStorage + ".4.2": 4096, hrStorage + ".5.2": 1 << 20, hrStorage + ".6.2": 1,
		hrStorage + ".2.3": ".1.3.6.1.2.1.25.2.1.2", hrStorage + ".3.3": "Physical memory", hrStorage + ".4.3": 1024, hrStorage + ".5.3": 1 << 24, hrStorage + ".6.3": 1,
	}
	inv, err := ReadSession(f)
	if err != nil {
		t.Fatal(err)
	}
	if inv.System.Vendor != "TrueNAS" || len(inv.Volumes) != 1 || inv.Volumes[0].Name != "/mnt/tank" || inv.Volumes[0].Total != 4096<<30 {
		t.Fatalf("got %+v %+v", inv.System, inv.Volumes)
	}
}

func TestFromCreds(t *testing.T) {
	if _, ok := FromCreds("https://nas", map[string]string{"username": "x"}); ok {
		t.Fatal("no SNMP settings should be not ok")
	}
	c, ok := FromCreds("https://192.168.1.50:443", map[string]string{"snmp_community": "public"})
	if !ok || c.Host != "192.168.1.50" || c.Port != 161 {
		t.Fatalf("%+v", c)
	}
	c, ok = FromCreds("snmp://nas:1161", map[string]string{"snmp_user": "ncc", "snmp_auth_pass": "a"})
	if !ok || c.Host != "nas" || c.Port != 1161 || c.User != "ncc" {
		t.Fatalf("%+v", c)
	}
	if c, _ := FromCreds("10.0.0.5", map[string]string{"snmp_community": "x"}); c.Host != "10.0.0.5" {
		t.Fatalf("bare host: %+v", c)
	}
}
