package snmpnet

import (
	"context"
	"strings"
	"testing"

	"github.com/dertown/network-control-centre/internal/drivers"
	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/storage/snmpnas"
	"github.com/gosnmp/gosnmp"
)

type fakeSession map[string]any // OID -> value

func (f fakeSession) Get(oids []string) (map[string]gosnmp.SnmpPDU, error) {
	out := map[string]gosnmp.SnmpPDU{}
	for _, o := range oids {
		if v, ok := f[o]; ok {
			out[o] = gosnmp.SnmpPDU{Name: o, Value: v}
		}
	}
	return out, nil
}

func (f fakeSession) Walk(root string) ([]gosnmp.SnmpPDU, error) {
	var out []gosnmp.SnmpPDU
	for o, v := range f {
		if strings.HasPrefix(o, root+".") {
			out = append(out, gosnmp.SnmpPDU{Name: "." + o, Value: v})
		}
	}
	return out, nil
}

func TestReadSwitch(t *testing.T) {
	sw := fakeSession{
		oidSysDescr:    []byte("Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E8\nTechnical Support"),
		oidSysObjectID: ".1.3.6.1.4.1.9.1.1208",
		oidSysUpTime:   uint32(8640000),
		oidSysName:     []byte("core-sw1"),
		oidLLDPLocSub:  4,
		oidLLDPLocCh:   []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		// two copper ports and a VLAN interface (type 53, ignored)
		oidIfTable + ".3.1": 6, oidIfTable + ".2.1": []byte("GigabitEthernet1/0/1"), oidIfTable + ".8.1": 1, oidIfTable + ".6.1": []byte{0, 0x11, 0x22, 0x33, 0x44, 0x01},
		oidIfTable + ".3.2": 6, oidIfTable + ".2.2": []byte("GigabitEthernet1/0/2"), oidIfTable + ".8.2": 1, oidIfTable + ".6.2": []byte{0, 0x11, 0x22, 0x33, 0x44, 0x02},
		oidIfTable + ".3.100": 53, oidIfTable + ".2.100": []byte("Vlan1"),
		oidIfXTable + ".1.1": []byte("Gi1/0/1"), oidIfXTable + ".15.1": 1000,
		oidIfXTable + ".1.2": []byte("Gi1/0/2"), oidIfXTable + ".15.2": 1000, oidIfXTable + ".18.2": []byte("uplink to gateway"),
		// an access point on port 2 seen over LLDP
		oidLLDPRem + ".4.0.2.1": 4, oidLLDPRem + ".5.0.2.1": []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01},
		oidLLDPRem + ".6.0.2.1": 5, oidLLDPRem + ".7.0.2.1": []byte("eth0"),
		oidLLDPRem + ".9.0.2.1": []byte("ap-lobby"), oidLLDPRem + ".10.0.2.1": []byte("Wireless Access Point"),
		// MAC table: a printer on port 1 (VLAN 10), the AP itself behind port 2
		oidBasePortIf + ".1": 1, oidBasePortIf + ".2": 2,
		oidQFdbPort + ".10.0.21.93.1.2.3": 1,
		oidQFdbPort + ".1.170.187.204.0.0.1": 2,
		oidARP + ".100.192.168.10.20": []byte{0, 0x15, 0x5d, 1, 2, 3},
	}
	dial = func(context.Context, snmpnas.Config) (snmpnas.Session, func(), error) { return sw, func() {}, nil }
	tg := drivers.Target{Name: "core", Kind: "snmpnet", Address: "10.0.0.2", Options: map[string]string{OptRole: "switch", OptVendor: "snmp-cisco-catalyst"}}
	res, err := Driver{}.Collect(context.Background(), tg, map[string]string{"snmp_community": "x"})
	if err != nil {
		t.Fatal(err)
	}
	s := res.Snapshot
	if len(s.Devices) != 2 {
		t.Fatalf("devices %+v", s.Devices)
	}
	d := s.Devices[0]
	if d.ID != "00:11:22:33:44:55" || d.Name != "core-sw1" || d.Make != "Cisco" || d.Kind != inventory.KindSwitch || d.Uptime != 86400 || len(d.Ports) != 2 {
		t.Fatalf("switch %+v", d)
	}
	if !strings.HasPrefix(d.Model, "Cisco IOS Software, C2960X") || strings.Contains(d.Model, "Technical") {
		t.Fatalf("model %q", d.Model)
	}
	if !d.Ports[1].Infra || d.Ports[0].Infra || d.Ports[1].Profile != "uplink to gateway" {
		t.Fatalf("ports %+v", d.Ports)
	}
	ap := s.Devices[1]
	if ap.ID != "aa:bb:cc:00:00:01" || ap.Kind != inventory.KindAP || ap.Discovery != inventory.SourceLLDP {
		t.Fatalf("ap %+v", ap)
	}
	if len(s.Links) != 1 || s.Links[0].APort != "Gi1/0/2" || s.Links[0].BPort != "eth0" || s.Links[0].SpeedMbps != 1000 {
		t.Fatalf("links %+v", s.Links)
	}
	if len(s.Clients) != 1 || s.Clients[0].MAC != "00:15:5d:01:02:03" || s.Clients[0].IP != "192.168.10.20" || s.Clients[0].SwitchPort != 1 || s.Clients[0].VLAN != 10 {
		t.Fatalf("clients %+v", s.Clients)
	}
}

func TestMakerFromOID(t *testing.T) {
	if got := makerFromOID(".1.3.6.1.4.1.2636.1.1.1.2.21"); got != "Juniper" {
		t.Fatal(got)
	}
	if got := makerFromOID("1.3.6.1.2.1.1"); got != "" {
		t.Fatal(got)
	}
}
