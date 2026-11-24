package hyperv

import (
	"context"
	"strings"
	"testing"

	hv "github.com/dertown/network-control-centre/internal/hypervisor"
	"github.com/dertown/network-control-centre/internal/winps"
)

type fakeShell struct {
	ran *[]string
	out string
}

func (f fakeShell) Run(_ context.Context, s string) (string, error) { *f.ran = append(*f.ran, s); return f.out, nil }
func (fakeShell) Close() error                                     { return nil }

func TestHyperVCollectAndPower(t *testing.T) {
	var ran []string
	winps.Dial = func(context.Context, string, map[string]string, map[string]string) (winps.Shell, error) {
		return fakeShell{&ran, `{"host":"HV01","cpus":16,"mem":68719476736,"free":34359738368,"load":12.5,"up":86400,
			"ver":"Microsoft Windows Server 2022 Datacenter 10.0.20348","model":"Dell Inc. PowerEdge R650",
			"vms":[{"id":"6f1d3c1e-1111-2222-3333-444455556666","n":"dc02","s":"Running","c":2,"cpu":7,"mem":4294967296,"used":2147483648,
			"up":3600,"notes":"","ip":["10.0.0.12","fe80::1"],"disk":64424509440,"du":21474836480,"ic":"Up to date"},
			{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","n":"old","s":"Off","c":1,"cpu":0,"mem":1073741824,"used":0,"up":0,"ip":null,"disk":0,"du":0,"ic":""}]}`}, nil
	}
	tg := hv.Target{Name: "hv01", Kind: "hyperv", Address: "hv01"}
	res, err := Provider{}.Collect(context.Background(), tg, nil)
	if err != nil {
		t.Fatal(err)
	}
	inv := res.Inventory
	if len(inv.Hosts) != 1 || inv.Hosts[0].Name != "HV01" || inv.Hosts[0].MemUsed != 34359738368 || inv.Hosts[0].CPUUsage != 0.125 {
		t.Fatalf("host %+v", inv.Hosts)
	}
	if len(inv.VMs) != 2 || inv.VMs[0].State != hv.StateRunning || inv.VMs[1].State != hv.StateStopped {
		t.Fatalf("vms %+v", inv.VMs)
	}
	if ips := inv.VMs[0].IPs; len(ips) != 1 || ips[0] != "10.0.0.12" {
		t.Fatalf("link-local address kept: %v", ips)
	}
	ran = nil
	if err := (Provider{}).Power(context.Background(), tg, nil, inv.VMs[0].ID, hv.ActionShutdown); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ran[0], "Get-VM -Id '6f1d3c1e-1111-2222-3333-444455556666'") || !strings.Contains(ran[0], "Stop-VM -VM $vm -Force") {
		t.Fatalf("power script %q", ran[0])
	}
	if err := (Provider{}).Power(context.Background(), tg, nil, "hyperv/x'; Remove-Item C:\\", hv.ActionStart); err == nil {
		t.Fatal("a made-up VM id was accepted")
	}
}
