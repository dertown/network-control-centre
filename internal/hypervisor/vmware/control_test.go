package vmware

import (
	"context"
	"crypto/tls"
	"net/url"
	"testing"

	"github.com/vmware/govmomi/simulator"

	hv "github.com/dertown/network-control-centre/internal/hypervisor"
)

func TestControl(t *testing.T) {
	m := simulator.ESX()
	if err := m.Create(); err != nil {
		t.Fatal(err)
	}
	m.Service.TLS = new(tls.Config)
	m.Service.Listen = &url.URL{User: url.UserPassword("ncc", "secret")}
	srv := m.Service.NewServer()
	defer func() { srv.Close(); m.Remove() }()
	ctx := context.Background()
	tg := hv.Target{Name: "esx", Kind: "vmware", Address: "https://" + srv.URL.Host, Options: map[string]string{}}
	creds := map[string]string{"username": "ncc", "password": "secret"}
	p := Provider{}
	list := func() []hv.VM {
		res, err := p.Collect(ctx, tg, creds)
		if err != nil {
			t.Fatal(err)
		}
		return res.Inventory.VMs
	}
	vms := list()
	target := vms[0]
	if target.State != hv.StateRunning {
		t.Fatalf("simulator VM not running: %s", target.State)
	}
	if err := p.Delete(ctx, tg, creds, target.ID); err == nil {
		t.Fatal("deleted a running VM")
	}
	if err := p.Power(ctx, tg, creds, target.ID, hv.ActionStop); err != nil {
		t.Fatal(err)
	}
	name, cpus, mem, notes := "renamed", 4, 2048, "hello"
	if err := p.Configure(ctx, tg, creds, target.ID, hv.Settings{Name: &name, CPUs: &cpus, MemoryMB: &mem, Notes: &notes}); err != nil {
		t.Fatal(err)
	}
	var got hv.VM
	for _, v := range list() {
		if v.ID == target.ID {
			got = v
		}
	}
	if got.Name != "renamed" || got.CPUs != 4 || got.MemBytes != 2048<<20 || got.State != hv.StateStopped || got.Notes != "hello" {
		t.Fatalf("after stop+configure: %+v", got)
	}
	if err := p.Power(ctx, tg, creds, target.ID, hv.ActionStart); err != nil {
		t.Fatal(err)
	}
	if err := p.Power(ctx, tg, creds, target.ID, hv.ActionStop); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(ctx, tg, creds, target.ID); err != nil {
		t.Fatal(err)
	}
	if n := len(list()); n != len(vms)-1 {
		t.Fatalf("%d VMs after delete, want %d", n, len(vms)-1)
	}
}
