package vmware

import (
	"context"
	"crypto/tls"
	"errors"
	"net/url"
	"testing"

	"github.com/vmware/govmomi/simulator"

	hv "github.com/dertown/network-control-centre/internal/hypervisor"
)

func run(t *testing.T, model *simulator.Model, pass string) (*hv.Result, error) {
	t.Helper()
	if err := model.Create(); err != nil {
		t.Fatal(err)
	}
	model.Service.TLS = new(tls.Config)
	model.Service.Listen = &url.URL{User: url.UserPassword("ncc", "secret")}
	srv := model.Service.NewServer()
	t.Cleanup(func() { srv.Close(); model.Remove() })
	return Provider{}.Collect(context.Background(),
		hv.Target{Name: "vc", Kind: "vmware", Address: "https://" + srv.URL.Host, Options: map[string]string{}},
		map[string]string{"username": "ncc", "password": pass})
}

func check(t *testing.T, res *hv.Result, err error, hosts, vms int) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if res.OptionUpdates[OptFingerprint] == "" {
		t.Error("certificate was not pinned on first use")
	}
	inv := res.Inventory
	if len(inv.Hosts) != hosts || len(inv.VMs) != vms {
		t.Fatalf("got %d hosts, %d VMs; want %d, %d", len(inv.Hosts), len(inv.VMs), hosts, vms)
	}
	running := 0
	for _, v := range inv.VMs {
		if v.Name == "" || v.Host == "" || v.CPUs == 0 || v.MemBytes == 0 || v.State == hv.StateUnknown {
			t.Errorf("incomplete VM: %+v", v)
		}
		if v.State == hv.StateRunning {
			running++
		}
	}
	if running == 0 {
		t.Error("no running VMs")
	}
	for _, h := range inv.Hosts {
		if h.Name == "" || h.CPUs == 0 || h.MemBytes == 0 {
			t.Errorf("incomplete host: %+v", h)
		}
	}
	if inv.Version == "" {
		t.Error("no version")
	}
}

func TestVCenter(t *testing.T) {
	m := simulator.VPX()
	m.Machine = 3
	res, err := run(t, m, "secret")
	c := m.Count()
	check(t, res, err, c.Host, c.Machine)
}

func TestESXi(t *testing.T) {
	m := simulator.ESX()
	res, err := run(t, m, "secret")
	check(t, res, err, 1, m.Count().Machine)
}

func TestBadPassword(t *testing.T) {
	_, err := run(t, simulator.ESX(), "wrong")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("got %v", err)
	}
}
