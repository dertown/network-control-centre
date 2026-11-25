package proxmox

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	hv "github.com/dertown/network-control-centre/internal/hypervisor"
	"github.com/dertown/network-control-centre/internal/mocklab"
)

func collect(t *testing.T, creds map[string]string) (*hv.Result, error) {
	t.Helper()
	srv := httptest.NewTLSServer(mocklab.Proxmox("secret", "pw"))
	t.Cleanup(srv.Close)
	return Provider{}.Collect(context.Background(), hv.Target{Name: "pve", Kind: "proxmox", Address: srv.URL, Options: map[string]string{}}, creds)
}

func TestCollectWithToken(t *testing.T) {
	res, err := collect(t, map[string]string{"token_id": "ncc@pve!monitor", "token_secret": "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if res.OptionUpdates[OptFingerprint] == "" {
		t.Error("certificate was not pinned on first use")
	}
	inv := res.Inventory
	if len(inv.Hosts) != 2 || inv.Version != "Proxmox VE 8.2.4" {
		t.Fatalf("hosts %+v version %q", inv.Hosts, inv.Version)
	}
	if len(inv.VMs) != 7 {
		t.Fatalf("got %d VMs", len(inv.VMs))
	}
	by := map[string]hv.VM{}
	for _, v := range inv.VMs {
		by[v.Name] = v
	}
	ncc := by["ncc"]
	if ncc.State != hv.StateRunning || ncc.Host != "pve1" || ncc.CPUs != 2 || ncc.MemBytes != 2<<30 || ncc.OS != "Linux" {
		t.Errorf("ncc: %+v", ncc)
	}
	if len(inv.Hosts[0].IPs) != 1 || inv.Hosts[0].IPs[0] != "192.168.1.12" || inv.Hosts[1].IPs[0] != "192.168.1.13" {
		t.Errorf("host addresses from cluster status: %+v", inv.Hosts)
	}
	if len(ncc.MACs) != 1 || ncc.MACs[0] != "bc:24:11:00:00:64" {
		t.Errorf("ncc MACs %v", ncc.MACs)
	}
	if p := by["pihole"]; len(p.MACs) != 1 || p.MACs[0] != "bc:24:11:00:00:c8" {
		t.Errorf("pihole MACs %v", p.MACs)
	}
	if len(ncc.IPs) != 1 || ncc.IPs[0] != "192.168.1.247" || ncc.GuestTools != "agent running" {
		t.Errorf("ncc guest: %v %q", ncc.IPs, ncc.GuestTools)
	}
	if ha := by["home-assistant"]; len(ha.IPs) != 2 || ha.IPs[0] != "192.168.30.10" || len(ha.Tags) != 1 {
		t.Errorf("home-assistant: %+v", ha)
	}
	if w := by["win11-desktop"]; len(w.IPs) != 0 || w.GuestTools != "agent not responding" || w.OS != "Windows 11 / Server 2022+" {
		t.Errorf("win11: %+v", w)
	}
	if p := by["pihole"]; p.Type != "lxc" || len(p.IPs) != 1 || p.IPs[0] != "192.168.1.53" || p.OS != "Debian container" {
		t.Errorf("pihole: %+v", p)
	}
	if !by["ubuntu-2404-template"].Template || by["plex"].State != hv.StateStopped {
		t.Error("template or stopped state wrong")
	}
	if len(inv.Warnings) != 0 {
		t.Errorf("warnings: %v", inv.Warnings)
	}
}

func TestCollectWithPassword(t *testing.T) {
	res, err := collect(t, map[string]string{"username": "root", "password": "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Inventory.VMs) != 7 {
		t.Fatalf("got %d VMs", len(res.Inventory.VMs))
	}
}

func TestBadCredentials(t *testing.T) {
	if _, err := collect(t, map[string]string{"username": "root", "password": "nope"}); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("password: %v", err)
	}
	if _, err := collect(t, map[string]string{"token_id": "ncc@pve!monitor", "token_secret": "nope"}); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("token: %v", err)
	}
	if _, err := collect(t, map[string]string{"token_id": "ncc@pve", "token_secret": "x"}); err == nil {
		t.Error("token id without ! accepted")
	}
}

func TestConfigMACs(t *testing.T) {
	got := configMACs(map[string]any{
		"net1":   "e1000=52:54:00:AA:BB:CC,bridge=vmbr1,tag=30",
		"net0":   "virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=1",
		"net2":   "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:02:01,ip=dhcp",
		"netx":   "virtio=00:00:00:00:00:01",
		"net3":   "bridge=vmbr0", // no MAC yet
		"ostype": "l26",
	})
	want := []string{"bc:24:11:00:00:01", "52:54:00:aa:bb:cc", "bc:24:11:00:02:01"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("got %v want %v", got, want)
	}
}
