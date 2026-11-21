package proxmox

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	hv "github.com/dertown/network-control-centre/internal/hypervisor"
	"github.com/dertown/network-control-centre/internal/mocklab"
)

func TestControl(t *testing.T) {
	for _, creds := range []map[string]string{
		{"token_id": "ncc@pve!monitor", "token_secret": "secret"},
		{"username": "root@pam", "password": "pw"}, // ticket login: writes need the CSRF token
	} {
		srv := httptest.NewTLSServer(mocklab.Proxmox("secret", "pw"))
		ctx := context.Background()
		tg := hv.Target{Name: "pve", Kind: "proxmox", Address: srv.URL, Options: map[string]string{}}
		p := Provider{}
		find := func(name string) hv.VM {
			t.Helper()
			res, err := p.Collect(ctx, tg, creds)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range res.Inventory.VMs {
				if v.Name == name {
					return v
				}
			}
			return hv.VM{}
		}

		if err := p.Power(ctx, tg, creds, "pve/qemu/100", hv.ActionStop); err != nil {
			t.Fatal(err)
		}
		if v := find("ncc"); v.State != hv.StateStopped {
			t.Fatalf("after stop: %s", v.State)
		}
		if err := p.Power(ctx, tg, creds, "pve/qemu/100", hv.ActionStart); err != nil {
			t.Fatal(err)
		}
		if v := find("ncc"); v.State != hv.StateRunning {
			t.Fatalf("after start: %s", v.State)
		}
		if err := p.Power(ctx, tg, creds, "pve/qemu/9000", hv.ActionStart); err == nil {
			t.Error("started a template")
		}

		name, cpus, mem, notes := "plex-media", 6, 4096, "movies"
		if err := p.Configure(ctx, tg, creds, "pve/qemu/103", hv.Settings{Name: &name, CPUs: &cpus, MemoryMB: &mem, Notes: &notes}); err != nil {
			t.Fatal(err)
		}
		if v := find("plex-media"); v.CPUs != 6 || v.MemBytes != 4096<<20 || v.Notes != "movies" {
			t.Fatalf("after configure: %+v", v)
		}
		small := 8
		if err := p.Configure(ctx, tg, creds, "pve/qemu/103", hv.Settings{MemoryMB: &small}); err == nil {
			t.Error("accepted 8 MB of memory")
		}
		ct := "pihole-2"
		if err := p.Configure(ctx, tg, creds, "pve/lxc/200", hv.Settings{Name: &ct}); err != nil {
			t.Fatal(err)
		}
		if v := find("pihole-2"); v.Type != "lxc" {
			t.Fatal("container rename failed")
		}

		if err := p.Delete(ctx, tg, creds, "pve/qemu/101"); err == nil || !strings.Contains(err.Error(), "stop") {
			t.Fatalf("deleted a running VM: %v", err)
		}
		if err := p.Delete(ctx, tg, creds, "pve/qemu/103"); err != nil {
			t.Fatal(err)
		}
		if v := find("plex-media"); v.Name != "" {
			t.Fatal("VM still listed after delete")
		}
		if err := p.Delete(ctx, tg, creds, "pve/qemu/103"); err == nil {
			t.Error("deleted a missing VM")
		}
		srv.Close()
	}
}
