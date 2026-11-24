package catalog_test

import (
	"testing"

	"github.com/dertown/network-control-centre/internal/catalog"

	_ "github.com/dertown/network-control-centre/internal/dns/azuredns"
	_ "github.com/dertown/network-control-centre/internal/dns/bind"
	_ "github.com/dertown/network-control-centre/internal/dns/powerdns"
	_ "github.com/dertown/network-control-centre/internal/dns/windowsdns"
	_ "github.com/dertown/network-control-centre/internal/drivers/snmpnet"
	_ "github.com/dertown/network-control-centre/internal/drivers/unifi"
	_ "github.com/dertown/network-control-centre/internal/hypervisor/hyperv"
	_ "github.com/dertown/network-control-centre/internal/hypervisor/proxmox"
	_ "github.com/dertown/network-control-centre/internal/hypervisor/vmware"
	_ "github.com/dertown/network-control-centre/internal/smarthome/homeassistant"
	_ "github.com/dertown/network-control-centre/internal/storage/nfs"
	_ "github.com/dertown/network-control-centre/internal/storage/qnap"
	_ "github.com/dertown/network-control-centre/internal/storage/smb"
	_ "github.com/dertown/network-control-centre/internal/storage/snmpnas"
	_ "github.com/dertown/network-control-centre/internal/storage/synology"
)

// Every entry must make a usable form: known groups, select defaults among the choices,
// conditions on fields that exist, and every wizard group offered by at least one vendor.
func TestCatalogEntriesAreWellFormed(t *testing.T) {
	groups := map[string]bool{}
	for _, g := range catalog.Groups {
		groups[g.ID] = true
	}
	used := map[string]bool{}
	for _, v := range catalog.List() {
		if v.Label == "" || v.Summary == "" || v.Kind == "" || v.Category == "" || len(v.Groups) == 0 {
			t.Errorf("%s: incomplete entry %+v", v.ID, v)
		}
		for _, g := range v.Groups {
			if !groups[g] {
				t.Errorf("%s: unknown group %q", v.ID, g)
			}
			used[g] = true
		}
		keys := map[string]bool{}
		for _, f := range v.Fields {
			if keys[f.Key] {
				t.Errorf("%s: field %s twice", v.ID, f.Key)
			}
			keys[f.Key] = true
		}
		for _, f := range v.Fields {
			if f.Store != catalog.StoreOption && f.Store != catalog.StoreSecret && f.Store != catalog.StoreForm {
				t.Errorf("%s.%s: store %q", v.ID, f.Key, f.Store)
			}
			for k := range f.ShowIf {
				if !keys[k] {
					t.Errorf("%s.%s: shown if %s, which isn't a field", v.ID, f.Key, k)
				}
			}
			if f.Type == catalog.Select {
				ok := f.Default == ""
				for _, c := range f.Choices {
					ok = ok || c.Value == f.Default
				}
				if !ok || len(f.Choices) == 0 {
					t.Errorf("%s.%s: default %q is not a choice", v.ID, f.Key, f.Default)
				}
			}
		}
		if !v.NoLogin {
			secret := false
			for _, f := range v.Fields {
				secret = secret || f.Store == catalog.StoreSecret
			}
			if !secret {
				t.Errorf("%s: no login fields", v.ID)
			}
		}
	}
	for g := range groups {
		if !used[g] {
			t.Errorf("group %s has no vendors", g)
		}
	}
	for _, id := range []string{"powerdns", "bind", "windowsdns", "azuredns", "proxmox", "vmware", "hyperv", "unifi", "snmpnet", "snmp-fortigate"} {
		if _, ok := catalog.Get(id); !ok {
			t.Errorf("%s is not in the catalog", id)
		}
	}
}

func TestCheckOptions(t *testing.T) {
	v, _ := catalog.Get("bind")
	if err := v.CheckOptions(map[string]string{"tsig_algorithm": "hmac-md5"}); err == nil {
		t.Fatal("a value outside the choices passed")
	}
	if err := v.CheckOptions(map[string]string{"tsig_algorithm": "hmac-sha512", "tls_fingerprint": "abc"}); err != nil {
		t.Fatal(err)
	}
}
