package unifi

import (
	"encoding/json"
	"errors"
	"testing"

	inv "github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/mocklab"
)

func mockFirewall(t *testing.T) *firewallData {
	t.Helper()
	fw := &firewallData{PoliciesKnown: true}
	var groups envelope[rawFirewallGroup]
	var rules envelope[rawFirewallRule]
	var fwds envelope[rawPortForward]
	for b, out := range map[*[]byte]any{&mocklab.RestFirewallGroup: &groups, &mocklab.RestFirewallRule: &rules,
		&mocklab.RestPortForward: &fwds, &mocklab.FirewallPolicies: &fw.Policies} {
		if err := json.Unmarshal(*b, out); err != nil {
			t.Fatal(err)
		}
	}
	fw.Groups, fw.Rules, fw.Forwards = groups.Data, rules.Data, fwds.Data
	return fw
}

func ruleByID(f *inv.Firewall, id string) inv.FirewallRule {
	for _, r := range f.Rules {
		if r.ID == id {
			return r
		}
	}
	return inv.FirewallRule{}
}

func TestBuildFirewallZonePolicies(t *testing.T) {
	f := BuildFirewall("home", mockFirewall(t), mockSiteConfig(t, true), load[rawClient](t, "stat_sta.json"))
	if f.Mode != inv.FirewallZones || len(f.Rules) != 7 {
		t.Fatalf("mode %q, %d rules", f.Mode, len(f.Rules))
	}
	// the admin's own policies come first, by index; built-in ones last
	if f.Rules[0].ID != "fp_iot_dns" || !f.Rules[6].Builtin || f.Rules[3].Builtin {
		t.Fatalf("order: %+v", f.Rules)
	}
	block := ruleByID(f, "fp_iot_block")
	if block.Action != "block" || !block.Enabled || block.Source.Zone != "IoT" || block.Destination.Zone != "Internal" ||
		block.Source.Match != "Any" || block.Protocol != "Any" || !block.Logging {
		t.Errorf("block IoT: %+v", block)
	}
	dns := ruleByID(f, "fp_iot_dns")
	if dns.Source.Match != "IoT" || dns.Destination.Match != "DNS servers" || dns.Destination.Port != "53" ||
		dns.Protocol != "TCP/UDP" || dns.IPVersion != "IPv4" {
		t.Errorf("IoT DNS: %+v", dns)
	}
	web := ruleByID(f, "fp_dmz_web")
	if web.Destination.Zone != "Dmz" || web.Destination.Match != "192.168.50.10" || web.Destination.Port != "Web (80, 443)" {
		t.Errorf("DMZ web: %+v", web)
	}
	tv := ruleByID(f, "fp_kids")
	if tv.Enabled || tv.Action != "reject" || tv.Source.Match != "tv" || tv.Schedule != "every day" {
		t.Errorf("TV at night: %+v", tv)
	}
	if r := ruleByID(f, "fp_pre_2"); len(r.States) != 2 || r.States[0] != "established" {
		t.Errorf("return traffic: %+v", r)
	}
}

func TestBuildPortForwards(t *testing.T) {
	f := BuildFirewall("home", mockFirewall(t), mockSiteConfig(t, true), load[rawClient](t, "stat_sta.json"))
	if len(f.Forwards) != 4 {
		t.Fatalf("forwards: %+v", f.Forwards)
	}
	by := map[string]inv.PortForward{}
	for _, p := range f.Forwards {
		by[p.ID] = p
	}
	if p := by["pf_web"]; p.ExternalPort != "443" || p.ForwardIP != "192.168.50.10" || p.ForwardClient != "web-dmz" ||
		p.Protocol != "TCP" || p.Interface != "WAN" || p.Source != "Any" || !p.Enabled {
		t.Errorf("web: %+v", p)
	}
	if p := by["pf_ssh"]; p.Source != "Office IPs" || p.ForwardPort != "22" || p.ForwardClient != "nas" {
		t.Errorf("ssh: %+v", p)
	}
	if p := by["pf_plex"]; p.Protocol != "TCP/UDP" || p.Interface != "Both WANs" {
		t.Errorf("plex: %+v", p)
	}
	if p := by["pf_game"]; p.Enabled || p.ExternalPort != "27015-27030" {
		t.Errorf("game: %+v", p)
	}
}

func TestBuildFirewallLegacyRules(t *testing.T) {
	fw := &firewallData{
		Groups: []rawFirewallGroup{{ID: "g1", Name: "Web", Type: "port-group", Members: []string{"80", "443"}},
			{ID: "g2", Name: "Admins", Type: "address-group"}},
		Rules: []rawFirewallRule{
			{ID: "r2", Name: "Allow web", Enabled: true, Action: "accept", Ruleset: "WAN_IN", RuleIndex: 2001, Protocol: "tcp",
				DstAddress: "192.168.50.10", DstGroupIDs: []string{"g1"}},
			{ID: "r1", Name: "Drop IoT", Enabled: true, Action: "drop", Ruleset: "LAN_IN", RuleIndex: 2000,
				SrcNetworkID: "net_iot", DstNetworkID: "net_default", SrcGroupIDs: []string{"g2"}, StateNew: true},
		},
	}
	f := BuildFirewall("home", fw, mockSiteConfig(t, false), nil)
	if f.Mode != inv.FirewallLegacy || len(f.Rules) != 2 || f.Rules[0].Ruleset != "LAN_IN" {
		t.Fatalf("%+v", f)
	}
	if r := f.Rules[0]; r.Action != "block" || r.Source.Match != "IoT, Admins" || r.Destination.Match != "Default" ||
		len(r.States) != 1 || r.States[0] != "new" {
		t.Errorf("drop IoT: %+v", r)
	}
	if r := f.Rules[1]; r.Action != "allow" || r.Destination.Match != "192.168.50.10" || r.Destination.Port != "Web (80, 443)" {
		t.Errorf("allow web: %+v", r)
	}
}

func TestFirewallNotes(t *testing.T) {
	if n := refused("port forward", &authError{code: 403}); n == "" || !errors.Is(&authError{}, ErrUnauthorized) {
		t.Fatal(n)
	}
	f := BuildFirewall("home", &firewallData{Notes: []string{"x"}}, nil, nil)
	if f.Mode != "" || len(f.Notes) != 1 || f.Rules == nil || f.Forwards == nil {
		t.Fatalf("%+v", f)
	}
}
