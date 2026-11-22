package api_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/dnszones"
	"github.com/dertown/network-control-centre/internal/mocklab"
)

func zoneRow(rep dnszones.Report, network string) dnszones.Row {
	for _, r := range rep.Rows {
		if r.Network == network {
			return r
		}
	}
	return dnszones.Row{}
}

func TestDNSZonesAndVLANs(t *testing.T) {
	c, lab, routerID, done := vlanSetup(t, "ncc")
	defer done()
	pdnsLab := mocklab.NewPowerDNS("pdns-key")
	pdns := httptest.NewServer(pdnsLab)
	defer pdns.Close()
	var dnsT core.Target
	if code := c.do("POST", "/api/targets", map[string]any{
		"kind": "powerdns", "category": "dns", "name": "pdns", "address": pdns.URL,
		"credentials": map[string]string{"api_key": "pdns-key"},
	}, &dnsT); code != 201 {
		t.Fatalf("create dns target: %d", code)
	}

	var rep dnszones.Report
	if code := c.do("GET", "/api/dns/zonemap", nil, &rep); code != 200 {
		t.Fatalf("zonemap: %d", code)
	}
	// the mock router's Default network hands out home.lan, which the DNS server holds
	if rep.Domain != "home.lan." || len(rep.Rows) != 4 || len(rep.Servers) != 1 || !rep.Servers[0].CanCreate || !rep.Routers[0].CanSetDomain {
		t.Fatalf("report: %+v", rep)
	}
	iot := zoneRow(rep, "IoT")
	if iot.Suggested != "iot.home.lan." || iot.Status != "warn" || iot.VLAN != 30 {
		t.Fatalf("IoT: %+v", iot)
	}

	req := map[string]any{
		"server_id": dnsT.ID,
		"zones":     []map[string]any{{"name": "iot.home.lan", "delegate": true}, {"name": "dmz.home.lan", "delegate": true}},
		"assign": []map[string]any{
			{"zone": "iot.home.lan.", "router_id": routerID, "network_id": "net_iot", "set_dhcp_domain": true, "reverse": true},
			{"zone": "dmz.home.lan.", "router_id": routerID, "network_id": "net_dmz", "set_dhcp_domain": true},
			{"zone": "home.lan.", "router_id": routerID, "network_id": "net_default", "set_dhcp_domain": true},
		},
		"dry_run": true,
	}
	var out struct {
		Applied bool                  `json:"applied"`
		Plan    dnszones.Plan         `json:"plan"`
		Results []dnszones.StepResult `json:"results"`
		Error   string                `json:"error"`
	}
	if code := c.do("POST", "/api/dns/zoneplan", req, &out); code != 200 || out.Applied {
		t.Fatalf("preview: %d %+v", code, out)
	}
	var kinds []string
	for _, s := range out.Plan.Steps {
		kinds = append(kinds, s.Kind)
	}
	if got := strings.Join(kinds, ","); got != "create_zone,create_zone,delegate,delegate,create_reverse,assign,assign,assign,dhcp_domain,dhcp_domain" {
		t.Fatalf("steps: %s", got)
	}
	if len(lab.Writes()) != 0 || len(pdnsLab.Patches) != 0 {
		t.Fatalf("a preview must not change anything: %v %v", lab.Writes(), pdnsLab.Patches)
	}

	req["dry_run"] = false
	if code := c.do("POST", "/api/dns/zoneplan", req, &out); code != 200 || !out.Applied || len(out.Results) != 10 {
		t.Fatalf("apply: %d %+v", code, out)
	}
	writes := strings.Join(lab.Writes(), "\n")
	if !strings.Contains(writes, "PUT rest/networkconf/net_iot domain_name=iot.home.lan") || !strings.Contains(writes, "net_dmz domain_name=dmz.home.lan") ||
		strings.Contains(writes, "net_default") {
		t.Fatalf("router writes: %s", writes)
	}

	pollUntil(c, routerID)
	rep = dnszones.Report{} // decoding into a used slice keeps old fields
	c.do("GET", "/api/dns/zonemap", nil, &rep)
	if r := zoneRow(rep, "IoT"); r.Status != "pass" || r.Zone != "iot.home.lan." || !r.ZoneFound || !r.ReverseFound || r.DHCPDomain != "iot.home.lan" {
		t.Fatalf("IoT after: %+v", r)
	}
	// the DMZ has no reverse zone (it wasn't asked for)
	if r := zoneRow(rep, "DMZ"); r.Status != "warn" || len(r.Issues) != 1 || r.Issues[0].Code != dnszones.IssueNoReverse {
		t.Fatalf("DMZ after: %+v", r)
	}
	var subdomain bool
	for _, z := range rep.Zones {
		if z.Zone == "iot.home.lan." && z.Parent == "home.lan." && len(z.Networks) == 1 {
			subdomain = true
		}
	}
	if !subdomain {
		t.Fatalf("zones: %+v", rep.Zones)
	}

	// putting IoT in the DMZ's zone is flagged
	if code := c.do("POST", "/api/dns/zoneplan", map[string]any{"server_id": dnsT.ID,
		"assign": []map[string]any{{"zone": "dmz.home.lan.", "router_id": routerID, "network_id": "net_iot"}}}, &out); code != 200 {
		t.Fatalf("reassign: %d %+v", code, out)
	}
	rep = dnszones.Report{} // decoding into a used slice keeps old fields
	c.do("GET", "/api/dns/zonemap", nil, &rep)
	r := zoneRow(rep, "IoT")
	var mismatch bool
	for _, is := range r.Issues {
		mismatch = mismatch || is.Code == dnszones.IssueNameMismatch
	}
	if !mismatch {
		t.Fatalf("mismatch not flagged: %+v", r)
	}

	// a zone in use can't be deleted; unassign first
	if code := c.do("DELETE", "/api/dns/"+itoa(dnsT.ID)+"/zones/iot.home.lan.", nil, nil); code != 200 {
		t.Fatalf("iot.home.lan. is no longer assigned and can be deleted: %d", code)
	}
	if code := c.do("DELETE", "/api/dns/"+itoa(dnsT.ID)+"/zones/dmz.home.lan.", nil, nil); code != 409 {
		t.Fatalf("delete assigned zone: %d", code)
	}
	if code := c.do("DELETE", "/api/dns/zonemap/"+itoa(r.AssignmentID), nil, nil); code != 200 {
		t.Fatalf("unassign: %d", code)
	}
	rep = dnszones.Report{} // decoding into a used slice keeps old fields
	c.do("GET", "/api/dns/zonemap", nil, &rep)
	if r := zoneRow(rep, "IoT"); r.Zone != "" || r.Suggested != "iot.home.lan." {
		t.Fatalf("after unassign: %+v", r)
	}
}
