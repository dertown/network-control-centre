package api_test

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/assistant"
	"github.com/dertown/network-control-centre/internal/dnszones"
	"github.com/dertown/network-control-centre/internal/drivers/unifi"
	"github.com/dertown/network-control-centre/internal/mocklab"
)

func TestAssistant(t *testing.T) {
	unifi.BounceDown = 50 * time.Millisecond
	c, lab, _, done := vlanSetup(t, "ncc")
	defer done()

	var home struct {
		Providers []struct {
			ID        string `json:"id"`
			Connected bool   `json:"connected"`
			Enabled   bool   `json:"enabled"`
		} `json:"providers"`
		Plans []assistant.Plan `json:"plans"`
	}
	if code := c.do("GET", "/api/assistant", nil, &home); code != 200 || len(home.Providers) != 5 || len(home.Plans) != 0 {
		t.Fatalf("home: %d %+v", code, home)
	}
	if p := home.Providers[0]; p.ID != assistant.KindClaude || p.Connected || p.Enabled {
		t.Fatalf("claude: %+v", p)
	}
	if p := home.Providers[4]; p.ID != assistant.KindOllama || !p.Connected {
		t.Fatalf("ollama needs no sign-in: %+v", p)
	}

	// installing a tool shows its plan, and needs confirming
	var ip assistant.InstallPlan
	if code := c.do("GET", "/api/assistant/providers/ollama/install", nil, &ip); code != 200 || ip.CanInstall || ip.Problem == "" {
		t.Fatalf("ollama install plan: %d %+v", code, ip)
	}
	if code := c.do("POST", "/api/assistant/providers/claude-code/install", map[string]bool{"confirm": false}, nil); code != 400 {
		t.Fatalf("install without confirming: %d", code)
	}
	if code := c.do("POST", "/api/assistant/providers/ollama/install", map[string]bool{"confirm": true}, nil); code != 409 {
		t.Fatalf("installing ollama: %d", code)
	}

	// an API key is not a way in
	if code := c.do("POST", "/api/assistant/providers/claude-code/paste", map[string]string{"value": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"}, nil); code != 400 {
		t.Fatalf("API key accepted: %d", code)
	}
	if code := c.do("POST", "/api/assistant/plans", map[string]string{"provider": "claude-code"}, nil); code != 409 {
		t.Fatalf("plan with a provider that is off: %d", code)
	}

	// what the assistant sees
	var pic struct {
		Picture assistant.Picture `json:"picture"`
		Size    string            `json:"size"`
	}
	if code := c.do("GET", "/api/assistant/picture", nil, &pic); code != 200 || len(pic.Picture.Routers) != 1 || !pic.Picture.Routers[0].CanChange {
		t.Fatalf("picture: %d %+v", code, pic)
	}
	if !strings.Contains(pic.Size, "4 networks") {
		t.Fatalf("size: %s", pic.Size)
	}

	// NCC's own rules: the smart devices on Default go to IoT, the NAS behind the Plex
	// forward is offered for the DMZ but not picked
	var plan assistant.Plan
	if code := c.do("POST", "/api/assistant/plans", map[string]string{"goal": ""}, &plan); code != 201 {
		t.Fatalf("plan: %d", code)
	}
	if plan.Source != "rules" || plan.Status != assistant.PlanProposed || len(plan.Steps) != 2 {
		t.Fatalf("plan: %+v", plan)
	}
	mv := plan.Steps[0]
	names := []string{}
	for _, cl := range mv.Clients {
		names = append(names, cl.Name)
	}
	if mv.Kind != assistant.StepMove || mv.NetworkName != "IoT" || !mv.Recommended || !strings.Contains(strings.Join(names, ","), "garage-cam") ||
		strings.Contains(strings.Join(names, ","), "desk-pc") || strings.Contains(strings.Join(names, ","), "thermostat") {
		t.Fatalf("IoT move: %+v", mv)
	}
	if dmz := plan.Steps[1]; dmz.NetworkName != "DMZ" || dmz.Recommended || dmz.Clients[0].Name != "nas" {
		t.Fatalf("DMZ move: %+v", dmz)
	}
	if len(lab.Writes()) != 0 {
		t.Fatalf("planning changed the console: %v", lab.Writes())
	}

	// nothing is applied without confirmation, or for a step that isn't in the plan
	if code := c.do("POST", "/api/assistant/plans/"+plan.ID+"/deploy", map[string]any{"steps": []string{"s1"}}, nil); code != 400 {
		t.Fatalf("unconfirmed deploy: %d", code)
	}
	if code := c.do("POST", "/api/assistant/plans/"+plan.ID+"/deploy", map[string]any{"steps": []string{"s9"}, "confirm": true}, nil); code != 400 {
		t.Fatalf("unknown step: %d", code)
	}
	if len(lab.Writes()) != 0 {
		t.Fatalf("console changed: %v", lab.Writes())
	}

	if code := c.do("POST", "/api/assistant/plans/"+plan.ID+"/deploy", map[string]any{"steps": []string{"s1"}, "confirm": true}, nil); code != 202 {
		t.Fatalf("deploy: %d", code)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		c.do("GET", "/api/assistant/plans/"+plan.ID, nil, &plan)
		if plan.Status != assistant.PlanDeploying || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if plan.Status != assistant.PlanDeployed || plan.Steps[0].Result == nil || plan.Steps[0].Result.State != "ok" || plan.Steps[1].Result != nil {
		t.Fatalf("deployed: %s %+v %+v", plan.Status, plan.Steps[0].Result, plan.Steps[1].Result)
	}
	if !strings.Contains(plan.Steps[0].Result.Message, "to IoT") {
		t.Fatalf("result: %+v", plan.Steps[0].Result)
	}
	writes := strings.Join(lab.Writes(), "\n")
	if !strings.Contains(writes, "net_iot") {
		t.Fatalf("console writes: %s", writes)
	}
	if code := c.do("POST", "/api/assistant/plans/"+plan.ID+"/deploy", map[string]any{"steps": []string{"s2"}, "confirm": true}, nil); code != 409 {
		t.Fatalf("second deploy of one plan: %d", code)
	}

	var audit []struct {
		Action string `json:"action"`
	}
	c.do("GET", "/api/audit", nil, &audit)
	seen := map[string]bool{}
	for _, a := range audit {
		seen[a.Action] = true
	}
	for _, want := range []string{"assistant.plan", "assistant.deploy", "assistant.deployed", "vlan.move"} {
		if !seen[want] {
			t.Errorf("audit misses %s", want)
		}
	}
}

func TestAssistantDNSZones(t *testing.T) {
	unifi.BounceDown = 50 * time.Millisecond
	c, lab, routerID, done := vlanSetup(t, "ncc")
	defer done()
	pdns := httptest.NewServer(mocklab.NewPowerDNS("pdns-key"))
	defer pdns.Close()
	if code := c.do("POST", "/api/targets", map[string]any{
		"kind": "powerdns", "category": "dns", "name": "pdns", "address": pdns.URL,
		"credentials": map[string]string{"api_key": "pdns-key"},
	}, nil); code != 201 {
		t.Fatalf("create dns target: %d", code)
	}

	// with a DNS server that can make zones, the plan gives IoT its own zone and hands it out
	var plan assistant.Plan
	if code := c.do("POST", "/api/assistant/plans", map[string]string{}, &plan); code != 201 {
		t.Fatalf("plan: %d", code)
	}
	var kinds []string
	for _, s := range plan.Steps {
		kinds = append(kinds, s.Kind)
		if (s.Kind == assistant.StepCreateZone || s.Kind == assistant.StepAssignZone) && s.Problem != "" {
			t.Fatalf("%s: %s", s.Title, s.Problem)
		}
	}
	if strings.Join(kinds, ",") != "move_clients,move_clients,create_zone,assign_zone" || plan.Steps[2].Zone != "iot.home.lan." {
		t.Fatalf("steps: %v %+v", kinds, plan.Steps)
	}

	if code := c.do("POST", "/api/assistant/plans/"+plan.ID+"/deploy", map[string]any{"steps": []string{"s3", "s4"}, "confirm": true}, nil); code != 202 {
		t.Fatalf("deploy: %d", code)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		c.do("GET", "/api/assistant/plans/"+plan.ID, nil, &plan)
		if plan.Status != assistant.PlanDeploying || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if plan.Status != assistant.PlanDeployed {
		t.Fatalf("deployed: %s %+v %+v", plan.Status, plan.Steps[2].Result, plan.Steps[3].Result)
	}
	if w := strings.Join(lab.Writes(), "\n"); !strings.Contains(w, "net_iot domain_name=iot.home.lan") {
		t.Fatalf("router writes: %s", w)
	}
	pollUntil(c, routerID)
	var rep dnszones.Report
	c.do("GET", "/api/dns/zonemap", nil, &rep)
	if r := zoneRow(rep, "IoT"); r.Zone != "iot.home.lan." || !r.ZoneFound || r.DHCPDomain != "iot.home.lan" {
		t.Fatalf("IoT after: %+v", r)
	}
}
