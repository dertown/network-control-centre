package assistant

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/drivers"
	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/iot"
	"github.com/dertown/network-control-centre/internal/store"
	"github.com/dertown/network-control-centre/internal/vault"
)

// a small office: one flat LAN, a guest network, cameras and printers on the LAN, and a NAS
// the internet reaches through a port forward.
func office() Inputs {
	snap := &inventory.Snapshot{
		Target: "udr", TakenAt: time.Now(),
		Devices: []inventory.Device{{ID: "aa:00:00:00:00:01", Name: "Rack switch", Kind: inventory.KindSwitch, Managed: true, Online: true,
			Discovery: inventory.SourceController, Ports: []inventory.Port{{Index: 3, Name: "Port 3"}, {Index: 4, Name: "Port 4"}}}},
		Networks: []inventory.Network{
			{ID: "lan", Name: "Default", Purpose: "corporate", Subnet: "192.168.1.0/24", Zone: "internal", InternetAccess: true},
			{ID: "guest", Name: "Guest", Purpose: "guest", VLAN: 20, Subnet: "192.168.20.0/24", Zone: "hotspot", InternetAccess: true},
			{ID: "wan", Name: "Internet", Purpose: "wan"},
		},
		Clients: []inventory.Client{
			{MAC: "de:ad:00:00:00:01", Name: "lobby-cam", Vendor: "Hikvision", IP: "192.168.1.20", NetworkID: "lan", Wired: true, SwitchMAC: "aa:00:00:00:00:01", SwitchPort: 3},
			{MAC: "de:ad:00:00:00:02", Name: "hp-laserjet", Vendor: "HP Inc.", IP: "192.168.1.30", NetworkID: "lan", SSID: "Office"},
			{MAC: "de:ad:00:00:00:03", Name: "finance-pc", Vendor: "Dell", IP: "192.168.1.40", NetworkID: "lan", Wired: true, SwitchMAC: "aa:00:00:00:00:01", SwitchPort: 4},
			{MAC: "de:ad:00:00:00:04", Name: "nas", Vendor: "Synology", IP: "192.168.1.50", NetworkID: "lan", SSID: "Office"},
			{MAC: "de:ad:00:00:00:05", Name: "boardroom-tv", Vendor: "Samsung", IP: "192.168.1.60", NetworkID: "lan", SSID: "Office"},
		},
		Firewall: &inventory.Firewall{Forwards: []inventory.PortForward{{Name: "NAS", Enabled: true, Protocol: "TCP", ExternalPort: "5001", ForwardIP: "192.168.1.50"}}},
	}
	return Inputs{
		Routers: []RouterInput{{ID: 1, Name: "udr", CanChange: true, CanSetDomain: true, Snapshot: snap}},
		IoT: []iot.Device{
			{MAC: "de:ad:00:00:00:01", Type: iot.TypeCamera},
			{MAC: "de:ad:00:00:00:02", Type: iot.TypePrinter},
			{MAC: "de:ad:00:00:00:05", Type: iot.TypeDisplay, NetworkOK: true, NetworkOKReason: "casts from laptops"},
		},
		IoTNetworks: map[string]bool{},
		DNS:         []DNSServer{{ID: 7, Name: "ns1", Kind: "powerdns", Zones: []string{"corp.lan.", "1.168.192.in-addr.arpa."}, CanCreateZones: true}},
	}
}

func kinds(steps []Step) string {
	var s []string
	for _, st := range steps {
		s = append(s, st.Kind)
	}
	return strings.Join(s, ",")
}

func TestBaseline(t *testing.T) {
	p := BuildPicture(office())
	if p.Domain != "corp.lan." {
		t.Fatalf("domain: %q", p.Domain)
	}
	a := Baseline(p)
	steps, notes := Check(p, a)
	want := "create_vlan,move_clients,create_vlan,move_clients,create_zone,assign_zone,create_zone,assign_zone"
	if kinds(steps) != want {
		t.Fatalf("steps %s, notes %v", kinds(steps), notes)
	}
	for _, st := range steps {
		if st.Problem != "" {
			t.Errorf("%s: %s", st.Title, st.Problem)
		}
	}
	iotNet := steps[0].Network
	if iotNet.Name != "IoT" || iotNet.VLAN != 30 || iotNet.Gateway != "192.168.30.1/24" || !iotNet.Isolated || !iotNet.InternetAccess || iotNet.DHCPStart == "" {
		t.Fatalf("IoT network: %+v", iotNet)
	}
	// camera and printer move; the TV may stay; the PC and NAS are not IoT
	mv := steps[1]
	if mv.NetworkID != "new:IoT" || len(mv.Clients) != 2 || mv.Clients[0].Name != "hp-laserjet" || mv.Clients[1].Name != "lobby-cam" || !mv.Recommended {
		t.Fatalf("IoT move: %+v", mv)
	}
	if !strings.Contains(mv.Why, "1 camera and 1 printer") {
		t.Errorf("why: %s", mv.Why)
	}
	// the NAS is forwarded from the internet: DMZ, not picked to begin with
	if steps[2].Network.Name != "DMZ" || steps[2].Network.VLAN != 50 {
		t.Fatalf("DMZ: %+v", steps[2].Network)
	}
	if dm := steps[3]; dm.Recommended || len(dm.Clients) != 1 || dm.Clients[0].Name != "nas" || !strings.Contains(dm.Why, "port forward") {
		t.Fatalf("DMZ move: %+v", dm)
	}
	if steps[4].Zone != "iot.corp.lan." || steps[4].DNSServerID != 7 || steps[5].Zone != "iot.corp.lan." || steps[5].NetworkName != "IoT" {
		t.Fatalf("zones: %+v %+v", steps[4], steps[5])
	}
	if !strings.Contains(strings.Join(steps[4].Warnings, " "), "under corp.lan") {
		t.Errorf("delegation warning: %v", steps[4].Warnings)
	}
}

func TestBaselineUsesExistingIoTNetwork(t *testing.T) {
	in := office()
	snap := in.Routers[0].Snapshot
	snap.Networks = append(snap.Networks, inventory.Network{ID: "iot", Name: "Smart devices", VLAN: 30, Subnet: "192.168.30.0/24", InternetAccess: true})
	in.IoTNetworks = map[string]bool{"iot": true}
	in.DNS = nil
	p := BuildPicture(in)
	a := Baseline(p)
	steps, _ := Check(p, a)
	if kinds(steps) != "move_clients,create_vlan,move_clients" || steps[0].NetworkID != "iot" {
		t.Fatalf("steps: %s %+v", kinds(steps), steps[0])
	}
	// the DMZ can't take VLAN 30 now
	if steps[1].Network.VLAN == 30 || steps[1].Network.Gateway == "192.168.30.1/24" {
		t.Fatalf("DMZ clashes: %+v", steps[1].Network)
	}
	if !strings.Contains(strings.Join(a.Notes, " "), "No DNS server") {
		t.Errorf("notes: %v", a.Notes)
	}
}

func TestCheckRejectsWhatDoesNotFit(t *testing.T) {
	p := BuildPicture(office())
	p.Routers[0].CanSetDomain = false
	p.DNS[0].CanCreateZones = false
	ans, err := ParseAnswer("Here you go:\n```json\n" + `{"summary":"s","notes":["n"],"steps":[
		{"kind":"create_vlan","router_id":1,"name":"Cams","vlan":20,"gateway":"192.168.40.1/24","why":"x"},
		{"kind":"move_clients","router_id":1,"network":"Cams","macs":["de:ad:00:00:00:01"],"why":"x"},
		{"kind":"move_clients","router_id":1,"network":"Guest","macs":["ff:ff:ff:ff:ff:ff"],"why":"x"},
		{"kind":"move_clients","router_id":99,"network":"Guest","macs":["de:ad:00:00:00:02"],"why":"x"},
		{"kind":"create_zone","dns_server_id":7,"zone":"corp.lan.","why":"x"},
		{"kind":"create_zone","dns_server_id":7,"zone":"bad_name.corp.lan","why":"x"},
		{"kind":"create_zone","dns_server_id":7,"zone":"cams.corp.lan","why":"x"},
		{"kind":"assign_zone","router_id":1,"network":"Guest","zone":"cams.corp.lan","why":"x"},
		{"kind":"assign_zone","router_id":1,"network":"Guest","zone":"nowhere.lan","why":"x"},
		{"kind":"delete_everything","why":"x"}
	]}` + "\n```")
	if err != nil {
		t.Fatal(err)
	}
	steps, notes := Check(p, ans)
	if kinds(steps) != "create_vlan,move_clients,create_zone,create_zone,assign_zone,assign_zone" {
		t.Fatalf("steps: %s notes: %v", kinds(steps), notes)
	}
	if !strings.Contains(steps[0].Problem, "VLAN 20 is already used by Guest") || steps[0].Recommended {
		t.Errorf("clash: %+v", steps[0])
	}
	if !strings.Contains(steps[1].Problem, "needs the Cams network") {
		t.Errorf("dependent move: %+v", steps[1])
	}
	if !strings.Contains(steps[2].Problem, "not a valid DNS name") || !strings.Contains(steps[3].Problem, "cannot create zones") {
		t.Errorf("zones: %q %q", steps[2].Problem, steps[3].Problem)
	}
	if !strings.Contains(steps[4].Problem, "needs the zone cams.corp.lan, which can't be created") {
		t.Errorf("assign to a zone that can't be made: %q", steps[4].Problem)
	}
	if !strings.Contains(steps[5].Problem, "no DNS server has the zone nowhere.lan") {
		t.Errorf("assign: %q", steps[5].Problem)
	}
	all := strings.Join(notes, "\n")
	for _, want := range []string{"ff:ff:ff:ff:ff:ff", "router NCC doesn't know", "already has the zone corp.lan", "delete_everything"} {
		if !strings.Contains(all, want) {
			t.Errorf("notes miss %q: %s", want, all)
		}
	}
}

func TestParseAnswer(t *testing.T) {
	if _, err := ParseAnswer("I can't help with that."); err == nil {
		t.Fatal("prose accepted")
	}
	a, err := ParseAnswer(`{"summary":"ok","steps":[]}`)
	if err != nil || a.Summary != "ok" {
		t.Fatalf("%+v %v", a, err)
	}
}

type fakeEnv struct {
	calls     []string
	failVLAN  bool
	networkID string
}

func (f *fakeEnv) CreateNetwork(_ context.Context, _ int64, spec drivers.NetworkSpec) (string, error) {
	f.calls = append(f.calls, "create "+spec.Name)
	if f.failVLAN {
		return "", errors.New("console said no")
	}
	f.networkID = "n-" + spec.Name
	return f.networkID, nil
}

func (f *fakeEnv) FindNetwork(_ context.Context, _ int64, name string) (string, error) {
	if f.networkID == "n-"+name {
		return f.networkID, nil
	}
	return "", nil
}

func (f *fakeEnv) MoveClients(_ context.Context, _ int64, networkID string, macs []string) (string, error) {
	f.calls = append(f.calls, "move "+networkID+" "+strings.Join(macs, " "))
	return "moved", nil
}

func (f *fakeEnv) CreateZone(_ context.Context, _ int64, zone string) error {
	f.calls = append(f.calls, "zone "+zone)
	return nil
}

func (f *fakeEnv) AssignZone(_ context.Context, _ int64, networkID, zone string) error {
	f.calls = append(f.calls, "assign "+networkID+" "+zone)
	return nil
}

func TestDeploy(t *testing.T) {
	p := BuildPicture(office())
	steps, _ := Check(p, Baseline(p))
	plan := &Plan{Steps: steps, Status: PlanProposed}
	// only the IoT part: network, move, zone, assign
	picked := map[string]bool{"s1": true, "s2": true, "s5": true, "s6": true}
	env := &fakeEnv{}
	updates := 0
	Deploy(context.Background(), env, plan, picked, func(*Plan) { updates++ })
	want := []string{"create IoT", "move n-IoT de:ad:00:00:00:02 de:ad:00:00:00:01", "zone iot.corp.lan.", "assign n-IoT iot.corp.lan."}
	if strings.Join(env.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls: %q", env.calls)
	}
	if plan.Status != PlanDeployed || updates != 5 || plan.Steps[2].Result != nil {
		t.Fatalf("status %s, %d updates, unpicked step result %+v", plan.Status, updates, plan.Steps[2].Result)
	}

	// a network that fails to be created takes its moves with it
	plan = &Plan{Steps: steps, Status: PlanProposed}
	for i := range plan.Steps {
		plan.Steps[i].Result = nil
	}
	env = &fakeEnv{failVLAN: true}
	Deploy(context.Background(), env, plan, picked, nil)
	if plan.Status != PlanPartial || plan.Steps[0].Result.State != "failed" || plan.Steps[1].Result.State != "skipped" || plan.Steps[5].Result.State != "skipped" {
		t.Fatalf("after a failure: %s %+v %+v", plan.Status, plan.Steps[0].Result, plan.Steps[1].Result)
	}
	if plan.Steps[4].Result.State != "ok" {
		t.Fatalf("the zone does not depend on the network: %+v", plan.Steps[4].Result)
	}
}

func newService(t *testing.T) *Service {
	st, err := store.OpenPath(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(st.DB); err != nil {
		t.Fatal(err)
	}
	vs := vault.NewLocal(st.DB)
	if err := vs.Initialize(context.Background(), "a vault passphrase"); err != nil {
		t.Fatal(err)
	}
	return &Service{DB: st.DB, Vault: vs, TempDir: t.TempDir(), Timeout: 20 * time.Second}
}

// tool writes a pretend command-line tool.
func tool(t *testing.T, script string) string {
	p := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAskRunsTheToolWithItsSignIn(t *testing.T) {
	s := newService(t)
	ctx := context.Background()
	// the tool sees only its private home and its token, and reads the prompt on stdin
	bin := tool(t, `
[ -z "$NCC_HOME" ] || { echo "leaked NCC environment" >&2; exit 1; }
case "$HOME" in */ncc-ai-*) ;; *) echo "not a private home: $HOME" >&2; exit 1;; esac
[ "$CLAUDE_CODE_OAUTH_TOKEN" = "sk-ant-oat01-abcdefghijklmnopqrstuvwxyz" ] || { echo "no token" >&2; exit 1; }
[ "$1" = "-p" ] || { echo "not headless" >&2; exit 1; }
grep -q "GOAL:" || { echo "no prompt" >&2; exit 1; }
echo '{"summary":"from the model","steps":[]}'
`)
	t.Setenv("NCC_HOME", "/should-not-leak")
	if err := s.Save(ctx, Settings{Kind: KindClaude, Enabled: true, Binary: bin}); err != nil {
		t.Fatal(err)
	}
	k, _ := KindByID(KindClaude)
	if _, err := s.Ask(ctx, KindClaude, "hi"); err == nil || !strings.Contains(err.Error(), "not signed in") {
		t.Fatalf("unsigned: %v", err)
	}
	if err := s.SavePasted(ctx, k, "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"); err == nil {
		t.Fatal("API key accepted")
	}
	if err := s.SavePasted(ctx, k, "Your token: sk-ant-oat01-abcdefghijklmnopqrstuvwxyz\n"); err != nil {
		t.Fatal(err)
	}
	plan, err := s.MakePlan(ctx, BuildPicture(office()), KindClaude, "keep it simple", "derek")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Source != "ai" || plan.Summary != "from the model" || plan.AIError != "" || len(plan.Steps) != 0 {
		t.Fatalf("plan: %+v", plan)
	}
	got, err := s.LoadPlan(ctx, plan.ID)
	if err != nil || got.Summary != "from the model" {
		t.Fatalf("load: %+v %v", got, err)
	}
	st, _ := s.Get(ctx, KindClaude)
	if st.LastUsed == nil || st.LastError != "" {
		t.Fatalf("settings: %+v", st)
	}
}

func TestAskFallsBackToRules(t *testing.T) {
	s := newService(t)
	ctx := context.Background()
	bin := tool(t, `echo "Sorry, I can't do that."`)
	s.Save(ctx, Settings{Kind: KindClaude, Enabled: true, Binary: bin})
	k, _ := KindByID(KindClaude)
	s.SavePasted(ctx, k, "sk-ant-oat01-abcdefghijklmnopqrstuvwxyz")
	plan, err := s.MakePlan(ctx, BuildPicture(office()), KindClaude, "", "derek")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Source != "rules" || !strings.Contains(plan.AIError, "no JSON plan") || len(plan.Steps) != 8 {
		t.Fatalf("plan: %s %q %d", plan.Source, plan.AIError, len(plan.Steps))
	}
}

func TestAskKeepsRefreshedSignIn(t *testing.T) {
	s := newService(t)
	ctx := context.Background()
	// Codex keeps its sign-in in $CODEX_HOME/auth.json and refreshes it as it runs
	bin := tool(t, `
grep -q old "$CODEX_HOME/auth.json" || { echo "sign-in not restored" >&2; exit 1; }
[ "$1" = "exec" ] || exit 1
echo '{"tokens":"new"}' > "$CODEX_HOME/auth.json"
cat >/dev/null
echo 'OK'
`)
	s.Save(ctx, Settings{Kind: KindCodex, Enabled: true, Binary: bin})
	k, _ := KindByID(KindCodex)
	if err := s.SavePasted(ctx, k, `{"tokens":"old"}`); err != nil {
		t.Fatal(err)
	}
	if ans, err := s.Ask(ctx, KindCodex, "hi"); err != nil || ans != "OK" {
		t.Fatalf("%q %v", ans, err)
	}
	sec, _ := s.Vault.Get(ctx, SecretPath(KindCodex))
	b, _ := base64.StdEncoding.DecodeString(sec["file:.codex/auth.json"])
	if !strings.Contains(string(b), "new") {
		t.Fatalf("refreshed sign-in not kept: %s", b)
	}
	// no private homes are left behind
	if left, _ := filepath.Glob(filepath.Join(s.TempDir, "ncc-ai-*")); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
}

func TestSignIn(t *testing.T) {
	s := newService(t)
	ctx := context.Background()
	bin := tool(t, `
[ "$1" = "setup-token" ] || exit 1
echo "Browser didn't open? Use the url below to sign in:"
echo "https://claude.ai/oauth/authorize?code=true"
printf "Paste code here if prompted > "
read code
[ "$code" = "abc123" ] || { echo "wrong code"; exit 1; }
echo "Your OAuth token (valid for 1 year):"
echo "sk-ant-oat01-ZYXWVUTSRQPONMLKJIHGFEDCBA0123456789"
`)
	s.Save(ctx, Settings{Kind: KindClaude, Binary: bin})
	m := &SignIns{Service: s}
	v, err := m.Start(KindClaude)
	if err != nil {
		t.Fatal(err)
	}
	wait := func(cond func(SignInView) bool) SignInView {
		deadline := time.Now().Add(10 * time.Second)
		for {
			v, err := m.View(v.ID)
			if err != nil {
				t.Fatal(err)
			}
			if cond(v) || time.Now().After(deadline) {
				return v
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	v = wait(func(v SignInView) bool { return strings.Contains(v.Output, "Paste code") })
	if !strings.Contains(v.Output, "https://claude.ai/oauth/authorize") {
		t.Fatalf("output: %q", v.Output)
	}
	if _, err := m.Input(v.ID, "abc123"); err != nil {
		t.Fatal(err)
	}
	v = wait(func(v SignInView) bool { return v.State != SignInRunning })
	if v.State != SignInConnected {
		t.Fatalf("state %s: %s\n%s", v.State, v.Error, v.Output)
	}
	if strings.Contains(v.Output, "0123456789") || !strings.Contains(v.Output, "saved in the vault") {
		t.Fatalf("token shown to the browser: %q", v.Output)
	}
	sec, err := s.Vault.Get(ctx, SecretPath(KindClaude))
	if err != nil || sec["env:CLAUDE_CODE_OAUTH_TOKEN"] != "sk-ant-oat01-ZYXWVUTSRQPONMLKJIHGFEDCBA0123456789" {
		t.Fatalf("vault: %v %v", sec, err)
	}
	st, _ := s.Get(ctx, KindClaude)
	if !st.Enabled || st.ConnectedAt == nil {
		t.Fatalf("settings: %+v", st)
	}
}

func TestStripANSI(t *testing.T) {
	if got := stripANSI("\x1b[1;32mOpen\x1b[0m https://x\r\n\x1b]0;title\x07done"); got != "Open https://x\ndone" {
		t.Fatalf("%q", got)
	}
}
