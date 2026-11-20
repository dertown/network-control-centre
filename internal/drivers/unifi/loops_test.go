package unifi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	inv "github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/mocklab"
)

const (
	gw = "aa:00:00:00:00:01"
	sA = "aa:00:00:00:00:0a"
	sB = "aa:00:00:00:00:0b"
	sC = "aa:00:00:00:00:0c"
)

func dev(mac, name, typ string, ports ...rawPort) rawDevice {
	return rawDevice{MAC: mac, Name: name, Type: typ, State: 1, PortTable: ports}
}

func port(idx int, stp string) rawPort {
	return rawPort{PortIdx: idx, Name: "Port " + itoa(idx), Up: true, Speed: 1000, StpState: stp}
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func uplink(d *rawDevice, to string, remote, local int) {
	d.Uplink = rawUplink{UplinkMAC: to, UplinkRemotePort: remote, PortIdx: local, Type: "wire", Speed: 1000}
}

func lldp(d *rawDevice, local int, chassis, portID string) {
	d.LLDPTable = append(d.LLDPTable, rawLLDP{ChassisID: chassis, PortID: portID, LocalPortIdx: local})
}

func detect(t *testing.T, devs []rawDevice, events ...rawEvent) []inv.Loop {
	t.Helper()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	snap := Build("home", devs, nil, nil, now)
	return DetectLoops("home", devs, events, snap, now)
}

func portSet(l inv.Loop) string {
	var s []string
	for _, p := range l.Ports {
		s = append(s, p.DeviceName+":"+itoa(p.Port))
	}
	return strings.Join(s, ",")
}

// baseline: gateway, switch A on gateway port 1, switch B on A port 8, with LLDP both ways.
func baseline() []rawDevice {
	g := dev(gw, "Router", "udm", port(1, ""), port(2, ""), port(3, ""))
	a := dev(sA, "Switch A", "usw", port(1, "forwarding"), port(3, "forwarding"), port(4, "forwarding"), port(5, "forwarding"), port(6, "forwarding"), port(8, "forwarding"))
	b := dev(sB, "Switch B", "usw", port(1, "forwarding"), port(2, "forwarding"), port(3, "forwarding"))
	uplink(&a, gw, 1, 1)
	uplink(&b, sA, 8, 1)
	lldp(&g, 1, sA, "Port 1")
	lldp(&a, 1, gw, "eth1")
	lldp(&a, 8, sB, "Port 1")
	lldp(&b, 1, sA, "Port 8")
	return []rawDevice{g, a, b}
}

func TestNoLoopsInRecordedNetwork(t *testing.T) {
	if l := detect(t, load[rawDevice](t, "stat_device.json")); len(l) != 0 {
		t.Fatalf("recorded network has no loops, got %+v", l)
	}
	if l := detect(t, baseline()); len(l) != 0 {
		t.Fatalf("tree network has no loops, got %+v", l)
	}
}

func TestSelfLoopBetweenTwoPorts(t *testing.T) {
	devs := baseline()
	lldp(&devs[1], 5, sA, "Port 6")
	lldp(&devs[1], 6, sA, "Port 5")
	loops := detect(t, devs)
	if len(loops) != 1 {
		t.Fatalf("want 1 loop, got %+v", loops)
	}
	l := loops[0]
	if l.Kind != inv.LoopSelf || l.Severity != inv.LoopCritical || portSet(l) != "Switch A:5,Switch A:6" {
		t.Fatalf("got %s %s %s: %s", l.Kind, l.Severity, portSet(l), l.Summary)
	}
	if !strings.Contains(l.Summary, "Port 5 and Port 6") || len(l.Links) != 1 || l.Links[0].A != sA || l.Links[0].B != sA {
		t.Fatalf("summary/links: %q %+v", l.Summary, l.Links)
	}
}

func TestSelfLoopWithUnreadablePortIDs(t *testing.T) {
	devs := baseline()
	// some firmware reports the far port as a MAC address
	lldp(&devs[1], 3, sA, "aa:00:00:00:00:0a")
	lldp(&devs[1], 4, sA, "aa:00:00:00:00:0a")
	loops := detect(t, devs)
	if len(loops) != 1 || loops[0].Kind != inv.LoopSelf || portSet(loops[0]) != "Switch A:3,Switch A:4" {
		t.Fatalf("got %+v", loops)
	}
}

func TestRingContainedBySTP(t *testing.T) {
	devs := baseline()
	// an extra cable from Router port 2 to Switch B port 2; STP blocks Switch B port 2
	devs[2].PortTable[1].StpState = "blocking"
	lldp(&devs[0], 2, sB, "Port 2")
	lldp(&devs[2], 2, gw, "eth2")
	loops := detect(t, devs)
	if len(loops) != 1 {
		t.Fatalf("want 1 loop, got %+v", loops)
	}
	l := loops[0]
	if l.Kind != inv.LoopCycle || l.Severity != inv.LoopWarning {
		t.Fatalf("got %s %s: %s", l.Kind, l.Severity, l.Summary)
	}
	for _, want := range []string{"Router:1", "Switch A:1", "Switch A:8", "Switch B:1", "Switch B:2", "Router:2"} {
		if !strings.Contains(portSet(l)+",", want+",") {
			t.Errorf("ring ports %s miss %s", portSet(l), want)
		}
	}
	if len(l.Links) != 3 || !strings.Contains(l.Detail, "Port 2 on Switch B") {
		t.Errorf("links %d, detail %q", len(l.Links), l.Detail)
	}
}

func TestParallelLinksBetweenSwitches(t *testing.T) {
	devs := baseline()
	// a second cable from Switch A port 3 to Switch B port 3, nothing blocked
	lldp(&devs[1], 3, sB, "Port 3")
	lldp(&devs[2], 3, sA, "Port 3")
	loops := detect(t, devs)
	if len(loops) != 1 || loops[0].Severity != inv.LoopCritical {
		t.Fatalf("got %+v", loops)
	}
	if ps := portSet(loops[0]); !strings.Contains(ps, "Switch A:3") || !strings.Contains(ps, "Switch B:3") {
		t.Fatalf("ports %s", ps)
	}

	// the same with far ports NCC cannot read: one segment, Switch A has two ports in it
	devs = baseline()
	devs[2].LLDPTable = nil
	devs[1].LLDPTable = devs[1].LLDPTable[:1]
	lldp(&devs[1], 3, sB, "?")
	lldp(&devs[1], 4, sB, "?")
	lldp(&devs[1], 8, sB, "?")
	loops = detect(t, devs)
	if len(loops) != 1 || loops[0].Kind != inv.LoopParallel || !strings.HasPrefix(loops[0].Summary, "Switch A: Port 3, Port 4 and Port 8 all lead to Switch B") {
		t.Fatalf("got %+v", loops)
	}
}

func TestLAGIsNotALoop(t *testing.T) {
	devs := baseline()
	devs[1].PortTable[1].OpMode, devs[1].PortTable[2].OpMode = "aggregate", "aggregate"
	devs[1].PortTable[2].AggregatedBy = 3
	devs[2].PortTable[1].OpMode, devs[2].PortTable[2].OpMode = "aggregate", "aggregate"
	devs[2].PortTable[2].AggregatedBy = 2
	lldp(&devs[1], 3, sB, "Port 2")
	lldp(&devs[1], 4, sB, "Port 3")
	lldp(&devs[2], 2, sA, "Port 3")
	lldp(&devs[2], 3, sA, "Port 4")
	// the LAG replaces the port 8 cable
	devs[1].LLDPTable = append(devs[1].LLDPTable[:1], devs[1].LLDPTable[2:]...)
	devs[2].LLDPTable = devs[2].LLDPTable[1:]
	uplink(&devs[2], sA, 3, 2)
	if loops := detect(t, devs); len(loops) != 0 {
		t.Fatalf("LAG flagged as loop: %+v", loops)
	}
}

func TestUnmanagedSwitchPassingLLDPIsNotALoop(t *testing.T) {
	// Switch A port 5 feeds a dumb switch with Switch B and Switch C behind it; the dumb
	// switch passes LLDP, so all three hear each other on one port each.
	devs := baseline()[:2]
	devs[1].LLDPTable = devs[1].LLDPTable[:1]
	b := dev(sB, "Switch B", "usw", port(1, "forwarding"))
	c := dev(sC, "Switch C", "usw", port(1, "forwarding"))
	uplink(&b, sA, 5, 1)
	uplink(&c, sA, 5, 1)
	lldp(&devs[1], 5, sB, "Port 1")
	lldp(&devs[1], 5, sC, "Port 1")
	lldp(&b, 1, sA, "Port 5")
	lldp(&b, 1, sC, "Port 1")
	lldp(&c, 1, sA, "Port 5")
	lldp(&c, 1, sB, "Port 1")
	devs = append(devs, b, c)
	if loops := detect(t, devs); len(loops) != 0 {
		t.Fatalf("shared segment flagged as loop: %+v", loops)
	}
}

func TestUnexplainedSTPBlock(t *testing.T) {
	devs := baseline()
	devs[1].PortTable[3].StpState = "discarding" // port 5, nothing visible on it
	loops := detect(t, devs)
	if len(loops) != 1 || loops[0].Kind != inv.LoopSTP || portSet(loops[0]) != "Switch A:5" || loops[0].Severity != inv.LoopWarning {
		t.Fatalf("got %+v", loops)
	}
}

func TestLoopEvents(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	devs := baseline()
	evs := []rawEvent{
		{Key: "EVT_SW_DetectedLoop", Msg: "Switch[aa:00:00:00:00:0b] detected a loop on port 3", Sw: sB, Time: now.Add(-time.Hour).UnixMilli()},
		{Key: "EVT_SW_DetectedLoop", Msg: "Switch[aa:00:00:00:00:0b] detected a loop on port 3", Sw: sB, Time: now.Add(-30 * time.Minute).UnixMilli()},
		{Key: "EVT_SW_StpPortBlocking", Msg: "Switch A STP port blocking on port 6", Sw: sA, Port: 6, Time: now.Add(-2 * time.Hour).UnixMilli()},
		{Key: "EVT_SW_DetectedLoop", Msg: "old loop", Sw: sB, Port: 2, Time: now.Add(-48 * time.Hour).UnixMilli()},
		{Key: "EVT_AP_Connected", Msg: "AP connected", Time: now.UnixMilli()},
	}
	loops := DetectLoops("home", devs, evs, Build("home", devs, nil, nil, now), now)
	if len(loops) != 2 {
		t.Fatalf("want 2 event findings, got %+v", loops)
	}
	l := loops[0]
	if l.Severity != inv.LoopCritical || l.Count != 2 || portSet(l) != "Switch B:3" || l.Summary != "UniFi detected a loop on Switch B Port 3" {
		t.Fatalf("loop event: %+v", l)
	}
	if !l.SeenAt.Equal(now.Add(-30 * time.Minute)) {
		t.Errorf("seen at %v", l.SeenAt)
	}
	if loops[1].Severity != inv.LoopWarning || portSet(loops[1]) != "Switch A:6" {
		t.Errorf("stp event: %+v", loops[1])
	}
}

func TestLooseEventsFromSystemLog(t *testing.T) {
	raw := json.RawMessage(`{"data":[{"key":"SWITCH_LOOP_DETECTED","message":"Loop detected on Port 7",
		"timestamp":1763640000000,"parameters":{"DEVICE":{"id":"AA-00-00-00-00-0A","name":"Switch A"},"PORT":{"id":"7","name":"Port 7"}}},
		{"key":"CLIENT_CONNECTED","message":"phone joined"}]}`)
	evs := looseEvents(raw)
	if len(evs) != 2 || evs[0].Sw != "AA-00-00-00-00-0A" || evs[0].Port != 7 || evs[0].Time != 1763640000000 {
		t.Fatalf("got %+v", evs)
	}
	if k, crit := loopEventKind(evs[0]); k != "loop" || !crit {
		t.Fatalf("kind %q %v", k, crit)
	}
}

func TestMockLabLoops(t *testing.T) {
	var env envelope[rawDevice]
	if err := json.Unmarshal(mocklab.LoopDevices(), &env); err != nil {
		t.Fatal(err)
	}
	loops := detect(t, env.Data, rawEvent{Key: "EVT_SW_DetectedLoop", Msg: "loop on port 14", Sw: "aa:bb:cc:00:00:04", Port: 14})
	if len(loops) != 2 {
		t.Fatalf("want 2 loops, got %+v", loops)
	}
	if loops[0].Kind != inv.LoopSelf || portSet(loops[0]) != "Rack switch:14,Rack switch:15" || loops[0].Severity != inv.LoopCritical {
		t.Errorf("self loop: %s %s %s", loops[0].Kind, portSet(loops[0]), loops[0].Severity)
	}
	if loops[0].Count != 1 || !strings.Contains(loops[0].Detail, "UniFi also logged") {
		t.Errorf("event not merged into the self loop: %+v", loops[0])
	}
	if loops[1].Kind != inv.LoopCycle || loops[1].Severity != inv.LoopWarning {
		t.Errorf("ring: %s %s %s", loops[1].Kind, loops[1].Severity, loops[1].Summary)
	}
	t.Log(loops[1].Summary, "|", loops[1].Detail)
}
