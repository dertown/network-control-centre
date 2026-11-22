package api_test

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/iot"
	"github.com/dertown/network-control-centre/internal/mocklab"
)

type iotView struct {
	Devices  []iot.Device `json:"devices"`
	Networks []struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		IoT       bool   `json:"iot"`
		Suggested bool   `json:"suggested"`
		Devices   int    `json:"devices"`
	} `json:"networks"`
	Chosen     bool `json:"networks_chosen"`
	Candidates []struct {
		MAC     string `json:"mac"`
		Name    string `json:"name"`
		Ignored bool   `json:"ignored"`
	} `json:"candidates"`
}

func (v iotView) dev(name string) *iot.Device {
	for i := range v.Devices {
		if v.Devices[i].Name == name || v.Devices[i].Hostname == name {
			return &v.Devices[i]
		}
	}
	return nil
}

func hasIssue(d *iot.Device, issue string) bool {
	for _, x := range d.Issues {
		if x == issue {
			return true
		}
	}
	return false
}

func TestIoTInventory(t *testing.T) {
	ncc, _ := newNCC(t)
	defer ncc.Close()
	unifi := httptest.NewTLSServer(mocklab.UniFiOffice())
	defer unifi.Close()
	ha := httptest.NewServer(mocklab.HomeAssistant("tok"))
	defer ha.Close()

	jar, _ := cookiejar.New(nil)
	c := &client{t: t, base: ncc.URL, hc: &http.Client{Jar: jar}}
	c.do("POST", "/api/setup", map[string]string{"username": "derek", "password": "a-long-password", "vault_passphrase": "vault passphrase 1"}, nil)
	var login struct {
		CSRF string `json:"csrf"`
	}
	c.do("POST", "/api/login", map[string]string{"username": "derek", "password": "a-long-password"}, &login)
	c.csrf = login.CSRF

	var tg, hub core.Target
	if code := c.do("POST", "/api/targets", map[string]any{"kind": "unifi", "category": "device", "name": "office", "address": unifi.URL,
		"credentials": map[string]string{"username": "ncc", "password": "demo-password"}}, &tg); code != 201 {
		t.Fatalf("create unifi: %d", code)
	}
	if code := c.do("POST", "/api/targets", map[string]any{"kind": "homeassistant", "category": "smarthome", "name": "home", "address": ha.URL,
		"credentials": map[string]string{"token": "tok"}}, &hub); code != 201 {
		t.Fatalf("create ha: %d", code)
	}
	var v iotView
	for i := 0; i < 100; i++ {
		c.do("POST", "/api/targets/"+itoa(tg.ID)+"/poll", nil, nil)
		c.do("POST", "/api/targets/"+itoa(hub.ID)+"/poll", nil, nil)
		v = iotView{}
		c.do("GET", "/api/iot", nil, &v)
		if d := v.dev("thermostat"); len(v.Devices) > 0 && d != nil && d.Firmware != "" {
			break
		}
	}
	// home clients that look like IoT, plus the office's 13
	for _, name := range []string{"Printer", "tv", "thermostat", "kitchen-plug", "lounge-speaker", "doorbell", "Hall lights", "garage-cam",
		"cam-lobby-01", "nvr-01", "hp-printer-2f", "phone-reception", "boardroom-cp4", "door-main-entrance", "ups-server-room", "bms-jace-01", "airq-3f-east"} {
		if v.dev(name) == nil {
			t.Errorf("%s not in the inventory", name)
		}
	}
	for _, name := range []string{"phone", "laptop", "desk-pc", "nas", "guest-laptop"} {
		if v.dev(name) != nil {
			t.Errorf("%s should not be in the inventory", name)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	if v.Chosen || len(v.Networks) == 0 {
		t.Fatalf("networks: %+v", v.Networks)
	}
	for _, n := range v.Networks {
		if n.IoT != (n.Name == "IoT") {
			t.Fatalf("network %s iot=%v", n.Name, n.IoT)
		}
	}
	cam := v.dev("cam-lobby-01")
	if cam.Type != iot.TypeCamera || cam.Network != "IoT" || cam.Uplink != "Rack switch port 9" || hasIssue(cam, iot.IssueWrongNetwork) || !cam.Online {
		t.Fatalf("camera: %+v", cam)
	}
	ups := v.dev("ups-server-room")
	if ups.Type != iot.TypePower || !hasIssue(ups, iot.IssueWrongNetwork) {
		t.Fatalf("ups: %+v", ups)
	}
	if th := v.dev("thermostat"); th.Firmware != "4.2.6" || th.Model != "Google Nest Learning Thermostat (4th gen)" {
		t.Fatalf("thermostat: %+v", th)
	}

	// record where the UPS is and who owns it, and allow it on the main LAN
	if code := c.do("PUT", "/api/iot/devices", map[string]any{"macs": []string{ups.MAC}, "site": "HQ", "building": "Main", "floor": "B1",
		"room": "Server room", "owner": "IT", "network_ok": true, "network_ok_reason": "needs the management LAN"}, nil); code != 200 {
		t.Fatalf("update: %d", code)
	}
	if code := c.do("PUT", "/api/iot/devices", map[string]any{"macs": []string{ups.MAC}}, nil); code != 400 {
		t.Fatalf("empty update: %d", code)
	}
	// the TV is a meeting-room display: not IoT for this office
	if code := c.do("PUT", "/api/iot/devices", map[string]any{"macs": []string{v.dev("tv").MAC}, "ignored": true}, nil); code != 200 {
		t.Fatalf("ignore: %d", code)
	}
	// choose the networks: IoT and DMZ
	if code := c.do("PUT", "/api/iot/networks", map[string]any{"ids": []string{"net_iot", "net_dmz"}}, nil); code != 200 {
		t.Fatalf("networks: %d", code)
	}
	// add the desk PC by hand (a kiosk, say)
	if code := c.do("POST", "/api/iot/devices", map[string]any{"mac": "DE-AD-00-00-00-05", "type": "display"}, nil); code != 200 {
		t.Fatalf("add: %d", code)
	}
	if code := c.do("POST", "/api/iot/devices", map[string]any{"mac": "02:00:00:00:99:99"}, nil); code != 404 {
		t.Fatalf("add unknown: %d", code)
	}
	v = iotView{}
	c.do("GET", "/api/iot", nil, &v)
	ups = v.dev("ups-server-room")
	if ups.Site != "HQ" || ups.Room != "Server room" || ups.Owner != "IT" || hasIssue(ups, iot.IssueWrongNetwork) || hasIssue(ups, iot.IssueNoLocation) || ups.UpdatedBy != "derek" {
		t.Fatalf("ups after update: %+v", ups)
	}
	if tv := v.dev("tv"); !tv.Ignored || len(tv.Issues) != 0 {
		t.Fatalf("tv: %+v", tv)
	}
	if pc := v.dev("desk-pc"); pc == nil || pc.Type != iot.TypeDisplay {
		t.Fatalf("desk-pc: %+v", pc)
	}
	if !v.Chosen {
		t.Fatal("networks not chosen")
	}
	ignoredListed := false
	for _, cd := range v.Candidates {
		if cd.Name == "desk-pc" {
			t.Fatal("desk-pc still a candidate")
		}
		ignoredListed = ignoredListed || cd.Name == "tv" && cd.Ignored
	}
	if !ignoredListed {
		t.Fatal("ignored tv should be offered again")
	}

	// a viewer can look but not change anything
	c.do("POST", "/api/users", map[string]string{"username": "viv", "password": "another-long-password", "role": "viewer"}, nil)
	jar2, _ := cookiejar.New(nil)
	viewer := &client{t: t, base: ncc.URL, hc: &http.Client{Jar: jar2}}
	viewer.do("POST", "/api/login", map[string]string{"username": "viv", "password": "another-long-password"}, &login)
	viewer.csrf = login.CSRF
	if code := viewer.do("GET", "/api/iot", nil, nil); code != 200 {
		t.Fatalf("viewer read: %d", code)
	}
	if code := viewer.do("PUT", "/api/iot/devices", map[string]any{"macs": []string{ups.MAC}, "owner": "me"}, nil); code != 403 {
		t.Fatalf("viewer update: %d", code)
	}
	if code := c.do("DELETE", "/api/iot/devices/"+ups.MAC, nil, nil); code != 200 {
		t.Fatalf("delete: %d", code)
	}
}
