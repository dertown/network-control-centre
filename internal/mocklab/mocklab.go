// Package mocklab emulates a small UniFi network and a PowerDNS server so NCC can be
// tested and demonstrated without touching a real network.
package mocklab

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "embed"
)

// StatDevice is a recorded UniFi stat/device response: a Dream Router 7, two U6 Pro access
// points, a UniFi switch, a switch with an unknown model code and a third-party LLDP switch.
//
//go:embed stat_device.json
var StatDevice []byte

// StatSta is a recorded UniFi stat/sta (clients) response.
//
//go:embed stat_sta.json
var StatSta []byte

// StatStaDPI is a recorded UniFi stat/stadpi (per-client DPI, by application) response.
//
//go:embed stat_stadpi.json
var StatStaDPI []byte

// StatSiteDPI is a recorded UniFi stat/sitedpi (site DPI, by category) response.
//
//go:embed stat_sitedpi.json
var StatSiteDPI []byte

// RestNetworkConf, RestPortConf and RestWLANConf are recorded rest/networkconf,
// rest/portconf and rest/wlanconf responses: a Default LAN, Guest (VLAN 20), IoT (VLAN 30),
// DMZ (VLAN 50) and a WAN, a trunk and a DMZ port profile, and four SSIDs (one open guest
// network, a WPA2 IoT one with TKIP and a short passphrase, and a hidden WPA1 "Smart-Plugs").
//
//go:embed rest_networkconf.json
var RestNetworkConf []byte

//go:embed rest_portconf.json
var RestPortConf []byte

//go:embed rest_wlanconf.json
var RestWLANConf []byte

// StatRogueAP is a stat/rogueap response: the neighbours' Wi-Fi networks the Lounge AP and
// the Dream Router hear, crowded on 2.4 GHz channel 6.
//
//go:embed stat_rogueap.json
var StatRogueAP []byte

// FirewallZones is a recorded v2 firewall/zone response (zone-based firewall), with the
// DMZ network in the DMZ zone and IoT in a custom zone.
//
//go:embed firewall_zone.json
var FirewallZones []byte

// FirewallPolicies is a recorded v2 firewall-policies response (zone-based firewall): four
// policies the admin made, one of them off, and three of the console's built-in ones.
//
//go:embed firewall_policies.json
var FirewallPolicies []byte

// RestFirewallGroup, RestFirewallRule and RestPortForward are recorded rest/firewallgroup,
// rest/firewallrule (empty: the console uses zone-based firewall) and rest/portforward
// responses: a port group and two address groups, and four port forwards, one of them off.
//
//go:embed rest_firewallgroup.json
var RestFirewallGroup []byte

//go:embed rest_firewallrule.json
var RestFirewallRule []byte

//go:embed rest_portforward.json
var RestPortForward []byte

// TrafficV2 is a recorded UniFi Network 9+ v2 traffic API response (per-client
// application usage). A console with this API answers the legacy DPI calls with no rows.
//
//go:embed traffic_v2.json
var TrafficV2 []byte

// UniFi returns a handler that behaves like a UniFi OS console for the API NCC uses.
// It accepts username "ncc" with password "demo-password", or API key "demo-key", with full
// rights, and username "viewer" with password "demo-password" as a View Only account that
// may read but not change anything.
func UniFi() http.Handler { return unifi(false) }

// UniFiLab is a pretend UniFi console that remembers changes.
type UniFiLab struct {
	http.Handler
	state *uState
}

// NewUniFi returns a pretend UniFi console whose changes can be inspected.
func NewUniFi() *UniFiLab {
	h, st := unifiWithState(false, false)
	return &UniFiLab{Handler: h, state: st}
}

// Writes returns every change request the console received, as "METHOD path body".
func (u *UniFiLab) Writes() []string { return u.state.Writes() }

// IgnoreOverride makes the access points ignore a Virtual Network Override for this Wi-Fi
// client, as happens with a private (random) Wi-Fi address: when it rejoins it is back on its
// Wi-Fi network's VLAN.
func (u *UniFiLab) IgnoreOverride(mac string) {
	u.state.mu.Lock()
	defer u.state.mu.Unlock()
	if u.state.noOverride == nil {
		u.state.noOverride = map[string]bool{}
	}
	u.state.noOverride[strings.ToLower(mac)] = true
}

// UniFiWithLoops is UniFi with two switching loops cabled in: Rack switch ports 14 and 15
// are patched to each other (nothing blocks it), and a second cable from Dream Router port 2
// to Mystery switch port 2 closes a ring that spanning tree is holding shut. The event log
// has the matching loop-protection event.
func UniFiWithLoops() http.Handler { return unifi(true) }

// LoopDevices returns StatDevice with the loops of UniFiWithLoops cabled in.
func LoopDevices() []byte {
	var env struct {
		Meta any              `json:"meta"`
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(StatDevice, &env); err != nil {
		panic(err)
	}
	port := func(idx int, stp string) map[string]any {
		return map[string]any{"port_idx": idx, "name": "Port " + itoa(idx), "up": true, "speed": 1000, "stp_state": stp}
	}
	lldp := func(local int, chassis, portID string) map[string]any {
		return map[string]any{"chassis_id": chassis, "port_id": portID, "local_port_idx": local, "is_wired": true}
	}
	add := func(d map[string]any, key string, v ...map[string]any) {
		list, _ := d[key].([]any)
		for _, x := range v {
			list = append(list, x)
		}
		d[key] = list
	}
	for _, d := range env.Data {
		switch strings.ToLower(d["mac"].(string)) {
		case "aa:bb:cc:00:00:01": // Dream Router 7: port 2 cabled to Mystery switch port 2
			add(d, "lldp_table", lldp(2, "aa:bb:cc:00:00:05", "Port 2"))
		case "aa:bb:cc:00:00:04": // Rack switch: port 14 patched into port 15
			add(d, "port_table", port(14, "forwarding"), port(15, "forwarding"))
			add(d, "lldp_table", lldp(14, "aa:bb:cc:00:00:04", "Port 15"), lldp(15, "aa:bb:cc:00:00:04", "Port 14"))
		case "aa:bb:cc:00:00:05": // Mystery switch: STP blocks the extra cable on port 2
			add(d, "port_table", port(1, "forwarding"), port(2, "blocking"))
			add(d, "lldp_table", lldp(2, "aa:bb:cc:00:00:01", "eth2"))
		}
	}
	b, err := json.Marshal(env)
	if err != nil {
		panic(err)
	}
	return b
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

// loopEvents is a stat/event response with a loop-protection event on Rack switch port 14.
func loopEvents() []byte {
	ms := time.Now().Add(-10 * time.Minute).UnixMilli()
	return []byte(`{"meta":{"rc":"ok"},"data":[{"key":"EVT_SW_DetectedLoop","sw":"aa:bb:cc:00:00:04","sw_name":"Rack switch",` +
		`"port":14,"time":` + strconv.FormatInt(ms, 10) + `,"msg":"Switch[Rack switch] detected a network loop on port 14 and disabled it"}]}`)
}

func unifi(loops bool) http.Handler {
	h, _ := unifiWithState(loops, false)
	return h
}

// UniFiOffice is UniFi with an office's IoT devices on it as well: IP cameras and an NVR,
// a printer, desk and conference phones, a meeting-room system, signage, a door controller,
// a UPS, a building controller and an air quality sensor. Some sit on the IoT network and
// some on the main LAN.
func UniFiOffice() http.Handler {
	h, _ := unifiWithState(false, true)
	return h
}

// OfficeClients are the extra clients of UniFiOffice, in stat/sta form.
var OfficeClients = []map[string]any{
	officeClient("00:40:8c:10:00:01", "cam-lobby-01", "Axis Communications AB", "192.168.30.31", "net_iot", 9, ""),
	officeClient("00:40:8c:10:00:02", "cam-loading-dock", "Axis Communications AB", "192.168.30.32", "net_iot", 10, ""),
	officeClient("00:09:18:10:00:03", "cam-carpark-02", "Hanwha Vision", "192.168.1.153", "net_default", 11, ""),
	officeClient("44:19:b6:10:00:04", "nvr-01", "Hangzhou Hikvision Digital Technology", "192.168.30.10", "net_iot", 13, ""),
	officeClient("a0:b3:cc:10:00:05", "hp-printer-2f", "HP Inc.", "192.168.1.155", "net_default", 14, ""),
	officeClient("64:16:7f:10:00:06", "phone-reception", "Polycom", "192.168.1.156", "net_default", 15, ""),
	officeClient("80:5e:c0:10:00:07", "yealink-boardroom", "Yealink Network Technology", "192.168.30.41", "net_iot", 16, ""),
	officeClient("00:10:7f:10:00:08", "boardroom-cp4", "Crestron Electronics", "192.168.30.42", "net_iot", 3, ""),
	officeClient("90:ac:3f:10:00:09", "lobby-signage", "BrightSign LLC", "192.168.30.51", "net_iot", 6, ""),
	officeClient("00:06:8e:10:00:0a", "door-main-entrance", "HID Global", "192.168.30.61", "net_iot", 8, ""),
	officeClient("00:c0:b7:10:00:0b", "ups-server-room", "American Power Conversion", "192.168.1.161", "net_default", 1, ""),
	officeClient("00:1b:c5:10:00:0c", "bms-jace-01", "Tridium Inc", "192.168.30.71", "net_iot", 12, ""),
	officeClient("e0:e5:cf:10:00:0d", "airq-3f-east", "Airthings ASA", "192.168.1.163", "net_default", 0, "aa:bb:cc:00:00:02"),
}

func officeClient(mac, host, oui, ip, network string, port int, ap string) map[string]any {
	c := map[string]any{"mac": mac, "hostname": host, "oui": oui, "ip": ip, "network_id": network, "uptime": 86000,
		"tx_bytes": 1048576, "rx_bytes": 524288}
	if ap != "" {
		c["is_wired"], c["ap_mac"], c["essid"] = false, ap, "Office"
	} else {
		c["is_wired"], c["sw_mac"], c["sw_port"] = true, "aa:bb:cc:00:00:04", port
	}
	return c
}

// UniFiHomelab is UniFi with the mock Proxmox cluster's machines plugged in: host pve1 and
// three of its guests share Rack switch port 9, and host pve2 with two guests shares Mystery
// switch port 3. The router can only see several MACs on one port, so it draws each as an
// unmanaged switch; NCC's topology works out from the Proxmox connection that they are hosts.
func UniFiHomelab() http.Handler {
	h, _ := unifiWithClients(false, HomelabClients)
	return h
}

// HomelabClients are the extra clients of UniFiHomelab, in stat/sta form. The guests' MACs
// are the ones the mock Proxmox gives them (BC:24:11:00 + VM id).
var HomelabClients = []map[string]any{
	labClient("58:47:ca:70:00:01", "pve1", "Intel Corporate", "192.168.1.12", "aa:bb:cc:00:00:04", 9),
	labClient("bc:24:11:00:00:64", "ncc", "", "192.168.1.247", "aa:bb:cc:00:00:04", 9),
	labClient("bc:24:11:00:00:65", "home-assistant", "", "192.168.1.110", "aa:bb:cc:00:00:04", 9),
	labClient("bc:24:11:00:00:c8", "pihole", "", "192.168.1.53", "aa:bb:cc:00:00:04", 9),
	labClient("58:47:ca:70:00:02", "pve2", "Intel Corporate", "192.168.1.13", "aa:bb:cc:00:00:05", 3),
	labClient("bc:24:11:00:00:66", "DESKTOP-7Q2K1", "", "192.168.1.120", "aa:bb:cc:00:00:05", 3),
	labClient("bc:24:11:00:00:c9", "unifi-backup", "", "192.168.1.62", "aa:bb:cc:00:00:05", 3),
}

func labClient(mac, host, oui, ip, sw string, port int) map[string]any {
	c := map[string]any{"mac": mac, "hostname": host, "ip": ip, "network_id": "net_default", "uptime": 86000,
		"tx_bytes": 1048576, "rx_bytes": 524288, "is_wired": true, "sw_mac": sw, "sw_port": port}
	if oui != "" {
		c["oui"] = oui
	}
	return c
}

func unifiWithState(loops, office bool) (http.Handler, *uState) {
	var extra []map[string]any
	if office {
		extra = OfficeClients
	}
	return unifiWithClients(loops, extra)
}

func unifiWithClients(loops bool, extra []map[string]any) (http.Handler, *uState) {
	devices := StatDevice
	if loops {
		devices = LoopDevices()
	}
	st := newUState(devices)
	for _, c := range extra {
		cp := map[string]any{}
		for k, v := range c {
			cp[k] = v
		}
		st.clients = append(st.clients, cp)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		if (in["username"] != "ncc" && in["username"] != "viewer") || in["password"] != "demo-password" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		token := "demo"
		if in["username"] == "viewer" {
			token = "viewer"
		}
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: token, Path: "/", HttpOnly: true})
		w.Header().Set("X-Csrf-Token", "demo-csrf")
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("POST /api/auth/logout", func(w http.ResponseWriter, r *http.Request) {})
	ok := func(r *http.Request) bool {
		if r.Header.Get("X-API-KEY") == "demo-key" {
			return true
		}
		c, err := r.Cookie("TOKEN")
		return err == nil && (c.Value == "demo" || c.Value == "viewer")
	}
	// canWrite is false for the View Only account, like a real console
	canWrite := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !ok(r) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if c, err := r.Cookie("TOKEN"); err == nil && c.Value == "viewer" {
				apiErr(w, http.StatusForbidden, "api.err.NoPermission")
				return
			}
			if r.Header.Get("X-API-KEY") == "" && r.Header.Get("X-CSRF-Token") != "demo-csrf" {
				apiErr(w, http.StatusForbidden, "api.err.InvalidCSRF")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			h(w, r)
		}
	}
	serve := func(b []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !ok(r) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(b)
		}
	}
	dyn := func(sel func(*uState) []map[string]any) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { serve(st.list(sel))(w, r) }
	}
	mux.HandleFunc("GET /proxy/network/api/self/sites", serve([]byte(`{"meta":{"rc":"ok"},"data":[{"name":"default","desc":"Home"}]}`)))
	events := []byte(`{"meta":{"rc":"ok"},"data":[]}`)
	mux.HandleFunc("GET /proxy/network/api/s/default/stat/device", dyn(func(s *uState) []map[string]any { return s.devices }))
	mux.HandleFunc("GET /proxy/network/api/s/default/stat/alarm", serve([]byte(`{"meta":{"rc":"ok"},"data":[]}`)))
	mux.HandleFunc("GET /proxy/network/api/s/default/stat/event", func(w http.ResponseWriter, r *http.Request) {
		if loops {
			serve(loopEvents())(w, r)
			return
		}
		serve(events)(w, r)
	})
	mux.HandleFunc("GET /proxy/network/api/s/default/stat/rogueap", serve(StatRogueAP))
	mux.HandleFunc("GET /proxy/network/api/s/default/stat/sta", dyn(func(s *uState) []map[string]any { return s.clients }))
	// Like a Network 9+ console: application data comes from the v2 traffic API and the
	// legacy DPI calls answer "ok" with no rows.
	mux.HandleFunc("GET /proxy/network/v2/api/site/default/traffic", serve(TrafficV2))
	mux.HandleFunc("POST /proxy/network/api/s/default/stat/stadpi", serve([]byte(`{"meta":{"rc":"ok"},"data":[]}`)))
	mux.HandleFunc("POST /proxy/network/api/s/default/stat/sitedpi", serve([]byte(`{"meta":{"rc":"ok"},"data":[]}`)))
	mux.HandleFunc("GET /proxy/network/api/s/default/rest/networkconf", dyn(func(s *uState) []map[string]any { return s.networks }))
	mux.HandleFunc("POST /proxy/network/api/s/default/rest/networkconf", canWrite(st.createNetwork))
	mux.HandleFunc("PUT /proxy/network/api/s/default/rest/networkconf/{id}", canWrite(st.updateNetwork))
	mux.HandleFunc("PUT /proxy/network/api/s/default/rest/device/{id}", canWrite(st.updateDevice))
	mux.HandleFunc("GET /proxy/network/api/s/default/stat/user/{mac}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		st.getUser(w, r)
	})
	mux.HandleFunc("PUT /proxy/network/api/s/default/rest/user/{id}", canWrite(st.updateUser))
	mux.HandleFunc("GET /proxy/network/api/s/default/rest/user", dyn(func(s *uState) []map[string]any { return s.allUsers() }))
	mux.HandleFunc("POST /proxy/network/api/s/default/cmd/{mgr}", canWrite(st.command))
	mux.HandleFunc("GET /proxy/network/api/s/default/rest/portconf", serve(RestPortConf))
	mux.HandleFunc("GET /proxy/network/api/s/default/rest/wlanconf", dyn(func(s *uState) []map[string]any { return s.wlans }))
	mux.HandleFunc("PUT /proxy/network/api/s/default/rest/wlanconf/{id}", canWrite(st.updateWLAN))
	mux.HandleFunc("GET /proxy/network/v2/api/site/default/firewall/zone", serve(FirewallZones))
	mux.HandleFunc("GET /proxy/network/v2/api/site/default/firewall-policies", serve(FirewallPolicies))
	mux.HandleFunc("GET /proxy/network/api/s/default/rest/firewallgroup", serve(RestFirewallGroup))
	mux.HandleFunc("GET /proxy/network/api/s/default/rest/firewallrule", serve(RestFirewallRule))
	mux.HandleFunc("GET /proxy/network/api/s/default/rest/portforward", serve(RestPortForward))
	return mux, st
}

// PowerDNS is an in-memory PowerDNS Authoritative API with home.lan. and 1.168.192.in-addr.arpa.
type PowerDNS struct {
	APIKey string
	mu     sync.Mutex
	zones  map[string]map[string]rrset // zone -> "name|type" -> rrset
	// Patches records every PATCH body received, per zone.
	Patches map[string][]json.RawMessage
}

type record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type rrset struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	TTL        int      `json:"ttl"`
	ChangeType string   `json:"changetype,omitempty"`
	Records    []record `json:"records"`
}

// NewPowerDNS returns a server seeded with a couple of records.
func NewPowerDNS(apiKey string) *PowerDNS {
	p := &PowerDNS{APIKey: apiKey, zones: map[string]map[string]rrset{}, Patches: map[string][]json.RawMessage{}}
	add := func(zone, name, typ string, ttl int, vals ...string) {
		if p.zones[zone] == nil {
			p.zones[zone] = map[string]rrset{}
		}
		rs := rrset{Name: name, Type: typ, TTL: ttl}
		for _, v := range vals {
			rs.Records = append(rs.Records, record{Content: v})
		}
		p.zones[zone][name+"|"+typ] = rs
	}
	add("home.lan.", "home.lan.", "SOA", 3600, "ns1.home.lan. hostmaster.home.lan. 1 10800 3600 604800 3600")
	add("home.lan.", "home.lan.", "NS", 3600, "ns1.home.lan.")
	add("home.lan.", "ns1.home.lan.", "A", 3600, "192.168.1.10")
	add("home.lan.", "router.home.lan.", "A", 3600, "192.168.1.1")
	add("home.lan.", "old.home.lan.", "A", 300, "192.168.1.9")
	add("home.lan.", "pve1.home.lan.", "A", 3600, "192.168.1.12")
	add("home.lan.", "pve2.home.lan.", "A", 3600, "192.168.1.13")
	add("1.168.192.in-addr.arpa.", "1.168.192.in-addr.arpa.", "SOA", 3600, "ns1.home.lan. hostmaster.home.lan. 1 10800 3600 604800 3600")
	add("1.168.192.in-addr.arpa.", "1.1.168.192.in-addr.arpa.", "PTR", 3600, "router.home.lan.")
	add("1.168.192.in-addr.arpa.", "12.1.168.192.in-addr.arpa.", "PTR", 3600, "pve1.home.lan.")
	return p
}

// ServeHTTP implements the subset of /api/v1/servers/localhost NCC uses.
func (p *PowerDNS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("X-API-Key") != p.APIKey {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
		return
	}
	const base = "/api/v1/servers/localhost/zones"
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.URL.Path == "/api/v1/servers/localhost" && r.Method == http.MethodGet {
		_, _ = w.Write([]byte(`{"type":"Server","id":"localhost","daemon_type":"authoritative","version":"4.9.0-mock"}`))
		return
	}
	if r.URL.Path == base && r.Method == http.MethodGet {
		var out []map[string]any
		names := make([]string, 0, len(p.zones))
		for z := range p.zones {
			names = append(names, z)
		}
		sort.Strings(names)
		for _, z := range names {
			out = append(out, map[string]any{"id": z, "name": z, "kind": "Native", "serial": 1})
		}
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	if r.URL.Path == base && r.Method == http.MethodPost {
		var in struct {
			Name        string   `json:"name"`
			Kind        string   `json:"kind"`
			Nameservers []string `json:"nameservers"`
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &in); err != nil || !strings.HasSuffix(in.Name, ".") {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"error":"bad zone"}`))
			return
		}
		if _, dup := p.zones[in.Name]; dup {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"Domain '` + in.Name + `' already exists"}`))
			return
		}
		ns := in.Nameservers
		first := "ns1." + in.Name
		if len(ns) > 0 {
			first = ns[0]
		}
		z := map[string]rrset{in.Name + "|SOA": {Name: in.Name, Type: "SOA", TTL: 3600,
			Records: []record{{Content: first + " hostmaster." + in.Name + " 1 10800 3600 604800 3600"}}}}
		if len(ns) > 0 {
			rs := rrset{Name: in.Name, Type: "NS", TTL: 3600}
			for _, n := range ns {
				rs.Records = append(rs.Records, record{Content: n})
			}
			z[in.Name+"|NS"] = rs
		}
		p.zones[in.Name] = z
		p.Patches[in.Name] = append(p.Patches[in.Name], raw)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"` + in.Name + `","name":"` + in.Name + `"}`))
		return
	}
	zone := strings.TrimPrefix(r.URL.Path, base+"/")
	z, ok := p.zones[zone]
	if !ok || zone == r.URL.Path {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"Could not find domain"}`))
		return
	}
	switch r.Method {
	case http.MethodGet:
		var sets []rrset
		for _, rs := range z {
			sets = append(sets, rs)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": zone, "name": zone, "rrsets": sets})
	case http.MethodPatch:
		raw, _ := io.ReadAll(r.Body)
		var body struct {
			RRSets []rrset `json:"rrsets"`
		}
		if err := json.Unmarshal(raw, &body); err != nil || len(body.RRSets) == 0 {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"error":"bad request body"}`))
			return
		}
		for _, rs := range body.RRSets {
			if !strings.HasSuffix(rs.Name, ".") || (rs.Name != zone && !strings.HasSuffix(rs.Name, "."+zone)) {
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = w.Write([]byte(`{"error":"RRset ` + rs.Name + ` is out of zone"}`))
				return
			}
		}
		for _, rs := range body.RRSets {
			key := rs.Name + "|" + rs.Type
			if rs.ChangeType == "DELETE" {
				delete(z, key)
				continue
			}
			rs.ChangeType = ""
			z[key] = rs
		}
		p.Patches[zone] = append(p.Patches[zone], raw)
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		delete(p.zones, zone)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// Recursor is a pretend PowerDNS Recursor API: the server object and its zones, including
// the "." forward zone that sends internet queries upstream.
type Recursor struct {
	APIKey string
	// Forwarders are the upstream servers of the "." zone ("ip:port"); none means the
	// recursor resolves from the root servers itself.
	Forwarders []string
	// NoRecurse makes "." a forward-zones entry (no recursion desired) instead of
	// forward-zones-recurse.
	NoRecurse bool
}

// NewRecursor returns a recursor that forwards internet queries to the mock ISP's DNS
// servers, 203.0.113.53 and 203.0.113.54 (what the mock Dream Router reports on its WAN).
func NewRecursor(apiKey string) *Recursor {
	return &Recursor{APIKey: apiKey, Forwarders: []string{"203.0.113.53:53", "203.0.113.54:53"}}
}

// ServeHTTP implements the subset of the Recursor API NCC uses.
func (rc *Recursor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("X-API-Key") != rc.APIKey {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
		return
	}
	switch r.URL.Path {
	case "/api/v1/servers/localhost":
		_, _ = w.Write([]byte(`{"type":"Server","id":"localhost","daemon_type":"recursor","version":"5.1.0-mock"}`))
	case "/api/v1/servers/localhost/zones":
		zones := []map[string]any{
			{"id": "home.lan.", "name": "home.lan.", "kind": "Forwarded", "servers": []string{"192.168.1.10:5300"}, "recursion_desired": false},
		}
		if len(rc.Forwarders) > 0 {
			zones = append(zones, map[string]any{"id": ".", "name": ".", "kind": "Forwarded", "servers": rc.Forwarders, "recursion_desired": !rc.NoRecurse})
		}
		_ = json.NewEncoder(w).Encode(zones)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"Not Found"}`))
	}
}
