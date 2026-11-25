package mocklab

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
)

// uState is the changeable part of the pretend UniFi console: networks, device port
// overrides and per-client settings. Changes show up in what the console reports, as on a
// real console: a client moved to another network gets an address there.
type uState struct {
	mu       sync.Mutex
	networks []map[string]any
	wlans    []map[string]any
	devices  []map[string]any
	clients  []map[string]any
	users    map[string]map[string]any // by MAC
	down     map[string]bool           // switch ports switched off, "mac#port"
	// noOverride lists Wi-Fi clients (by MAC) whose access point ignores a Virtual Network
	// Override: when they rejoin they land back on their Wi-Fi network's VLAN.
	noOverride map[string]bool
	nextID     int
	// Writes records every change request, for tests: "METHOD path body".
	writes []string
}

func dataOf(b []byte) []map[string]any {
	var env struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		panic(err)
	}
	return env.Data
}

func newUState(devices []byte) *uState {
	s := &uState{networks: dataOf(RestNetworkConf), wlans: dataOf(RestWLANConf), devices: dataOf(devices), clients: dataOf(StatSta), users: map[string]map[string]any{}, down: map[string]bool{}}
	for _, d := range s.devices {
		if str(d["_id"]) == "" {
			d["_id"] = "dev_" + strings.ReplaceAll(strings.ToLower(str(d["mac"])), ":", "")
		}
	}
	return s
}

func envelope(data any) []byte {
	b, _ := json.Marshal(map[string]any{"meta": map[string]string{"rc": "ok"}, "data": data})
	return b
}

func apiErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	b, _ := json.Marshal(map[string]any{"meta": map[string]string{"rc": "error", "msg": msg}, "data": []any{}})
	_, _ = w.Write(b)
}

func (s *uState) list(sel func(*uState) []map[string]any) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return envelope(sel(s))
}

func str(v any) string { x, _ := v.(string); return x }

func vlanOf(n map[string]any) int {
	switch v := n["vlan"].(type) {
	case float64:
		return int(v)
	case string:
		var i int
		fmt.Sscanf(v, "%d", &i)
		return i
	}
	return 0
}

func (s *uState) network(id string) map[string]any {
	for _, n := range s.networks {
		if str(n["_id"]) == id {
			return n
		}
	}
	return nil
}

// readdress puts a client in a network. Like a real device, it keeps its old address until
// it reconnects (renew).
func (s *uState) readdress(c map[string]any, netID string) {
	n := s.network(netID)
	if n == nil {
		return
	}
	c["network_id"], c["network"] = netID, n["name"]
	if v := vlanOf(n); v > 0 && n["vlan_enabled"] == true {
		c["vlan"] = v
	} else {
		delete(c, "vlan")
	}
}

// renew is a client asking DHCP again: it gets its fixed IP, or an address in its network
// keeping the last number.
func (s *uState) renew(c map[string]any) {
	n := s.network(str(c["network_id"]))
	if n == nil {
		return
	}
	if u, ok := s.users[strings.ToLower(str(c["mac"]))]; ok && u["use_fixedip"] == true && str(u["network_id"]) == str(c["network_id"]) {
		c["ip"] = u["fixed_ip"]
		return
	}
	p, err := netip.ParsePrefix(str(n["ip_subnet"]))
	old, err2 := netip.ParseAddr(str(c["ip"]))
	if err != nil || err2 != nil || !p.Addr().Is4() {
		return
	}
	a, o := p.Masked().Addr().As4(), old.As4()
	a[3] = o[3]
	c["ip"] = netip.AddrFrom4(a).String()
}

func (s *uState) createNetwork(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, 400, "api.err.InvalidPayload")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, _ := json.Marshal(in)
	s.writes = append(s.writes, "POST rest/networkconf "+string(raw))
	for _, n := range s.networks {
		if strings.EqualFold(str(n["name"]), str(in["name"])) {
			apiErr(w, 400, "api.err.DuplicateName")
			return
		}
		if in["vlan_enabled"] == true && n["vlan_enabled"] == true && vlanOf(n) == vlanOf(in) {
			apiErr(w, 400, "api.err.VlanUsed")
			return
		}
	}
	s.nextID++
	in["_id"] = fmt.Sprintf("net_new%d", s.nextID)
	s.networks = append(s.networks, in)
	_, _ = w.Write(envelope([]any{in}))
}

// updateNetwork is a PUT of a whole network object, as UniFi expects.
func (s *uState) updateNetwork(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, 400, "api.err.InvalidPayload")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.network(r.PathValue("id"))
	if n == nil {
		apiErr(w, 400, "api.err.NetworkNotFound")
		return
	}
	s.writes = append(s.writes, "PUT rest/networkconf/"+r.PathValue("id")+" domain_name="+str(in["domain_name"]))
	for k, v := range in {
		if k != "_id" {
			n[k] = v
		}
	}
	_, _ = w.Write(envelope([]any{n}))
}

// updateWLAN is a PUT of a whole WLAN object. Clients on the SSID follow a change of name
// or network, as they would by rejoining. The passphrase is never recorded in Writes.
func (s *uState) updateWLAN(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, 400, "api.err.InvalidPayload")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var wl map[string]any
	for _, x := range s.wlans {
		if str(x["_id"]) == r.PathValue("id") {
			wl = x
		}
	}
	if wl == nil {
		apiErr(w, 400, "api.err.WlanNotFound")
		return
	}
	if p, ok := in["x_passphrase"].(string); ok && in["security"] == "wpapsk" && len(p) < 8 {
		apiErr(w, 400, "api.err.InvalidPassphrase")
		return
	}
	var changed []string
	for k, v := range in {
		if k == "_id" {
			continue
		}
		old, _ := json.Marshal(wl[k])
		nw, _ := json.Marshal(v)
		if string(old) != string(nw) {
			changed = append(changed, k)
		}
	}
	sortStrings(changed)
	s.writes = append(s.writes, "PUT rest/wlanconf/"+r.PathValue("id")+" "+strings.Join(changed, ","))
	oldName, oldNet := str(wl["name"]), str(wl["networkconf_id"])
	for k := range wl {
		if _, ok := in[k]; !ok && k != "_id" {
			delete(wl, k)
		}
	}
	for k, v := range in {
		if k != "_id" {
			wl[k] = v
		}
	}
	for _, c := range s.clients {
		if c["is_wired"] == true || str(c["essid"]) != oldName {
			continue
		}
		c["essid"] = wl["name"]
		if n := str(wl["networkconf_id"]); n != oldNet && n != "" {
			s.readdress(c, n)
			s.renew(c)
		}
	}
	_, _ = w.Write(envelope([]any{wl}))
}

func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

func (s *uState) updateDevice(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PortOverrides []map[string]any `json:"port_overrides"`
		RadioTable    []map[string]any `json:"radio_table"`
		WLANOverrides []map[string]any `json:"wlan_overrides"`
	}
	raw, _ := readAll(r)
	if err := json.Unmarshal(raw, &in); err != nil || (in.PortOverrides == nil && in.RadioTable == nil && in.WLANOverrides == nil) {
		apiErr(w, 400, "api.err.InvalidPayload")
		return
	}
	if in.PortOverrides == nil {
		s.updateRadios(w, r, raw, in.RadioTable, in.WLANOverrides)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes = append(s.writes, "PUT rest/device/"+r.PathValue("id")+" "+string(raw))
	var dev map[string]any
	for _, d := range s.devices {
		if str(d["_id"]) == r.PathValue("id") {
			dev = d
		}
	}
	if dev == nil {
		apiErr(w, 400, "api.err.UnknownDevice")
		return
	}
	list := make([]any, len(in.PortOverrides))
	for i, o := range in.PortOverrides {
		list[i] = o
		idx, _ := o["port_idx"].(float64)
		key := fmt.Sprintf("%s#%d", strings.ToLower(str(dev["mac"])), int(idx))
		if str(o["forward"]) == "disabled" {
			s.down[key] = true
			continue
		}
		wasDown := s.down[key]
		delete(s.down, key)
		native := str(o["native_networkconf_id"])
		for _, c := range s.portClients(str(dev["mac"]), int(idx)) {
			if native != "" && s.network(native) != nil {
				s.readdress(c, native)
			}
			if wasDown { // the link came back: the device asks for an address again
				s.renew(c)
			}
		}
	}
	dev["port_overrides"] = list
	_, _ = w.Write(envelope([]any{}))
}

func (s *uState) user(mac string) map[string]any {
	mac = strings.ToLower(mac)
	if u, ok := s.users[mac]; ok {
		return u
	}
	for _, c := range s.clients {
		if strings.EqualFold(str(c["mac"]), mac) {
			u := map[string]any{"_id": "user_" + strings.ReplaceAll(mac, ":", ""), "mac": mac}
			if mac == "de:ad:00:00:00:01" { // the NAS has a fixed IP
				u["use_fixedip"], u["fixed_ip"], u["network_id"] = true, "192.168.1.50", "net_default"
			}
			s.users[mac] = u
			return u
		}
	}
	return nil
}

func (s *uState) getUser(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.user(r.PathValue("mac"))
	if u == nil {
		apiErr(w, 400, "api.err.UnknownUser")
		return
	}
	_, _ = w.Write(envelope([]any{u}))
}

func (s *uState) updateUser(w http.ResponseWriter, r *http.Request) {
	raw, _ := readAll(r)
	var in map[string]any
	if err := json.Unmarshal(raw, &in); err != nil {
		apiErr(w, 400, "api.err.InvalidPayload")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes = append(s.writes, "PUT rest/user/"+r.PathValue("id")+" "+string(raw))
	var u map[string]any
	for mac := range s.users {
		if str(s.users[mac]["_id"]) == r.PathValue("id") {
			u = s.users[mac]
		}
	}
	if u == nil {
		apiErr(w, 400, "api.err.UnknownUser")
		return
	}
	for k, v := range in {
		u[k] = v
	}
	if u["virtual_network_override_enabled"] == true {
		for _, c := range s.clients {
			if strings.EqualFold(str(c["mac"]), str(u["mac"])) && c["is_wired"] != true {
				s.readdress(c, str(u["virtual_network_override_id"]))
			}
		}
	}
	_, _ = w.Write(envelope([]any{u}))
}

func (s *uState) portClients(swMAC string, idx int) []map[string]any {
	var out []map[string]any
	for _, c := range s.clients {
		sw, _ := c["sw_port"].(float64)
		if strings.EqualFold(str(c["sw_mac"]), swMAC) && int(sw) == idx && c["is_wired"] == true {
			out = append(out, c)
		}
	}
	return out
}

func (s *uState) command(w http.ResponseWriter, r *http.Request) {
	raw, _ := readAll(r)
	var in map[string]any
	_ = json.Unmarshal(raw, &in)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes = append(s.writes, "POST cmd/"+r.PathValue("mgr")+" "+string(raw))
	switch str(in["cmd"]) {
	case "kick-sta": // the client rejoins and asks for an address
		for _, c := range s.clients {
			if strings.EqualFold(str(c["mac"]), str(in["mac"])) {
				if s.noOverride[strings.ToLower(str(c["mac"]))] {
					for _, w := range s.wlans {
						if str(w["name"]) == str(c["essid"]) {
							s.readdress(c, str(w["networkconf_id"]))
						}
					}
				}
				s.renew(c)
			}
		}
	case "power-cycle":
		idx, _ := in["port_idx"].(float64)
		for _, c := range s.portClients(str(in["mac"]), int(idx)) {
			s.renew(c)
		}
	}
	_, _ = w.Write(envelope([]any{}))
}

func readAll(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	return io.ReadAll(io.LimitReader(r.Body, 1<<20))
}

// Writes returns every change request the console received, as "METHOD path body".
func (s *uState) Writes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.writes...)
}

// allUsers is rest/user: every client's saved record.
func (s *uState) allUsers() []map[string]any {
	var out []map[string]any
	for _, c := range s.clients {
		if u := s.user(str(c["mac"])); u != nil {
			out = append(out, u)
		}
	}
	return out
}

// updateRadios changes an access point's radio settings and per-AP Wi-Fi overrides. A radio
// moved to a fixed channel reports it straight away, with the channel use measured afresh.
func (s *uState) updateRadios(w http.ResponseWriter, r *http.Request, raw []byte, table, overrides []map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes = append(s.writes, "PUT rest/device/"+r.PathValue("id")+" "+string(raw))
	var dev map[string]any
	for _, d := range s.devices {
		if str(d["_id"]) == r.PathValue("id") {
			dev = d
		}
	}
	if dev == nil {
		apiErr(w, 400, "api.err.UnknownDevice")
		return
	}
	if table != nil {
		for _, rt := range table {
			switch v := rt["channel"].(type) {
			case string:
				if v != "auto" {
					apiErr(w, 400, "api.err.InvalidChannel")
					return
				}
			case float64:
				if v < 1 || v > 233 {
					apiErr(w, 400, "api.err.InvalidChannel")
					return
				}
			}
		}
		old := map[string]map[string]any{}
		if list, ok := dev["radio_table"].([]any); ok {
			for _, x := range list {
				if m, ok := x.(map[string]any); ok {
					old[str(m["name"])] = m
				}
			}
		}
		list := make([]any, len(table))
		for i, rt := range table {
			list[i] = rt
			if stats, ok := dev["radio_table_stats"].([]any); ok {
				for _, x := range stats {
					st, ok := x.(map[string]any)
					if !ok || str(st["name"]) != str(rt["name"]) {
						continue
					}
					if ch, ok := rt["channel"].(float64); ok {
						if prev, _ := old[str(rt["name"])]["channel"].(float64); prev != ch {
							st["channel"] = ch
							st["cu_total"] = 14
						}
					}
				}
			}
		}
		dev["radio_table"] = list
	}
	if overrides != nil {
		list := make([]any, len(overrides))
		for i, o := range overrides {
			list[i] = o
		}
		dev["wlan_overrides"] = list
	}
	_, _ = w.Write(envelope([]any{}))
}
