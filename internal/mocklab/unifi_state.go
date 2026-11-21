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
	devices  []map[string]any
	clients  []map[string]any
	users    map[string]map[string]any // by MAC
	nextID   int
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
	s := &uState{networks: dataOf(RestNetworkConf), devices: dataOf(devices), clients: dataOf(StatSta), users: map[string]map[string]any{}}
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

// readdress gives a client an address in its new network, keeping the last number.
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

func (s *uState) updateDevice(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PortOverrides []map[string]any `json:"port_overrides"`
	}
	raw, _ := readAll(r)
	if err := json.Unmarshal(raw, &in); err != nil || in.PortOverrides == nil {
		apiErr(w, 400, "api.err.InvalidPayload")
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
		native := str(o["native_networkconf_id"])
		if native == "" || s.network(native) == nil {
			continue
		}
		for _, c := range s.clients {
			sw, _ := c["sw_port"].(float64)
			if strings.EqualFold(str(c["sw_mac"]), str(dev["mac"])) && sw == idx && c["is_wired"] == true {
				s.readdress(c, native)
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

func (s *uState) command(w http.ResponseWriter, r *http.Request) {
	raw, _ := readAll(r)
	s.mu.Lock()
	s.writes = append(s.writes, "POST cmd/"+r.PathValue("mgr")+" "+string(raw))
	s.mu.Unlock()
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
