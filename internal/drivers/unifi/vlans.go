package unifi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/drivers"
	inv "github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/vault"
)

// Writing VLAN configuration.
//
// Creating a network is a POST to rest/networkconf.
//
// A client is put in another network one of two ways:
//   - Wired: the switch port it is cabled to gets the new network as its untagged (native)
//     network, through a per-port override on the switch (PUT rest/device/{id} with the
//     whole port_overrides list). Everything on that port moves, so the caller plans which
//     clients share it. A port profile on the port is replaced by the same settings set on the
//     port itself, with the new native network.
//   - Wireless: UniFi's per-client "Virtual Network Override" (PUT rest/user/{id}). The client
//     stays on the same Wi-Fi name and password, which matters for IoT devices that are a pain
//     to set up again, and the access point tags its traffic with the new VLAN.
//
// A fixed IP address reserved in the old network would no longer fit, so it is cleared.
//
// Writes need a UniFi account whose Network role can change settings. A View Only account
// can log in and read, but the console refuses every change with 401 or 403.

var _ drivers.NetworkWriter = Driver{}

// ErrReadOnly means the console refused a change because the account may only view.
var ErrReadOnly = errors.New("unifi: the account NCC uses may only view settings")

type permError struct{ err error }

func (e *permError) Error() string {
	what := "the change"
	var ae *authError
	if errors.As(e.err, &ae) {
		what = fmt.Sprintf("%s %s (HTTP %d)", ae.method, ae.path, ae.code)
	} else if e.err != nil {
		what = e.err.Error()
	}
	return "unifi: the console refused " + what + ": the account NCC uses can only view settings. " +
		"In UniFi OS open Admins & Users, edit that account and give it a UniFi Network role that can change settings " +
		"(Site Admin or Full Management), then try again"
}
func (e *permError) Is(t error) bool { return t == ErrReadOnly || t == ErrUnauthorized }
func (e *permError) Unwrap() error   { return e.err }

// writeSession logs in afresh for a change and logs out after. Changes are rare, and a
// separate session keeps them apart from the polling session.
func (d Driver) writeSession(ctx context.Context, t drivers.Target, creds vault.Secret, fn func(c *client) error) error {
	c, err := d.open(ctx, t, creds)
	if err != nil {
		return err
	}
	defer c.logout(ctx)
	c.resolveSite(ctx)
	return asPerm(fn(c))
}

// asPerm turns a refusal after a successful login into a permission error.
func asPerm(err error) error {
	var ae *authError
	var pe *permError
	if errors.As(err, &ae) && !ae.login && !errors.As(err, &pe) {
		return &permError{err: err}
	}
	return err
}

// write sends a change and checks UniFi's {"meta":{"rc":"ok"}} answer. out may be nil.
func write[T any](ctx context.Context, c *client, method, p string, body any) ([]T, error) {
	var env envelope[T]
	if err := c.req(ctx, method, c.apiPath(p), body, &env); err != nil {
		return nil, err
	}
	if env.Meta.RC != "" && env.Meta.RC != "ok" {
		if strings.Contains(env.Meta.Msg, "NoPermission") || strings.Contains(env.Meta.Msg, "Unauthorized") {
			return nil, &permError{err: fmt.Errorf("%s %s: %s", method, p, env.Meta.Msg)}
		}
		return nil, fmt.Errorf("unifi: %s %s: %s", method, p, friendlyMsg(env.Meta.Msg))
	}
	return env.Data, nil
}

// friendlyMsg turns UniFi's api.err.* codes into words.
func friendlyMsg(m string) string {
	known := map[string]string{
		"api.err.VlanUsed":            "that VLAN ID is already used by another network",
		"api.err.DuplicateName":       "a network with that name already exists",
		"api.err.NameAlreadyExists":   "a network with that name already exists",
		"api.err.IpSubnetConflict":    "that subnet overlaps another network",
		"api.err.InvalidPayload":      "the console did not accept the settings (invalid payload)",
		"api.err.InvalidVlan":         "the VLAN ID is not valid",
		"api.err.NetworkNotFound":     "the network no longer exists",
		"api.err.UnknownUser":         "the console does not know that client",
		"api.err.DhcpRangeOutOfRange": "the DHCP range is outside the subnet",
	}
	for k, v := range known {
		if strings.Contains(m, k) {
			return v + " (" + m + ")"
		}
	}
	return m
}

// CreateNetwork implements drivers.NetworkWriter.
func (d Driver) CreateNetwork(ctx context.Context, t drivers.Target, creds vault.Secret, spec drivers.NetworkSpec) (string, error) {
	var id string
	err := d.writeSession(ctx, t, creds, func(c *client) error {
		nets, err := getList[rawNetwork](ctx, c, "rest/networkconf")
		if err != nil {
			return err
		}
		for _, n := range nets {
			if strings.EqualFold(strings.TrimSpace(n.Name), spec.Name) {
				return fmt.Errorf("unifi: a network named %q already exists", n.Name)
			}
			if n.VLANEnabled && int(n.VLAN) == spec.VLAN {
				return fmt.Errorf("unifi: VLAN %d is already used by %q", spec.VLAN, n.Name)
			}
		}
		out, err := write[rawNetwork](ctx, c, http.MethodPost, "rest/networkconf", networkBody(spec))
		if err != nil {
			return err
		}
		if len(out) > 0 {
			id = out[0].ID
		}
		if id == "" {
			// some versions answer with an empty list: find it by name
			nets, err := getList[rawNetwork](ctx, c, "rest/networkconf")
			if err != nil {
				return err
			}
			for _, n := range nets {
				if n.Name == spec.Name {
					id = n.ID
				}
			}
		}
		return nil
	})
	return id, err
}

// networkBody is the rest/networkconf body for a new network.
func networkBody(s drivers.NetworkSpec) map[string]any {
	b := map[string]any{
		"name":          s.Name,
		"enabled":       true,
		"networkgroup":  "LAN",
		"vlan_enabled":  true,
		"vlan":          s.VLAN,
		"igmp_snooping": false,
	}
	if s.Mode == "vlan-only" {
		b["purpose"] = "vlan-only"
		return b
	}
	b["purpose"] = "corporate"
	b["ip_subnet"] = s.Gateway
	b["is_nat"] = true
	b["network_isolation_enabled"] = s.Isolated
	b["internet_access_enabled"] = s.InternetAccess
	b["dhcpd_enabled"] = s.DHCP
	b["dhcpd_dns_enabled"] = false
	b["dhcpd_gateway_enabled"] = false
	b["dhcpd_time_offset_enabled"] = false
	b["dhcp_relay_enabled"] = false
	b["ipv6_interface_type"] = "none"
	if s.DHCP {
		b["dhcpd_start"] = s.DHCPStart
		b["dhcpd_stop"] = s.DHCPStop
		b["dhcpd_leasetime"] = 86400
	}
	return b
}

// rawDeviceConf is the part of a device the port write needs. Port overrides are kept as raw
// maps so settings NCC does not know about survive the round trip.
type rawDeviceConf struct {
	ID            string           `json:"_id"`
	MAC           string           `json:"mac"`
	Name          string           `json:"name"`
	PortTable     []rawPort        `json:"port_table"`
	PortOverrides []map[string]any `json:"port_overrides"`
}

type rawUser struct {
	ID         string `json:"_id"`
	MAC        string `json:"mac"`
	UseFixedIP bool   `json:"use_fixedip"`
	FixedIP    string `json:"fixed_ip"`
	NetworkID  string `json:"network_id"`
}

// MoveClients implements drivers.NetworkWriter.
func (d Driver) MoveClients(ctx context.Context, t drivers.Target, creds vault.Secret, networkID string, moves []drivers.ClientMove, reconnect bool) ([]drivers.MoveResult, error) {
	results := make([]drivers.MoveResult, len(moves))
	for i, m := range moves {
		results[i] = drivers.MoveResult{MAC: inv.NormMAC(m.MAC), Name: m.Name}
	}
	err := d.writeSession(ctx, t, creds, func(c *client) error {
		nets, err := getList[rawNetwork](ctx, c, "rest/networkconf")
		if err != nil {
			return err
		}
		var target *rawNetwork
		for i := range nets {
			if nets[i].ID == networkID {
				target = &nets[i]
			}
		}
		if target == nil {
			return fmt.Errorf("unifi: network %s no longer exists; refresh and try again", networkID)
		}
		if target.Purpose == "wan" || strings.Contains(target.Purpose, "vpn") {
			return fmt.Errorf("unifi: clients cannot be put in %s (%s)", target.Name, target.Purpose)
		}
		profiles, _ := getList[rawPortConf](ctx, c, "rest/portconf")

		// wired: group port changes per switch, one write each
		bySwitch := map[string][]int{}
		var order []string
		for i, m := range moves {
			if m.Method != drivers.MovePort {
				continue
			}
			sw := inv.NormMAC(m.SwitchMAC)
			if _, ok := bySwitch[sw]; !ok {
				order = append(order, sw)
			}
			bySwitch[sw] = append(bySwitch[sw], i)
		}
		if len(order) > 0 {
			devs, err := getList[rawDeviceConf](ctx, c, "stat/device")
			if err != nil {
				return err
			}
			for _, sw := range order {
				idx := bySwitch[sw]
				var dev *rawDeviceConf
				for i := range devs {
					if inv.NormMAC(devs[i].MAC) == sw {
						dev = &devs[i]
					}
				}
				if dev == nil || dev.ID == "" {
					for _, i := range idx {
						results[i].Error = "the switch is no longer adopted by this console"
					}
					continue
				}
				ports := map[int]bool{}
				for _, i := range idx {
					ports[moves[i].SwitchPort] = true
				}
				notes, err := setNativeNetwork(ctx, c, dev, ports, networkID, profiles)
				err = asPerm(err)
				for _, i := range idx {
					if err != nil {
						results[i].Error = err.Error()
						continue
					}
					results[i].OK = true
					results[i].Notes = append(results[i].Notes, notes[moves[i].SwitchPort]...)
				}
				if errors.Is(err, ErrReadOnly) {
					return err
				}
			}
		}

		// a fixed IP reserved in the old network would no longer fit: it is moved into the new
		// subnet (same last number when that is free), or dropped when it can't be
		fixed := newFixedIPs(ctx, c, target)

		// wireless (and anything else moved per client)
		for i, m := range moves {
			if m.Method != drivers.MoveClient {
				if m.Method != drivers.MovePort {
					results[i].Error = "unknown way to move this client: " + m.Method
				}
				continue
			}
			notes, err := overrideClient(ctx, c, results[i].MAC, networkID, fixed)
			err = asPerm(err)
			if err != nil {
				results[i].Error = err.Error()
				if errors.Is(err, ErrReadOnly) {
					return err
				}
				continue
			}
			results[i].OK, results[i].Notes = true, notes
		}
		for i, m := range moves {
			if m.Method == drivers.MovePort && results[i].OK {
				if note, err := rehomeFixedIP(ctx, c, results[i].MAC, fixed); err != nil {
					results[i].Notes = append(results[i].Notes, "could not update its fixed IP: "+err.Error())
				} else if note != "" {
					results[i].Notes = append(results[i].Notes, note)
				}
			}
		}
		if reconnect {
			var done []drivers.ClientMove
			var idx []int
			for i, m := range moves {
				if results[i].OK {
					done, idx = append(done, m), append(idx, i)
				}
			}
			notes := reconnectWith(ctx, c, done)
			for j, i := range idx {
				results[i].Notes = append(results[i].Notes, notes[j])
			}
		}
		return nil
	})
	if err != nil {
		for i := range results {
			if !results[i].OK && results[i].Error == "" {
				results[i].Error = err.Error()
			}
		}
	}
	return results, err
}

// setNativeNetwork makes networkID the untagged network of the given ports of dev. It returns
// notes per port.
func setNativeNetwork(ctx context.Context, c *client, dev *rawDeviceConf, ports map[int]bool, networkID string, profiles []rawPortConf) (map[int][]string, error) {
	notes := map[int][]string{}
	profByID := map[string]rawPortConf{}
	for _, p := range profiles {
		profByID[p.ID] = p
	}
	table := map[int]rawPort{}
	for _, p := range dev.PortTable {
		table[p.PortIdx] = p
	}
	overrides := make([]map[string]any, 0, len(dev.PortOverrides)+len(ports))
	seen := map[int]bool{}
	for _, o := range dev.PortOverrides {
		idx := portIdxOf(o)
		if ports[idx] {
			o = cloneMap(o)
			notes[idx] = applyNative(o, table[idx], networkID, profByID)
			seen[idx] = true
		}
		overrides = append(overrides, o)
	}
	for idx := range ports {
		if seen[idx] {
			continue
		}
		o := map[string]any{"port_idx": idx}
		if p, ok := table[idx]; ok && p.Name != "" {
			o["name"] = p.Name
		}
		notes[idx] = applyNative(o, table[idx], networkID, profByID)
		overrides = append(overrides, o)
	}
	path := "rest/device/" + url.PathEscape(dev.ID)
	_, err := write[json.RawMessage](ctx, c, http.MethodPut, path, map[string]any{"port_overrides": overrides})
	if err != nil && strings.Contains(err.Error(), "InvalidPayload") {
		// older firmware does not know setting_preference
		for _, o := range overrides {
			delete(o, "setting_preference")
		}
		_, err = write[json.RawMessage](ctx, c, http.MethodPut, path, map[string]any{"port_overrides": overrides})
	}
	return notes, err
}

// applyNative sets the native network on one port override. A port profile is replaced by
// its own settings on the port, so the port keeps its tagged networks.
func applyNative(o map[string]any, p rawPort, networkID string, profiles map[string]rawPortConf) []string {
	var notes []string
	confID, _ := o["portconf_id"].(string)
	if confID == "" {
		confID = p.PortconfID
	}
	if prof, ok := profiles[confID]; ok {
		notes = append(notes, fmt.Sprintf("port profile %q replaced by the same settings on the port, with the new network", prof.Name))
		if _, ok := o["tagged_vlan_mgmt"]; !ok && prof.TaggedVLANMgmt != "" {
			o["tagged_vlan_mgmt"] = prof.TaggedVLANMgmt
			if len(prof.ExcludedIDs) > 0 {
				o["excluded_networkconf_ids"] = prof.ExcludedIDs
			}
		}
		if _, ok := o["forward"]; !ok && prof.Forward != "" && prof.Forward != "disabled" {
			o["forward"] = prof.Forward
			if prof.Forward == "customize" {
				o["tagged_networkconf_ids"] = withoutID(prof.TaggedIDs, networkID)
			}
		}
	}
	delete(o, "portconf_id")
	if f, _ := o["forward"].(string); f == "disabled" {
		o["forward"] = "native"
	}
	if tags, ok := o["tagged_networkconf_ids"].([]any); ok {
		var keep []any
		for _, t := range tags {
			if t != networkID {
				keep = append(keep, t)
			}
		}
		o["tagged_networkconf_ids"] = keep
	}
	o["native_networkconf_id"] = networkID
	o["setting_preference"] = "manual"
	return notes
}

func withoutID(ids []string, id string) []string {
	var out []string
	for _, x := range ids {
		if x != id {
			out = append(out, x)
		}
	}
	return out
}

func portIdxOf(o map[string]any) int {
	switch v := o["port_idx"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	}
	return 0
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// lookupUser finds the console's saved record for a client, by MAC.
func lookupUser(ctx context.Context, c *client, mac string) (*rawUser, error) {
	users, err := getList[rawUser](ctx, c, "stat/user/"+url.PathEscape(mac))
	if err == nil {
		for i := range users {
			if inv.NormMAC(users[i].MAC) == mac && users[i].ID != "" {
				return &users[i], nil
			}
		}
	}
	if errors.Is(err, ErrUnauthorized) {
		return nil, err
	}
	all, err := getList[rawUser](ctx, c, "rest/user")
	if err != nil {
		return nil, err
	}
	for i := range all {
		if inv.NormMAC(all[i].MAC) == mac && all[i].ID != "" {
			return &all[i], nil
		}
	}
	return nil, nil
}

// fixedIPs hands out fixed IPs in the network clients move to.
type fixedIPs struct {
	net    *rawNetwork
	prefix netip.Prefix
	ok     bool
	taken  map[netip.Addr]bool
}

func newFixedIPs(ctx context.Context, c *client, target *rawNetwork) *fixedIPs {
	f := &fixedIPs{net: target, taken: map[netip.Addr]bool{}}
	gw, err := netip.ParsePrefix(strings.TrimSpace(target.IPSubnet))
	if err != nil || !gw.Addr().Is4() {
		return f // VLAN-only network: no subnet to put a fixed IP in
	}
	f.prefix, f.ok = gw.Masked(), true
	f.taken[gw.Addr()] = true
	if users, err := getList[rawUser](ctx, c, "rest/user"); err == nil {
		for _, u := range users {
			if a, err := netip.ParseAddr(u.FixedIP); err == nil && u.UseFixedIP {
				f.taken[a] = true
			}
		}
	}
	return f
}

// place returns the address in the new subnet with the same last number as old, if free.
func (f *fixedIPs) place(old string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(old)
	if !f.ok || err != nil || !a.Is4() {
		return netip.Addr{}, false
	}
	if f.prefix.Contains(a) {
		return a, true
	}
	n, o := f.prefix.Addr().As4(), a.As4()
	bits := f.prefix.Bits()
	var nv, ov uint32
	for i := 0; i < 4; i++ {
		nv, ov = nv<<8|uint32(n[i]), ov<<8|uint32(o[i])
	}
	host := ov & (uint32(1)<<(32-bits) - 1)
	v := nv | host
	cand := netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	if host == 0 || host == uint32(1)<<(32-bits)-1 || f.taken[cand] {
		return netip.Addr{}, false
	}
	f.taken[cand] = true
	return cand, true
}

// fixedIPChange returns the client settings that move its fixed IP to the new network.
func (f *fixedIPs) change(u *rawUser) (map[string]any, string) {
	if u == nil || !u.UseFixedIP || u.NetworkID == f.net.ID {
		return nil, ""
	}
	if a, ok := f.place(u.FixedIP); ok {
		return map[string]any{"use_fixedip": true, "fixed_ip": a.String(), "network_id": f.net.ID},
			fmt.Sprintf("fixed IP moved from %s to %s", u.FixedIP, a)
	}
	return map[string]any{"use_fixedip": false},
		fmt.Sprintf("fixed IP %s removed: it belonged to the old network and its number is taken or doesn't fit in %s", u.FixedIP, f.net.Name)
}

// overrideClient puts one client in a network with UniFi's Virtual Network Override.
func overrideClient(ctx context.Context, c *client, mac, networkID string, fixed *fixedIPs) ([]string, error) {
	u, err := lookupUser(ctx, c, mac)
	if err != nil {
		return nil, err
	}
	if u == nil {
		// never saved: create the client record with the override
		_, err := write[rawUser](ctx, c, http.MethodPost, "group/user", map[string]any{
			"objects": []map[string]any{{"data": map[string]any{
				"mac": mac, "virtual_network_override_enabled": true, "virtual_network_override_id": networkID,
			}}},
		})
		return nil, err
	}
	body := map[string]any{"virtual_network_override_enabled": true, "virtual_network_override_id": networkID}
	var notes []string
	if ch, note := fixed.change(u); ch != nil {
		for k, v := range ch {
			body[k] = v
		}
		notes = append(notes, note)
	}
	_, err = write[json.RawMessage](ctx, c, http.MethodPut, "rest/user/"+url.PathEscape(u.ID), body)
	return notes, err
}

// rehomeFixedIP moves a wired client's fixed IP into the new network.
func rehomeFixedIP(ctx context.Context, c *client, mac string, fixed *fixedIPs) (string, error) {
	u, err := lookupUser(ctx, c, mac)
	if err != nil || u == nil {
		return "", err
	}
	ch, note := fixed.change(u)
	if ch == nil {
		return "", nil
	}
	_, err = write[json.RawMessage](ctx, c, http.MethodPut, "rest/user/"+url.PathEscape(u.ID), ch)
	return note, err
}

// BounceDown is how long a wired port is switched off so the device on it notices and asks
// for a new address. Tests shorten it.
var BounceDown = 10 * time.Second

// reconnectWith makes clients ask for a new address: Wi-Fi clients are disconnected and
// rejoin; a PoE port is power-cycled; any other wired port is switched off for BounceDown
// and back on. It returns one note per move.
func reconnectWith(ctx context.Context, c *client, moves []drivers.ClientMove) []string {
	notes := make([]string, len(moves))
	type port struct {
		sw  string
		idx int
	}
	portNote := map[port]string{}
	byPort := map[port][]int{}
	var ports []port
	for i, m := range moves {
		switch m.Method {
		case drivers.MoveClient:
			mac := inv.NormMAC(m.MAC)
			if _, err := write[json.RawMessage](ctx, c, http.MethodPost, "cmd/stamgr", map[string]string{"cmd": "kick-sta", "mac": mac}); err != nil {
				notes[i] = "could not reconnect it (" + err.Error() + "); it gets the new address when it next reconnects"
			} else {
				notes[i] = "disconnected so it rejoins and gets an address in the new network"
			}
		case drivers.MovePort:
			p := port{inv.NormMAC(m.SwitchMAC), m.SwitchPort}
			if _, ok := byPort[p]; !ok {
				ports = append(ports, p)
			}
			byPort[p] = append(byPort[p], i)
		}
	}
	if len(ports) > 0 {
		devs, err := getList[rawDeviceConf](ctx, c, "stat/device")
		if err != nil {
			for _, p := range ports {
				portNote[p] = "could not reconnect it (" + err.Error() + ")"
			}
		}
		bounce := map[string]map[int]bool{}
		for _, p := range ports {
			if err != nil {
				continue
			}
			var dev *rawDeviceConf
			for i := range devs {
				if inv.NormMAC(devs[i].MAC) == p.sw {
					dev = &devs[i]
				}
			}
			if dev == nil {
				portNote[p] = "could not reconnect it: the switch is gone"
				continue
			}
			poe := false
			for _, pt := range dev.PortTable {
				if pt.PortIdx == p.idx && pt.PoEEnable && float64(pt.PoEPower) > 0 {
					poe = true
				}
			}
			if poe {
				_, perr := write[json.RawMessage](ctx, c, http.MethodPost, "cmd/devmgr",
					map[string]any{"cmd": "power-cycle", "mac": p.sw, "port_idx": p.idx})
				if perr == nil {
					portNote[p] = "PoE port power-cycled so it restarts and gets an address in the new network"
					continue
				}
			}
			if bounce[p.sw] == nil {
				bounce[p.sw] = map[int]bool{}
			}
			bounce[p.sw][p.idx] = true
		}
		for sw, idxs := range bounce {
			var dev *rawDeviceConf
			for i := range devs {
				if inv.NormMAC(devs[i].MAC) == sw {
					dev = &devs[i]
				}
			}
			berr := bouncePorts(ctx, c, dev, idxs)
			for idx := range idxs {
				p := port{sw, idx}
				if berr != nil {
					portNote[p] = "could not reconnect it (" + berr.Error() + "); unplug it for a moment or restart it to get the new address"
				} else {
					portNote[p] = fmt.Sprintf("switch port turned off for %s and back on so it asks for an address in the new network", BounceDown.Round(time.Second))
				}
			}
		}
	}
	for p, idx := range byPort {
		for _, i := range idx {
			notes[i] = portNote[p]
		}
	}
	return notes
}

// bouncePorts switches ports off, waits, and restores the overrides as they were. Restoring
// is retried, since a port left off cuts the device off.
func bouncePorts(ctx context.Context, c *client, dev *rawDeviceConf, idxs map[int]bool) error {
	orig := dev.PortOverrides
	off := make([]map[string]any, 0, len(orig)+len(idxs))
	seen := map[int]bool{}
	for _, o := range orig {
		idx := portIdxOf(o)
		if idxs[idx] {
			o = cloneMap(o)
			o["forward"] = "disabled"
			seen[idx] = true
		}
		off = append(off, o)
	}
	for idx := range idxs {
		if !seen[idx] {
			off = append(off, map[string]any{"port_idx": idx, "forward": "disabled"})
		}
	}
	path := "rest/device/" + url.PathEscape(dev.ID)
	if _, err := write[json.RawMessage](ctx, c, http.MethodPut, path, map[string]any{"port_overrides": off}); err != nil {
		return err
	}
	select {
	case <-time.After(BounceDown):
	case <-ctx.Done():
	}
	restore := orig
	if restore == nil {
		restore = []map[string]any{}
	}
	// use a fresh context: the port must come back even if the request was cancelled
	rctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var err error
	for try := 0; try < 4; try++ {
		if _, err = write[json.RawMessage](rctx, c, http.MethodPut, path, map[string]any{"port_overrides": restore}); err == nil {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("the port may still be off: turning it back on failed (%v); turn it on in UniFi", err)
}

// Reconnect implements drivers.NetworkWriter.
func (d Driver) Reconnect(ctx context.Context, t drivers.Target, creds vault.Secret, moves []drivers.ClientMove) ([]drivers.MoveResult, error) {
	results := make([]drivers.MoveResult, len(moves))
	err := d.writeSession(ctx, t, creds, func(c *client) error {
		notes := reconnectWith(ctx, c, moves)
		for i, m := range moves {
			results[i] = drivers.MoveResult{MAC: inv.NormMAC(m.MAC), Name: m.Name, OK: !strings.HasPrefix(notes[i], "could not"), Notes: []string{notes[i]}}
			if !results[i].OK {
				results[i].Error, results[i].Notes = notes[i], nil
			}
		}
		return nil
	})
	return results, err
}

// SetNetworkDomain implements drivers.NetworkDomainSetter. UniFi wants the whole network
// object back on a PUT, so the current one is read, its domain_name changed and sent back.
func (d Driver) SetNetworkDomain(ctx context.Context, t drivers.Target, creds vault.Secret, networkID, domain string) error {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	return d.writeSession(ctx, t, creds, func(c *client) error {
		nets, err := getList[map[string]any](ctx, c, "rest/networkconf")
		if err != nil {
			return err
		}
		for _, n := range nets {
			if id, _ := n["_id"].(string); id != networkID {
				continue
			}
			if p, _ := n["purpose"].(string); p == "wan" || strings.Contains(p, "vpn") {
				return fmt.Errorf("unifi: %v is a %s network, which has no DHCP domain", n["name"], p)
			}
			n["domain_name"] = domain
			_, err := write[rawNetwork](ctx, c, http.MethodPut, "rest/networkconf/"+url.PathEscape(networkID), n)
			return err
		}
		return fmt.Errorf("unifi: %s", friendlyMsg("api.err.NetworkNotFound"))
	})
}
