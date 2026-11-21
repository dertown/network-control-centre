package unifi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

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

		// wireless (and anything else moved per client)
		for i, m := range moves {
			if m.Method != drivers.MoveClient {
				if m.Method != drivers.MovePort {
					results[i].Error = "unknown way to move this client: " + m.Method
				}
				continue
			}
			notes, err := overrideClient(ctx, c, results[i].MAC, networkID)
			err = asPerm(err)
			if err != nil {
				results[i].Error = err.Error()
				if errors.Is(err, ErrReadOnly) {
					return err
				}
				continue
			}
			results[i].OK, results[i].Notes = true, notes
			if reconnect {
				if _, err := write[json.RawMessage](ctx, c, http.MethodPost, "cmd/stamgr", map[string]string{"cmd": "kick-sta", "mac": results[i].MAC}); err != nil {
					results[i].Notes = append(results[i].Notes, "could not reconnect it ("+err.Error()+"); it moves when it next reconnects")
				} else {
					results[i].Notes = append(results[i].Notes, "disconnected so it rejoins in the new network")
				}
			}
		}
		// a fixed IP reserved in the old network no longer fits: clear it for wired clients too
		for i, m := range moves {
			if m.Method == drivers.MovePort && results[i].OK {
				if note, err := clearFixedIP(ctx, c, results[i].MAC, networkID); err == nil && note != "" {
					results[i].Notes = append(results[i].Notes, note)
				}
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

// overrideClient puts one client in a network with UniFi's Virtual Network Override.
func overrideClient(ctx context.Context, c *client, mac, networkID string) ([]string, error) {
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
	if u.UseFixedIP && u.NetworkID != networkID {
		body["use_fixedip"] = false
		notes = append(notes, fmt.Sprintf("fixed IP %s removed: it belonged to the old network", u.FixedIP))
	}
	_, err = write[json.RawMessage](ctx, c, http.MethodPut, "rest/user/"+url.PathEscape(u.ID), body)
	return notes, err
}

// clearFixedIP drops a fixed IP reserved in another network.
func clearFixedIP(ctx context.Context, c *client, mac, networkID string) (string, error) {
	u, err := lookupUser(ctx, c, mac)
	if err != nil || u == nil || !u.UseFixedIP || u.NetworkID == networkID {
		return "", err
	}
	_, err = write[json.RawMessage](ctx, c, http.MethodPut, "rest/user/"+url.PathEscape(u.ID), map[string]any{"use_fixedip": false})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("fixed IP %s removed: it belonged to the old network", u.FixedIP), nil
}
