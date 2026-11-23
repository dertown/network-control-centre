package core

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dertown/network-control-centre/internal/drivers"
	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/iot"
)

// Wi-Fi: weak settings NCC flags, and the preview of an SSID change. Like VLAN planning, this
// works from the latest snapshot and never talks to the router.

// Wi-Fi finding severities.
const (
	WiFiCritical = "critical"
	WiFiWarning  = "warning"
	WiFiInfo     = "info"
)

// WiFiFinding is one weak or questionable Wi-Fi setting.
type WiFiFinding struct {
	Severity string `json:"severity"`
	// Kind: open | wep | wpa1 | mixed-wpa1 | tkip | short-passphrase | iot-vlan | guest-lan |
	// width-2g | channel-2g | same-channel | busy.
	Kind string `json:"kind"`
	// SSIDID is set for findings about a Wi-Fi network, DeviceID for findings about a radio.
	SSIDID   string `json:"ssid_id,omitempty"`
	SSID     string `json:"ssid,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
	Device   string `json:"device,omitempty"`
	Summary  string `json:"summary"`
	Fix      string `json:"fix,omitempty"`
	Target   string `json:"target"`
}

func netByID(nets []inventory.Network, id string) *inventory.Network {
	for i := range nets {
		if nets[i].ID == id {
			return &nets[i]
		}
	}
	return nil
}

// guestNetwork is a network fit for guests: a guest purpose or zone, or isolated.
func guestNetwork(n *inventory.Network) bool {
	return n != nil && (n.Purpose == "guest" || n.Zone == "hotspot" || n.Isolated)
}

// isPersonal is WPA Personal in any version: the modes with a passphrase.
func isPersonal(sec string) bool {
	switch sec {
	case inventory.SecWPA1, inventory.SecWPA1WPA2, inventory.SecWPA2, inventory.SecWPA2WPA3, inventory.SecWPA3:
		return true
	}
	return false
}

// SSIDFindings checks one SSID. Disabled SSIDs are not checked.
func SSIDFindings(s inventory.SSID, nets []inventory.Network) []WiFiFinding {
	if !s.Enabled {
		return nil
	}
	var out []WiFiFinding
	add := func(sev, kind, summary, fix string) {
		out = append(out, WiFiFinding{Severity: sev, Kind: kind, SSIDID: s.ID, SSID: s.Name, Summary: summary, Fix: fix, Target: s.Target})
	}
	switch s.Security {
	case inventory.SecOpen:
		if s.Guest {
			add(WiFiWarning, "open", s.Name+" is an open guest network: anyone in range can join, and their traffic is not encrypted.",
				"Give it WPA2 and a guest passphrase you can share.")
		} else {
			add(WiFiCritical, "open", s.Name+" is an open network: anyone in range can join "+orNet(s.Network)+" and read unencrypted traffic.",
				"Set WPA2/WPA3 security and a passphrase.")
		}
	case inventory.SecWEP:
		add(WiFiCritical, "wep", s.Name+" uses WEP, which can be cracked in minutes.", "Switch it to WPA2/WPA3 with a new passphrase.")
	case inventory.SecWPA1:
		add(WiFiCritical, "wpa1", s.Name+" uses WPA (version 1), which is deprecated and easy to attack.", "Switch it to WPA2/WPA3.")
	case inventory.SecWPA1WPA2:
		add(WiFiWarning, "mixed-wpa1", s.Name+" still lets devices join with WPA (version 1).", "Switch it to WPA2 or WPA2/WPA3.")
	}
	if s.TKIP && s.Security != inventory.SecWPA1 {
		add(WiFiWarning, "tkip", s.Name+" allows TKIP encryption, which is weak and caps speeds at 54 Mbit/s.", "Switch it to WPA2 (AES only).")
	}
	if s.ShortPassphrase && isPersonal(s.Security) {
		add(WiFiWarning, "short-passphrase", s.Name+"'s passphrase is shorter than 12 characters, so it can be guessed offline.",
			"Change it to a passphrase of 12 or more characters.")
	}
	n := netByID(nets, s.NetworkID)
	if n != nil && iot.IsIoTNetwork(s.Name) && !iot.IsIoTNetwork(n.Name) && n.Zone != "dmz" && !guestNetwork(n) {
		add(WiFiWarning, "iot-vlan", s.Name+" looks like an IoT Wi-Fi but puts devices on "+n.Name+", with your computers.",
			"Assign it your IoT network.")
	}
	if !s.Guest && strings.Contains(strings.ToLower(s.Name), "guest") && n != nil && !guestNetwork(n) {
		add(WiFiWarning, "guest-lan", s.Name+" looks like a guest Wi-Fi but puts guests on "+n.Name+", where they can reach your devices.",
			"Assign it a guest or isolated network.")
	}
	return out
}

func orNet(n string) string {
	if n == "" {
		return "your network"
	}
	return n
}

// WiFiFindings checks every SSID and radio of a snapshot, worst first.
func WiFiFindings(snap *inventory.Snapshot) []WiFiFinding {
	if snap == nil || snap.WiFi == nil {
		return []WiFiFinding{}
	}
	out := []WiFiFinding{}
	for _, s := range snap.WiFi.SSIDs {
		out = append(out, SSIDFindings(s, snap.Networks)...)
	}
	radio := func(r inventory.Radio, sev, kind, summary, fix string) {
		out = append(out, WiFiFinding{Severity: sev, Kind: kind, DeviceID: r.DeviceID, Device: r.DeviceName, Summary: summary, Fix: fix, Target: snap.Target})
	}
	type chKey struct {
		band string
		ch   int
	}
	onChannel := map[chKey][]string{}
	for _, r := range snap.WiFi.Radios {
		if !r.Online {
			continue
		}
		if r.Band == "2.4" && r.WidthMHz > 20 {
			radio(r, WiFiWarning, "width-2g", fmt.Sprintf("%s uses %d MHz on 2.4 GHz, which overlaps most of the band and its neighbours.", r.DeviceName, r.WidthMHz),
				"Set the 2.4 GHz channel width to 20 MHz in UniFi Network.")
		}
		if r.Band == "2.4" && r.Channel > 0 && r.Channel != 1 && r.Channel != 6 && r.Channel != 11 {
			radio(r, WiFiWarning, "channel-2g", fmt.Sprintf("%s is on 2.4 GHz channel %d, which overlaps channels 1, 6 and 11.", r.DeviceName, r.Channel),
				"Use channel 1, 6 or 11 (or auto).")
		}
		if r.Utilization >= 70 {
			radio(r, WiFiWarning, "busy", fmt.Sprintf("%s's %s GHz channel is %d%% busy, so clients there get slow.", r.DeviceName, r.Band, r.Utilization),
				"Try another channel or move clients to 5 GHz.")
		}
		if r.Channel > 0 {
			k := chKey{r.Band, r.Channel}
			onChannel[k] = append(onChannel[k], r.DeviceName)
		}
	}
	keys := make([]chKey, 0, len(onChannel))
	for k := range onChannel {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].band != keys[j].band {
			return keys[i].band < keys[j].band
		}
		return keys[i].ch < keys[j].ch
	})
	for _, k := range keys {
		names := onChannel[k]
		if len(names) < 2 {
			continue
		}
		out = append(out, WiFiFinding{Severity: WiFiInfo, Kind: "same-channel", Device: strings.Join(names, ", "), Target: snap.Target,
			Summary: fmt.Sprintf("%s share %s GHz channel %d, so they take turns to talk.", joinAnd(names), k.band, k.ch),
			Fix:     "Fine if they are far apart; otherwise give them different channels."})
	}
	rank := map[string]int{WiFiCritical: 0, WiFiWarning: 1, WiFiInfo: 2}
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Severity] < rank[out[j].Severity] })
	return out
}

func joinAnd(s []string) string {
	if len(s) < 2 {
		return strings.Join(s, "")
	}
	return strings.Join(s[:len(s)-1], ", ") + " and " + s[len(s)-1]
}

// WiFiChangeLine is one setting that changes, in words.
type WiFiChangeLine struct {
	Setting string `json:"setting"`
	From    string `json:"from"`
	To      string `json:"to"`
}

// WiFiPlan is the preview of an SSID change.
type WiFiPlan struct {
	SSID     inventory.SSID   `json:"ssid"`
	Changes  []WiFiChangeLine `json:"changes"`
	Warnings []string         `json:"warnings"`
	// Resolves are the findings about this SSID that the change fixes; Remaining those it leaves.
	Resolves  []WiFiFinding `json:"resolves"`
	Remaining []WiFiFinding `json:"remaining"`
}

// SecurityLabel names a security mode for people.
func SecurityLabel(sec string) string {
	switch sec {
	case inventory.SecOpen:
		return "Open (no password)"
	case inventory.SecWEP:
		return "WEP"
	case inventory.SecWPA1:
		return "WPA"
	case inventory.SecWPA1WPA2:
		return "WPA/WPA2"
	case inventory.SecWPA2:
		return "WPA2"
	case inventory.SecWPA2WPA3:
		return "WPA2/WPA3"
	case inventory.SecWPA3:
		return "WPA3"
	case inventory.SecEnterprise:
		return "WPA Enterprise"
	case inventory.SecOWE:
		return "Enhanced Open"
	}
	return sec
}

func netLabel(n *inventory.Network) string {
	if n == nil {
		return "unknown"
	}
	if n.VLAN > 0 {
		return fmt.Sprintf("%s (VLAN %d)", n.Name, n.VLAN)
	}
	return n.Name + " (untagged)"
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// ValidPassphrase checks a WPA Personal passphrase: 8 to 63 printable ASCII characters.
func ValidPassphrase(p string) error {
	if len(p) < 8 || len(p) > 63 {
		return fmt.Errorf("the passphrase must be 8 to 63 characters long")
	}
	for _, r := range p {
		if r < 0x20 || r > 0x7e {
			return fmt.Errorf("the passphrase can only use printable ASCII characters (letters, digits, spaces and punctuation)")
		}
	}
	return nil
}

// PlanWiFiChange checks a change to one SSID against the snapshot and says what it does.
func PlanWiFiChange(snap *inventory.Snapshot, ssidID string, ch *drivers.WLANChange) (*WiFiPlan, error) {
	if snap == nil || snap.WiFi == nil {
		return nil, fmt.Errorf("NCC has not read this router's Wi-Fi yet; wait for the next refresh")
	}
	var cur *inventory.SSID
	for i := range snap.WiFi.SSIDs {
		if snap.WiFi.SSIDs[i].ID == ssidID {
			cur = &snap.WiFi.SSIDs[i]
		}
	}
	if cur == nil {
		return nil, fmt.Errorf("no Wi-Fi network with id %q on %s", ssidID, snap.Target)
	}
	next := *cur
	p := &WiFiPlan{SSID: *cur, Changes: []WiFiChangeLine{}, Warnings: []string{}}
	clients := fmt.Sprintf("%d device%s", cur.Clients, map[bool]string{true: "", false: "s"}[cur.Clients == 1])

	if ch.Name != nil {
		name := strings.TrimSpace(*ch.Name)
		if name == cur.Name {
			ch.Name = nil
		} else {
			if name == "" || len(name) > 32 {
				return nil, fmt.Errorf("a Wi-Fi name must be 1 to 32 characters long")
			}
			for _, o := range snap.WiFi.SSIDs {
				if o.ID != cur.ID && strings.EqualFold(o.Name, name) {
					return nil, fmt.Errorf("there is already a Wi-Fi network called %q", o.Name)
				}
			}
			ch.Name = &name
			next.Name = name
			p.Changes = append(p.Changes, WiFiChangeLine{"Name", cur.Name, name})
			if cur.Clients > 0 {
				p.Warnings = append(p.Warnings, fmt.Sprintf("Devices remember Wi-Fi by name: the %s on %s lose their connection and must each be joined to %s by hand.", clients, cur.Name, name))
			}
		}
	}
	if ch.Enabled != nil {
		if *ch.Enabled == cur.Enabled {
			ch.Enabled = nil
		} else {
			next.Enabled = *ch.Enabled
			p.Changes = append(p.Changes, WiFiChangeLine{"Broadcasting", onOff(cur.Enabled), onOff(*ch.Enabled)})
			if !*ch.Enabled && cur.Clients > 0 {
				p.Warnings = append(p.Warnings, fmt.Sprintf("The %s on %s are disconnected now and can't rejoin until it is switched back on.", clients, cur.Name))
			}
		}
	}
	if ch.Hidden != nil {
		if *ch.Hidden == cur.Hidden {
			ch.Hidden = nil
		} else {
			next.Hidden = *ch.Hidden
			p.Changes = append(p.Changes, WiFiChangeLine{"Hidden name", onOff(cur.Hidden), onOff(*ch.Hidden)})
			if *ch.Hidden {
				p.Warnings = append(p.Warnings, "Hiding the name adds no real security (it still shows up to anyone looking), and some devices find hidden networks hard to join.")
			}
		}
	}
	if ch.NetworkID != nil {
		if *ch.NetworkID == cur.NetworkID {
			ch.NetworkID = nil
		} else {
			n := netByID(snap.Networks, *ch.NetworkID)
			if n == nil {
				return nil, fmt.Errorf("no network with id %q on %s", *ch.NetworkID, snap.Target)
			}
			if n.Purpose == "wan" || strings.Contains(n.Purpose, "vpn") {
				return nil, fmt.Errorf("%s is a %s network; Wi-Fi can only use a LAN or VLAN", n.Name, n.Purpose)
			}
			next.NetworkID, next.Network, next.VLAN = n.ID, n.Name, n.VLAN
			p.Changes = append(p.Changes, WiFiChangeLine{"Network", netLabel(netByID(snap.Networks, cur.NetworkID)), netLabel(n)})
			if cur.Clients > 0 {
				p.Warnings = append(p.Warnings, fmt.Sprintf("The %s on %s rejoin and get addresses in %s. Anything that reaches them by their old address (port forwards, fixed IPs, firewall rules) needs updating.", clients, cur.Name, n.Name))
			}
		}
	}
	if ch.Security != nil {
		if *ch.Security == cur.Security {
			ch.Security = nil
		} else {
			switch *ch.Security {
			case inventory.SecWPA2, inventory.SecWPA2WPA3, inventory.SecWPA3:
			default:
				return nil, fmt.Errorf("NCC can set WPA2, WPA2/WPA3 or WPA3 security, not %q", *ch.Security)
			}
			if cur.Security == inventory.SecEnterprise {
				return nil, fmt.Errorf("%s uses WPA Enterprise (RADIUS); change its security in UniFi Network", cur.Name)
			}
			if !isPersonal(cur.Security) && ch.Passphrase == nil {
				return nil, fmt.Errorf("%s has no passphrase yet: set one to switch it to %s", cur.Name, SecurityLabel(*ch.Security))
			}
			next.Security, next.TKIP = *ch.Security, false
			p.Changes = append(p.Changes, WiFiChangeLine{"Security", SecurityLabel(cur.Security), SecurityLabel(*ch.Security)})
			if *ch.Security == inventory.SecWPA3 {
				p.Warnings = append(p.Warnings, "Older devices (most made before 2019, and many smart plugs and cameras) cannot join WPA3-only networks. WPA2/WPA3 keeps them working.")
			}
			if cur.Clients > 0 {
				p.Warnings = append(p.Warnings, fmt.Sprintf("The %s on %s reconnect with the new security; a device that can't use it drops off.", clients, cur.Name))
			}
		}
	}
	if ch.Passphrase != nil {
		if err := ValidPassphrase(*ch.Passphrase); err != nil {
			return nil, err
		}
		if !isPersonal(next.Security) {
			return nil, fmt.Errorf("%s uses %s, which has no passphrase; choose WPA2 or WPA3 security as well", cur.Name, SecurityLabel(next.Security))
		}
		next.ShortPassphrase = len(*ch.Passphrase) < 12
		p.Changes = append(p.Changes, WiFiChangeLine{"Passphrase", "••••••", "new passphrase (" + fmt.Sprint(len(*ch.Passphrase)) + " characters)"})
		if cur.Clients > 0 {
			p.Warnings = append(p.Warnings, fmt.Sprintf("The %s on %s are disconnected and each needs the new passphrase to rejoin.", clients, cur.Name))
		}
	}
	if ch.Bands != nil {
		var bands []string
		for _, b := range []string{"2.4", "5", "6"} {
			if hasStr(ch.Bands, b) {
				bands = append(bands, b)
			}
		}
		for _, b := range ch.Bands {
			if b != "2.4" && b != "5" && b != "6" {
				return nil, fmt.Errorf("unknown band %q: use 2.4, 5 or 6", b)
			}
		}
		if len(bands) == 0 {
			return nil, fmt.Errorf("%s needs at least one band", cur.Name)
		}
		if strings.Join(bands, ",") == strings.Join(cur.Bands, ",") {
			ch.Bands = nil
		} else {
			ch.Bands = bands
			next.Bands = bands
			p.Changes = append(p.Changes, WiFiChangeLine{"Bands", bandList(cur.Bands), bandList(bands)})
			if hasStr(bands, "6") {
				switch next.Security {
				case inventory.SecWPA3, inventory.SecEnterprise, inventory.SecOWE:
				case inventory.SecWPA2WPA3:
					p.Warnings = append(p.Warnings, "6 GHz only allows WPA3: devices that only know WPA2 keep joining on 2.4 or 5 GHz.")
				default:
					return nil, fmt.Errorf("6 GHz Wi-Fi requires WPA3; set %s to WPA2/WPA3 or WPA3 first", cur.Name)
				}
				has6 := false
				for _, r := range snap.WiFi.Radios {
					has6 = has6 || r.Band == "6"
				}
				if !has6 {
					p.Warnings = append(p.Warnings, "None of your access points has a 6 GHz radio, so this changes nothing until you add one.")
				}
			}
			counts := map[string]int{}
			for _, c := range snap.Clients {
				if !c.Wired && c.SSID == cur.Name {
					counts[c.Band]++
				}
			}
			for _, b := range cur.Bands {
				if !hasStr(bands, b) && counts[b] > 0 {
					msg := fmt.Sprintf("The %d device%s on %s at %s GHz must move to %s, or lose Wi-Fi if they can't.", counts[b], map[bool]string{true: "", false: "s"}[counts[b] == 1], cur.Name, b, bandList(bands))
					if b == "2.4" {
						msg += " Many smart plugs, bulbs and cameras only have 2.4 GHz."
					}
					p.Warnings = append(p.Warnings, msg)
				}
			}
		}
	}
	if len(p.Changes) == 0 {
		return nil, fmt.Errorf("nothing to change")
	}
	before := SSIDFindings(*cur, snap.Networks)
	after := SSIDFindings(next, snap.Networks)
	p.Resolves, p.Remaining = []WiFiFinding{}, after
	if p.Remaining == nil {
		p.Remaining = []WiFiFinding{}
	}
	stays := map[string]bool{}
	for _, f := range after {
		stays[f.Kind] = true
	}
	for _, f := range before {
		if !stays[f.Kind] {
			p.Resolves = append(p.Resolves, f)
		}
	}
	p.SSID = next
	return p, nil
}

func bandList(b []string) string {
	if len(b) == 0 {
		return "none"
	}
	return strings.Join(b, ", ") + " GHz"
}
