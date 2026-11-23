package unifi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/dertown/network-control-centre/internal/drivers"
	inv "github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/vault"
)

// Wi-Fi.
//
// Reading: rest/wlanconf lists the SSIDs with their security, bands and network; each access
// point (and a router with built-in Wi-Fi) in stat/device has a radio_table (settings: channel
// or "auto", width as "ht", transmit power) and a radio_table_stats (what the radio is doing
// now: the channel it picked, clients, channel utilisation). Wireless clients in stat/sta carry
// their signal, radio and channel.
//
// Writing: UniFi wants the whole WLAN object back on a PUT to rest/wlanconf/{id}, so the
// current one is read, changed and sent back, keeping settings NCC does not know about.
//
// Access point radios: channel, width ("ht") and transmit power live in the device's
// radio_table, and the Wi-Fi networks one access point leaves off are its wlan_overrides
// (wlan_id + radio + enabled: false). Both are sent back whole on a PUT to rest/device/{id}.
// UniFi has no documented switch to power a radio down, so "off" for a band means every
// Wi-Fi network is switched off on it for that access point; a wireless mesh uplink, which
// uses its own hidden network, is not touched by that (NCC still refuses it, to be safe).
//
// Neighbouring networks come from stat/rogueap: every network an access point hears that is
// not the site's own, with its channel and signal.
//
// The passphrase (x_passphrase) is read on every poll only to tell whether it is short; it
// never goes into the snapshot.

var (
	_ drivers.WiFiWriter    = Driver{}
	_ drivers.APRadioWriter = Driver{}
)

// shortPassphrase is the length below which a WPA passphrase counts as short.
const shortPassphrase = 12

// rawChannel is a radio's channel setting: a number or "auto".
type rawChannel struct {
	N    int
	Auto bool
}

func (c *rawChannel) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if strings.EqualFold(s, "auto") {
		c.Auto = true
		return nil
	}
	c.N, _ = strconv.Atoi(s)
	return nil
}

type rawRadio struct {
	Name        string     `json:"name"`  // wifi0, wifi1...
	Radio       string     `json:"radio"` // ng (2.4 GHz) | na (5 GHz) | 6e (6 GHz)
	Channel     rawChannel `json:"channel"`
	HT          flexInt    `json:"ht"` // channel width in MHz: 20 | 40 | 80 | 160 | 320
	TxPowerMode string     `json:"tx_power_mode"`
	TxPower     flexInt    `json:"tx_power"`
}

type rawWLANOverride struct {
	WLANID    string `json:"wlan_id"`
	Radio     string `json:"radio"` // ng | na | 6e
	RadioName string `json:"radio_name"`
	Enabled   *bool  `json:"enabled"`
}

type rawNeighbor struct {
	ESSID   string  `json:"essid"`
	BSSID   string  `json:"bssid"`
	APMAC   string  `json:"ap_mac"`
	Radio   string  `json:"radio"`
	Channel flexInt `json:"channel"`
	Signal  flexInt `json:"signal"` // dBm
	RSSI    flexInt `json:"rssi"`   // dB above the noise floor, when signal is missing
}

// radioCode is UniFi's radio code for a band in GHz.
func radioCode(band string) string {
	return map[string]string{"2.4": "ng", "5": "na", "6": "6e"}[band]
}

type rawRadioStats struct {
	Name    string  `json:"name"`
	Radio   string  `json:"radio"`
	Channel flexInt `json:"channel"`
	TxPower flexInt `json:"tx_power"`
	NumSta  int     `json:"num_sta"`
	CuTotal flexInt `json:"cu_total"` // channel utilisation, %
}

// bandOf turns UniFi's radio code into GHz.
func bandOf(radio string) string {
	switch strings.ToLower(radio) {
	case "ng":
		return "2.4"
	case "na":
		return "5"
	case "6e":
		return "6"
	}
	return ""
}

// wlanSecurity sums up a WLAN's security as one of the inventory.Sec* modes.
func wlanSecurity(w rawWLAN) string {
	switch strings.ToLower(w.Security) {
	case "open", "":
		return inv.SecOpen
	case "wep":
		return inv.SecWEP
	case "wpaeap", "osen":
		return inv.SecEnterprise
	case "owe":
		return inv.SecOWE
	}
	switch {
	case w.WPA3Support && !w.WPA3Transition:
		return inv.SecWPA3
	case w.WPA3Support:
		return inv.SecWPA2WPA3
	}
	switch strings.ToLower(w.WPAMode) {
	case "wpa1", "wpa":
		return inv.SecWPA1
	case "auto":
		return inv.SecWPA1WPA2
	}
	return inv.SecWPA2
}

func wlanBands(w rawWLAN) []string {
	var out []string
	for _, b := range w.WLANBands {
		if g := map[string]string{"2g": "2.4", "5g": "5", "6g": "6"}[strings.ToLower(b)]; g != "" {
			out = append(out, g)
		}
	}
	if len(out) > 0 {
		return out
	}
	switch strings.ToLower(w.WLANBand) {
	case "2g":
		return []string{"2.4"}
	case "5g":
		return []string{"5"}
	}
	return []string{"2.4", "5"}
}

// buildWiFi reads the SSIDs and access point radios. nil when the console reported neither.
func buildWiFi(target string, devs []rawDevice, clients []rawClient, cfg *siteConfig, ix *netIndex) *inv.WiFi {
	w := &inv.WiFi{SSIDs: []inv.SSID{}, Radios: []inv.Radio{}}
	perSSID := map[string]int{}
	perRadio := map[string]int{} // "ap-mac|band"
	for _, c := range clients {
		if c.IsWired {
			continue
		}
		perSSID[c.ESSID]++
		perRadio[inv.NormMAC(c.APMAC)+"|"+bandOf(c.Radio)]++
	}
	if cfg != nil {
		for _, r := range cfg.WLANs {
			s := inv.SSID{
				ID: r.ID, Name: r.Name, Enabled: r.Enabled == nil || *r.Enabled, Hidden: r.HideSSID,
				Security: wlanSecurity(r), TKIP: strings.EqualFold(r.WPAEnc, "tkip") || strings.EqualFold(r.WPAEnc, "auto"),
				PMF: r.PMFMode, Bands: wlanBands(r), Guest: r.IsGuest, ClientIsolation: r.L2Isolation,
				Clients: perSSID[r.Name], Target: target,
			}
			if s.Security != inv.SecWPA1 && s.Security != inv.SecWPA1WPA2 && s.Security != inv.SecWPA2 {
				s.TKIP = false // only WPA/WPA2 Personal can fall back to TKIP
			}
			if s.Security == inv.SecWPA1 || s.Security == inv.SecWPA1WPA2 || s.Security == inv.SecWPA2 ||
				s.Security == inv.SecWPA2WPA3 || s.Security == inv.SecWPA3 {
				s.ShortPassphrase = r.Passphrase != "" && len([]rune(r.Passphrase)) < shortPassphrase
			}
			id := r.NetworkID
			if id == "" && r.VLANEnabled && r.VLAN > 0 {
				if n, ok := ix.byVLAN[int(r.VLAN)]; ok {
					id = n.ID
				}
			}
			if id == "" {
				id = ix.defaultID
			}
			if n, ok := ix.byID[id]; ok {
				s.NetworkID, s.Network, s.VLAN = n.ID, n.Name, n.VLAN
			}
			w.SSIDs = append(w.SSIDs, s)
		}
	}
	sort.SliceStable(w.SSIDs, func(i, j int) bool { return strings.ToLower(w.SSIDs[i].Name) < strings.ToLower(w.SSIDs[j].Name) })

	for _, d := range devs {
		if len(d.RadioTable) == 0 {
			continue
		}
		mac := inv.NormMAC(d.MAC)
		stats := map[string]rawRadioStats{}
		for _, st := range d.RadioTableStats {
			stats[st.Name] = st
		}
		off := map[string][]string{}
		for _, o := range d.WLANOverrides {
			if o.Enabled != nil && !*o.Enabled && o.WLANID != "" {
				b := bandOf(o.Radio)
				off[b] = append(off[b], o.WLANID)
			}
		}
		for _, r := range d.RadioTable {
			band := bandOf(r.Radio)
			if band == "" {
				continue
			}
			rd := inv.Radio{
				DeviceID: mac, DeviceName: firstNonEmpty(d.Name, d.MAC), Online: d.State == 1, Band: band,
				Channel: r.Channel.N, ChannelAuto: r.Channel.Auto, WidthMHz: int(r.HT),
				TxPower: int(r.TxPower), TxPowerMode: strings.ToLower(r.TxPowerMode),
				Clients: perRadio[mac+"|"+band], SSIDsOff: off[band],
			}
			if st, ok := stats[r.Name]; ok {
				if st.Channel > 0 {
					rd.Channel = int(st.Channel)
				}
				if st.TxPower > 0 {
					rd.TxPower = int(st.TxPower)
				}
				if st.NumSta > rd.Clients {
					rd.Clients = st.NumSta
				}
				rd.Utilization = int(st.CuTotal)
			}
			w.Radios = append(w.Radios, rd)
		}
	}
	if len(w.SSIDs) == 0 && len(w.Radios) == 0 {
		return nil
	}
	if cfg != nil {
		for _, n := range cfg.Neighbors {
			band := bandOf(n.Radio)
			if band == "" || n.Channel <= 0 {
				continue
			}
			sig := int(n.Signal)
			if sig >= 0 && n.RSSI > 0 {
				sig = int(n.RSSI) - 95 // UniFi's noise floor
			}
			if sig >= 0 {
				sig = 0
			}
			w.Neighbors = append(w.Neighbors, inv.Neighbor{SSID: n.ESSID, BSSID: inv.NormMAC(n.BSSID), Band: band,
				Channel: int(n.Channel), Signal: sig, SeenBy: inv.NormMAC(n.APMAC)})
		}
		// the loudest first, and no more than are useful
		sort.SliceStable(w.Neighbors, func(i, j int) bool { return w.Neighbors[i].Signal > w.Neighbors[j].Signal })
		if len(w.Neighbors) > 300 {
			w.Neighbors = w.Neighbors[:300]
		}
	}
	return w
}

// UpdateAPRadios implements drivers.APRadioWriter.
func (d Driver) UpdateAPRadios(ctx context.Context, t drivers.Target, creds vault.Secret, deviceID string, ch drivers.APChange) error {
	return d.writeSession(ctx, t, creds, func(c *client) error {
		devs, err := getList[map[string]any](ctx, c, "stat/device")
		if err != nil {
			return err
		}
		var dev map[string]any
		for _, x := range devs {
			if m, _ := x["mac"].(string); inv.NormMAC(m) == deviceID {
				dev = x
			}
		}
		if dev == nil {
			return fmt.Errorf("unifi: the access point %s is no longer adopted", deviceID)
		}
		id, _ := dev["_id"].(string)
		if id == "" {
			return fmt.Errorf("unifi: the console did not report an id for %v", dev["name"])
		}
		body, err := applyAPChange(dev, ch)
		if err != nil {
			return err
		}
		_, err = write[map[string]any](ctx, c, http.MethodPut, "rest/device/"+url.PathEscape(id), body)
		return err
	})
}

// applyAPChange works out the radio_table and wlan_overrides to send for a change to one
// access point, keeping every setting NCC does not know about.
func applyAPChange(dev map[string]any, ch drivers.APChange) (map[string]any, error) {
	body := map[string]any{}
	table, _ := dev["radio_table"].([]any)
	if len(ch.Radios) > 0 {
		out := make([]any, len(table))
		copy(out, table)
		for _, rs := range ch.Radios {
			code := radioCode(rs.Band)
			found := false
			for i, x := range out {
				r, ok := x.(map[string]any)
				if !ok || r["radio"] != code {
					continue
				}
				r = cloneMap(r)
				if rs.Channel != nil {
					if *rs.Channel == 0 {
						r["channel"] = "auto"
					} else {
						r["channel"] = *rs.Channel
					}
				}
				if rs.WidthMHz != nil {
					r["ht"] = *rs.WidthMHz
				}
				if rs.TxPowerMode != nil {
					r["tx_power_mode"] = *rs.TxPowerMode
					if *rs.TxPowerMode == "custom" {
						if rs.TxPower == nil {
							return nil, fmt.Errorf("unifi: a custom transmit power needs a value in dBm")
						}
						r["tx_power"] = *rs.TxPower
					}
				}
				out[i], found = r, true
			}
			if !found {
				return nil, fmt.Errorf("unifi: %v has no %s GHz radio", dev["name"], rs.Band)
			}
		}
		body["radio_table"] = out
	}
	if ch.SSIDsOff != nil {
		radioName := map[string]string{} // ng -> wifi0
		for _, x := range table {
			if r, ok := x.(map[string]any); ok {
				code, _ := r["radio"].(string)
				radioName[code], _ = r["name"].(string)
			}
		}
		existing, _ := dev["wlan_overrides"].([]any)
		var out []any
		seen := map[string]bool{} // "wlan|code"
		for _, x := range existing {
			o, ok := x.(map[string]any)
			if !ok {
				continue
			}
			code, _ := o["radio"].(string)
			wid, _ := o["wlan_id"].(string)
			offList, managed := ch.SSIDsOff[bandOf(code)]
			if !managed {
				out = append(out, o)
				continue
			}
			o = cloneMap(o)
			o["enabled"] = !contains(offList, wid)
			seen[wid+"|"+code] = true
			out = append(out, o)
		}
		bands := make([]string, 0, len(ch.SSIDsOff))
		for b := range ch.SSIDsOff {
			bands = append(bands, b)
		}
		sort.Strings(bands)
		for _, b := range bands {
			code := radioCode(b)
			if code == "" {
				return nil, fmt.Errorf("unifi: unknown band %q", b)
			}
			for _, wid := range ch.SSIDsOff[b] {
				if seen[wid+"|"+code] {
					continue
				}
				o := map[string]any{"wlan_id": wid, "radio": code, "enabled": false}
				if n := radioName[code]; n != "" {
					o["radio_name"] = n
				}
				out = append(out, o)
			}
		}
		if out == nil {
			out = []any{}
		}
		body["wlan_overrides"] = out
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("unifi: nothing to change")
	}
	return body, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// UpdateWLAN implements drivers.WiFiWriter.
func (d Driver) UpdateWLAN(ctx context.Context, t drivers.Target, creds vault.Secret, ssidID string, ch drivers.WLANChange) error {
	return d.writeSession(ctx, t, creds, func(c *client) error {
		w, err := findWLAN(ctx, c, ssidID)
		if err != nil {
			return err
		}
		if err := applyWLANChange(w, ch); err != nil {
			return err
		}
		_, err = write[map[string]any](ctx, c, http.MethodPut, "rest/wlanconf/"+url.PathEscape(ssidID), w)
		return err
	})
}

// WLANPassphrase implements drivers.WiFiWriter.
func (d Driver) WLANPassphrase(ctx context.Context, t drivers.Target, creds vault.Secret, ssidID string) (string, error) {
	var pass string
	err := d.writeSession(ctx, t, creds, func(c *client) error {
		w, err := findWLAN(ctx, c, ssidID)
		if err != nil {
			return err
		}
		if sec, _ := w["security"].(string); sec != "wpapsk" {
			return fmt.Errorf("unifi: %v has no passphrase (security %q)", w["name"], sec)
		}
		pass, _ = w["x_passphrase"].(string)
		if pass == "" {
			return fmt.Errorf("unifi: the console did not return the passphrase of %v; the account NCC uses may not be allowed to see it", w["name"])
		}
		return nil
	})
	return pass, err
}

func findWLAN(ctx context.Context, c *client, id string) (map[string]any, error) {
	ws, err := getList[map[string]any](ctx, c, "rest/wlanconf")
	if err != nil {
		return nil, err
	}
	for _, w := range ws {
		if wid, _ := w["_id"].(string); wid == id {
			return w, nil
		}
	}
	return nil, fmt.Errorf("unifi: the Wi-Fi network %s no longer exists", id)
}

// applyWLANChange changes a raw WLAN object in place.
func applyWLANChange(w map[string]any, ch drivers.WLANChange) error {
	sec, _ := w["security"].(string)
	if ch.Name != nil {
		w["name"] = *ch.Name
	}
	if ch.Enabled != nil {
		w["enabled"] = *ch.Enabled
	}
	if ch.Hidden != nil {
		w["hide_ssid"] = *ch.Hidden
	}
	if ch.NetworkID != nil {
		w["networkconf_id"] = *ch.NetworkID
		// firmware that predates networkconf_id tags with vlan/vlan_enabled; the network wins
		delete(w, "vlan")
		delete(w, "vlan_enabled")
	}
	if ch.Security != nil {
		if sec == "wpaeap" || sec == "osen" {
			return fmt.Errorf("unifi: %v uses WPA Enterprise (RADIUS); change it in UniFi Network", w["name"])
		}
		w["security"] = "wpapsk"
		w["wpa_mode"] = "wpa2"
		w["wpa_enc"] = "ccmp"
		switch *ch.Security {
		case inv.SecWPA2:
			w["wpa3_support"], w["wpa3_transition"] = false, false
			if p, _ := w["pmf_mode"].(string); p == "required" {
				w["pmf_mode"] = "optional"
			}
		case inv.SecWPA2WPA3:
			w["wpa3_support"], w["wpa3_transition"] = true, true
			w["pmf_mode"] = "optional"
		case inv.SecWPA3:
			w["wpa3_support"], w["wpa3_transition"] = true, false
			w["pmf_mode"] = "required"
		default:
			return fmt.Errorf("unifi: NCC can set WPA2, WPA2/WPA3 or WPA3, not %q", *ch.Security)
		}
		sec = "wpapsk"
	}
	if ch.Bands != nil {
		var codes []string
		has := map[string]bool{}
		for _, b := range ch.Bands {
			code := map[string]string{"2.4": "2g", "5": "5g", "6": "6g"}[b]
			if code == "" {
				return fmt.Errorf("unifi: unknown band %q", b)
			}
			codes = append(codes, code)
			has[code] = true
		}
		if len(codes) == 0 {
			return fmt.Errorf("unifi: a Wi-Fi network needs at least one band")
		}
		w["wlan_bands"] = codes
		// older firmware reads wlan_band: both | 2g | 5g
		switch {
		case has["2g"] && has["5g"]:
			w["wlan_band"] = "both"
		case has["5g"]:
			w["wlan_band"] = "5g"
		case has["2g"]:
			w["wlan_band"] = "2g"
		}
	}
	if ch.Passphrase != nil {
		if sec != "wpapsk" {
			return fmt.Errorf("unifi: %v has no passphrase to change; set WPA2 or WPA3 security first", w["name"])
		}
		w["x_passphrase"] = *ch.Passphrase
	}
	if sec == "wpapsk" {
		if p, _ := w["x_passphrase"].(string); len(p) < 8 {
			return fmt.Errorf("unifi: %v needs a passphrase of at least 8 characters", w["name"])
		}
	}
	return nil
}
