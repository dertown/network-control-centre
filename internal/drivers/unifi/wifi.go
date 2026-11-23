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
// The passphrase (x_passphrase) is read on every poll only to tell whether it is short; it
// never goes into the snapshot.

var _ drivers.WiFiWriter = Driver{}

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
		for _, r := range d.RadioTable {
			band := bandOf(r.Radio)
			if band == "" {
				continue
			}
			rd := inv.Radio{
				DeviceID: mac, DeviceName: firstNonEmpty(d.Name, d.MAC), Online: d.State == 1, Band: band,
				Channel: r.Channel.N, ChannelAuto: r.Channel.Auto, WidthMHz: int(r.HT),
				TxPower: int(r.TxPower), TxPowerMode: strings.ToLower(r.TxPowerMode),
				Clients: perRadio[mac+"|"+band],
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
	return w
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
