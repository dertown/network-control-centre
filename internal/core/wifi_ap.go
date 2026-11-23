package core

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dertown/network-control-centre/internal/drivers"
	"github.com/dertown/network-control-centre/internal/inventory"
)

// Access point radios: per-radio channel, width and transmit power, which Wi-Fi networks each
// access point broadcasts on each band, and the quietest channel for a radio. Like SSID
// changes, this works from the latest snapshot: a change is planned (checked and described)
// before it is sent, and changes that would cut off NCC itself or a mesh access point are
// refused.

// Channels24 are the 2.4 GHz channels NCC offers. 12 and 13 are allowed outside North
// America only; 14 is Japan-only (802.11b) and refused.
var Channels24 = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}

// Channels5 are the 5 GHz channels, UNII-1 to UNII-3.
var Channels5 = []int{36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165}

// Channels6 are the 6 GHz channels (1, 5, 9 ... 233).
var Channels6 = func() []int {
	var out []int
	for c := 1; c <= 233; c += 4 {
		out = append(out, c)
	}
	return out
}()

// PSC6 are the 6 GHz preferred scanning channels: the ones clients look on first.
var PSC6 = []int{5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229}

// BandWidths are the channel widths each band allows, in MHz.
var BandWidths = map[string][]int{"2.4": {20, 40}, "5": {20, 40, 80, 160}, "6": {20, 40, 80, 160, 320}}

// TxPowerModes are the transmit power settings NCC can set.
var TxPowerModes = []string{"auto", "high", "medium", "low", "custom"}

func channelsOf(band string) []int {
	switch band {
	case "2.4":
		return Channels24
	case "5":
		return Channels5
	case "6":
		return Channels6
	}
	return nil
}

func hasInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func hasStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// IsDFS is a 5 GHz channel that shares the air with weather radar: the access point listens
// for a minute before using it and must leave it at once if radar shows up.
func IsDFS(band string, ch int) bool {
	return band == "5" && ch >= 52 && ch <= 144
}

// block5 lists the 5 GHz channel blocks of each width; a channel and width are valid together
// when the channel is inside one block.
var block5 = map[int][][]int{
	40:  {{36, 40}, {44, 48}, {52, 56}, {60, 64}, {100, 104}, {108, 112}, {116, 120}, {124, 128}, {132, 136}, {140, 144}, {149, 153}, {157, 161}},
	80:  {{36, 40, 44, 48}, {52, 56, 60, 64}, {100, 104, 108, 112}, {116, 120, 124, 128}, {132, 136, 140, 144}, {149, 153, 157, 161}},
	160: {{36, 40, 44, 48, 52, 56, 60, 64}, {100, 104, 108, 112, 116, 120, 124, 128}},
}

// span is the 20 MHz channels a radio on channel ch with width w occupies (for 2.4 GHz, the
// channel numbers its signal reaches into).
func span(band string, ch, w int) []int {
	switch band {
	case "2.4":
		// a 20 MHz channel is about 4 channel numbers wide each side; 40 MHz adds 4 more upwards
		lo, hi := ch-2, ch+2
		if w >= 40 {
			hi = ch + 6
		}
		var out []int
		for c := lo; c <= hi; c++ {
			out = append(out, c)
		}
		return out
	case "5":
		if w > 20 {
			for _, b := range block5[w] {
				if hasInt(b, ch) {
					return b
				}
			}
		}
		return []int{ch}
	case "6":
		if w > 20 {
			n := w / 20 // channels per block
			start := ((ch-1)/(4*n))*(4*n) + 1
			var out []int
			for c := start; c < start+4*n; c += 4 {
				out = append(out, c)
			}
			return out
		}
		return []int{ch}
	}
	return []int{ch}
}

func overlaps(a, b []int) bool {
	for _, x := range a {
		if hasInt(b, x) {
			return true
		}
	}
	return false
}

// CheckChannel checks a channel and width for a band. channel 0 is auto.
func CheckChannel(band string, channel, width int) error {
	widths := BandWidths[band]
	if widths == nil {
		return fmt.Errorf("unknown band %q", band)
	}
	if width != 0 && !hasInt(widths, width) {
		return fmt.Errorf("%s GHz radios can use %s MHz channels, not %d MHz", band, joinInts(widths), width)
	}
	if channel == 0 {
		return nil
	}
	if !hasInt(channelsOf(band), channel) {
		if band == "2.4" && channel == 14 {
			return fmt.Errorf("channel 14 is only allowed in Japan, for old 802.11b devices")
		}
		return fmt.Errorf("%d is not a %s GHz channel", channel, band)
	}
	if band == "5" && width > 20 {
		ok := false
		for _, b := range block5[width] {
			ok = ok || hasInt(b, channel)
		}
		if !ok {
			return fmt.Errorf("channel %d can't be used %d MHz wide; pick a narrower width or another channel", channel, width)
		}
	}
	return nil
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = fmt.Sprint(x)
	}
	return joinAnd(s)
}

// ChannelSuggestion is the quietest channel NCC finds for one radio.
type ChannelSuggestion struct {
	DeviceID string `json:"device_id"`
	Device   string `json:"device"`
	Band     string `json:"band"`
	// Current is the channel the radio is on now; Channel the suggested one; WidthMHz the
	// suggested width (2.4 GHz is always 20 MHz).
	Current  int `json:"current"`
	Channel  int `json:"channel"`
	WidthMHz int `json:"width_mhz"`
	// Better is set when the suggestion is quieter than where the radio is now.
	Better bool   `json:"better"`
	Reason string `json:"reason"`
	// Options are the candidate channels, quietest first.
	Options []ChannelOption `json:"options"`
}

// ChannelOption is one candidate channel and what shares it.
type ChannelOption struct {
	Channel int `json:"channel"`
	// Score is how crowded it is: lower is quieter.
	Score int `json:"score"`
	// Own are your access points that overlap it; Neighbors the number of other networks heard.
	Own       []string `json:"own,omitempty"`
	Neighbors int      `json:"neighbors"`
	DFS       bool     `json:"dfs,omitempty"`
}

// candidates are the channels worth suggesting for a band and width: the three that don't
// overlap on 2.4 GHz, the start of each block on 5 and 6 GHz.
func candidates(band string, width int) []int {
	switch band {
	case "2.4":
		return []int{1, 6, 11}
	case "5":
		if width <= 20 {
			return []int{36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165}
		}
		var out []int
		for _, b := range block5[width] {
			out = append(out, b[0])
		}
		return out
	case "6":
		return PSC6 // clients look for 6 GHz networks on these first
	}
	return nil
}

// SuggestChannel finds the quietest channel for one radio, from the other access points' channels
// and how busy they are, and the neighbouring networks the access points hear.
func SuggestChannel(snap *inventory.Snapshot, deviceID, band string) (*ChannelSuggestion, error) {
	if snap == nil || snap.WiFi == nil {
		return nil, fmt.Errorf("NCC has not read this router's Wi-Fi yet")
	}
	var me *inventory.Radio
	for i, r := range snap.WiFi.Radios {
		if r.DeviceID == deviceID && r.Band == band {
			me = &snap.WiFi.Radios[i]
		}
	}
	if me == nil {
		return nil, fmt.Errorf("no %s GHz radio on access point %s", band, deviceID)
	}
	width := me.WidthMHz
	if band == "2.4" || width == 0 {
		width = 20
	}
	if band == "5" && width > 160 {
		width = 160
	}
	sug := &ChannelSuggestion{DeviceID: deviceID, Device: me.DeviceName, Band: band, Current: me.Channel, WidthMHz: width}
	if band == "5" {
		for _, l := range snap.Links {
			if l.Medium == "wireless" && l.B == deviceID {
				// a mesh access point has to stay on its parent's channel
				sug.Channel, sug.WidthMHz = me.Channel, me.WidthMHz
				sug.Options = []ChannelOption{}
				sug.Reason = me.DeviceName + " connects over 5 GHz Wi-Fi (mesh), so it stays on the channel of the access point it connects through."
				return sug, nil
			}
		}
	}
	score := func(ch int) ChannelOption {
		o := ChannelOption{Channel: ch, DFS: IsDFS(band, ch)}
		mine := span(band, ch, width)
		for _, r := range snap.WiFi.Radios {
			if r.Band != band || r.DeviceID == deviceID || !r.Online || r.Channel == 0 {
				continue
			}
			if overlaps(mine, span(band, r.Channel, max(r.WidthMHz, 20))) {
				o.Own = append(o.Own, r.DeviceName)
				// another of your own access points in the same air: they take turns
				o.Score += 30 + r.Utilization/2
				if r.Channel == ch {
					o.Score += 10
				}
			}
		}
		for _, n := range snap.WiFi.Neighbors {
			if n.Band != band || (n.SeenBy != "" && n.SeenBy != deviceID && hasNeighborsBy(snap, deviceID)) {
				continue
			}
			if overlaps(mine, span(band, n.Channel, 20)) {
				o.Neighbors++
				switch {
				case n.Signal >= -60:
					o.Score += 12
				case n.Signal >= -70:
					o.Score += 6
				default:
					o.Score += 2
				}
			}
		}
		if o.DFS {
			o.Score += 8 // radar can force a move, and the radio is silent for a minute after one
		}
		if band == "5" && ch == 165 {
			o.Score += 4 // only 20 MHz wide, and some older clients don't see it
		}
		return o
	}
	for _, ch := range candidates(band, width) {
		sug.Options = append(sug.Options, score(ch))
	}
	sort.SliceStable(sug.Options, func(i, j int) bool { return sug.Options[i].Score < sug.Options[j].Score })
	if len(sug.Options) == 0 {
		return nil, fmt.Errorf("no channels to suggest for %s GHz", band)
	}
	best := sug.Options[0]
	sug.Channel = best.Channel
	cur := score(me.Channel)
	if me.Channel == 0 {
		cur.Score = 1 << 20
	}
	// the radio's own block counts as where it is now
	inCurrent := me.Channel != 0 && hasInt(span(band, me.Channel, width), best.Channel)
	sug.Better = !inCurrent && best.Score+5 < cur.Score
	if band == "2.4" && me.WidthMHz > 20 {
		sug.Better = true
	}
	if band == "2.4" && me.Channel != 0 && !hasInt([]int{1, 6, 11}, me.Channel) {
		sug.Better = true
	}
	if inCurrent && !sug.Better {
		sug.Channel = me.Channel
	}
	var why []string
	if len(best.Own) == 0 {
		why = append(why, "none of your other access points use it")
	} else {
		why = append(why, "it is shared only with "+joinAnd(best.Own))
	}
	switch best.Neighbors {
	case 0:
		why = append(why, "no neighbouring networks were heard on it")
	case 1:
		why = append(why, "1 neighbouring network was heard on it")
	default:
		why = append(why, fmt.Sprintf("%d neighbouring networks were heard on it", best.Neighbors))
	}
	if !sug.Better {
		sug.Reason = fmt.Sprintf("%s is already on the quietest channel NCC can find (%s).", me.DeviceName, strings.Join(why, ", "))
		if me.Utilization >= 70 {
			sug.Reason += " The channel is busy from its own clients: move fast devices to 5 GHz, or add an access point."
		}
		return sug, nil
	}
	sug.Reason = fmt.Sprintf("Channel %d is the quietest for %s on %s GHz: %s.", best.Channel, me.DeviceName, band, strings.Join(why, ", "))
	if len(cur.Own) > 0 && me.Channel != 0 {
		sug.Reason += fmt.Sprintf(" Channel %d is shared with %s.", me.Channel, joinAnd(cur.Own))
	}
	return sug, nil
}

// hasNeighborsBy reports whether the access point itself reported neighbours; when it did,
// only what it heard counts (others may be out of its range).
func hasNeighborsBy(snap *inventory.Snapshot, deviceID string) bool {
	for _, n := range snap.WiFi.Neighbors {
		if n.SeenBy == deviceID {
			return true
		}
	}
	return false
}

// ChannelSuggestions are the suggestions for every online radio. They are worked out together:
// the radio that most needs a move goes first, and the others are suggested as if it had
// moved, so two access points are never both sent to the same quiet channel.
func ChannelSuggestions(snap *inventory.Snapshot) []ChannelSuggestion {
	out := []ChannelSuggestion{}
	if snap == nil || snap.WiFi == nil {
		return out
	}
	work := *snap
	wifi := *snap.WiFi
	wifi.Radios = append([]inventory.Radio(nil), snap.WiFi.Radios...)
	work.WiFi = &wifi
	// worst first: radios that should move, the busiest of those first
	type need struct {
		i     int
		score int
	}
	var order []need
	for i, r := range wifi.Radios {
		if !r.Online {
			continue
		}
		if s, err := SuggestChannel(&work, r.DeviceID, r.Band); err == nil {
			sc := 0
			for _, o := range s.Options {
				if o.Channel == s.Current {
					sc = o.Score
				}
			}
			if s.Better {
				sc += 10000
			}
			// the busiest radio suffers most, so it picks first
			order = append(order, need{i, sc + r.Utilization*10})
		}
	}
	sort.SliceStable(order, func(a, b int) bool { return order[a].score > order[b].score })
	byIndex := map[int]ChannelSuggestion{}
	for _, n := range order {
		r := wifi.Radios[n.i]
		s, err := SuggestChannel(&work, r.DeviceID, r.Band)
		if err != nil {
			continue
		}
		if s.Better {
			wifi.Radios[n.i].Channel, wifi.Radios[n.i].WidthMHz = s.Channel, s.WidthMHz
		}
		byIndex[n.i] = *s
	}
	for i := range wifi.Radios {
		if s, ok := byIndex[i]; ok {
			out = append(out, s)
		}
	}
	return out
}

// APSSIDToggle switches one Wi-Fi network on or off on one band of an access point.
type APSSIDToggle struct {
	SSIDID string `json:"ssid_id"`
	Band   string `json:"band"`
	On     bool   `json:"on"`
}

// APRequest is a requested change to one access point.
type APRequest struct {
	Radios []drivers.RadioSetting `json:"radios"`
	SSIDs  []APSSIDToggle         `json:"ssids"`
}

// Safety is what NCC knows about connections that must not be cut: the addresses of the
// person making the change and of NCC itself.
type Safety struct {
	ViewerIP string
	SelfIPs  []string
}

// APPlan is the preview of a change to one access point.
type APPlan struct {
	DeviceID string           `json:"device_id"`
	Device   string           `json:"device"`
	Changes  []WiFiChangeLine `json:"changes"`
	Warnings []string         `json:"warnings"`
	// Resolves are the findings about this access point the change fixes; Remaining those it leaves.
	Resolves  []WiFiFinding `json:"resolves"`
	Remaining []WiFiFinding `json:"remaining"`
	// Change is what is sent to the router.
	Change drivers.APChange `json:"change"`
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func channelText(ch int) string {
	if ch == 0 {
		return "auto"
	}
	return fmt.Sprint(ch)
}

func powerText(mode string, dbm int) string {
	switch mode {
	case "", "auto":
		return "auto"
	case "custom":
		return fmt.Sprintf("%d dBm", dbm)
	}
	return mode
}

// broadcasts reports whether an access point broadcasts an SSID on a band, given its radio.
func broadcasts(s inventory.SSID, r inventory.Radio, off []string) bool {
	return s.Enabled && hasStr(s.Bands, r.Band) && !hasStr(off, s.ID)
}

// PlanAPChange checks a change to one access point against the snapshot and says what it does.
func PlanAPChange(snap *inventory.Snapshot, deviceID string, req APRequest, safe Safety) (*APPlan, error) {
	if snap == nil || snap.WiFi == nil {
		return nil, fmt.Errorf("NCC has not read this router's Wi-Fi yet; wait for the next refresh")
	}
	radios := map[string]*inventory.Radio{}
	var name string
	online := false
	for i, r := range snap.WiFi.Radios {
		if r.DeviceID == deviceID {
			radios[r.Band] = &snap.WiFi.Radios[i]
			name, online = r.DeviceName, r.Online
		}
	}
	if len(radios) == 0 {
		return nil, fmt.Errorf("no access point with id %q on %s", deviceID, snap.Target)
	}
	p := &APPlan{DeviceID: deviceID, Device: name, Changes: []WiFiChangeLine{}, Warnings: []string{}}
	warn := func(f string, a ...any) { p.Warnings = append(p.Warnings, fmt.Sprintf(f, a...)) }
	ssid := func(id string) *inventory.SSID {
		for i := range snap.WiFi.SSIDs {
			if snap.WiFi.SSIDs[i].ID == id {
				return &snap.WiFi.SSIDs[i]
			}
		}
		return nil
	}

	// who is on this access point, by band and SSID
	type conn struct {
		who  string
		band string
		ssid string
	}
	var mustKeep []conn // connections that must not be cut: the viewer's and NCC's own
	onBand := map[string]int{}
	onSSIDBand := map[string]int{} // "ssid|band"
	for _, c := range snap.Clients {
		if c.Wired || c.APMAC != deviceID {
			continue
		}
		onBand[c.Band]++
		onSSIDBand[c.SSID+"|"+c.Band]++
		if c.IP == "" {
			continue
		}
		switch {
		case c.IP == safe.ViewerIP:
			mustKeep = append(mustKeep, conn{"your own connection to NCC (" + firstOf(c.Name, c.IP) + ")", c.Band, c.SSID})
		case hasStr(safe.SelfIPs, c.IP):
			mustKeep = append(mustKeep, conn{"NCC's own connection (" + c.IP + ")", c.Band, c.SSID})
		}
	}

	// mesh: access points that reach the network over Wi-Fi through this one, or this one's
	// own wireless uplink. UniFi meshes over 5 GHz.
	var meshKids []string
	meshParent := ""
	names := map[string]string{}
	for _, d := range snap.Devices {
		names[d.ID] = d.Name
	}
	for _, l := range snap.Links {
		if l.Medium != "wireless" || names[l.A] == "" || names[l.B] == "" {
			continue
		}
		if l.A == deviceID {
			meshKids = append(meshKids, names[l.B])
		}
		if l.B == deviceID {
			meshParent = l.A
		}
	}
	sort.Strings(meshKids)

	next := map[string]inventory.Radio{}
	for b, r := range radios {
		next[b] = *r
	}
	change := drivers.APChange{}
	seenBand := map[string]bool{}
	for _, rs := range req.Radios {
		r, ok := radios[rs.Band]
		if !ok {
			return nil, fmt.Errorf("%s has no %s GHz radio", name, rs.Band)
		}
		if seenBand[rs.Band] {
			return nil, fmt.Errorf("%s GHz is listed twice", rs.Band)
		}
		seenBand[rs.Band] = true
		n := next[rs.Band]
		out := drivers.RadioSetting{Band: rs.Band}
		label := rs.Band + " GHz "
		curCh := r.Channel
		if r.ChannelAuto {
			curCh = 0
		}
		ch, width := curCh, r.WidthMHz
		if rs.Channel != nil {
			ch = *rs.Channel
		}
		if rs.WidthMHz != nil {
			width = *rs.WidthMHz
		}
		if err := CheckChannel(rs.Band, ch, width); err != nil {
			return nil, fmt.Errorf("%s: %v", name, err)
		}
		moved := false
		if rs.Channel != nil && *rs.Channel != curCh {
			c := *rs.Channel
			out.Channel = &c
			from := channelText(curCh)
			if curCh == 0 && r.Channel > 0 {
				from = fmt.Sprintf("auto (now %d)", r.Channel)
			}
			p.Changes = append(p.Changes, WiFiChangeLine{label + "channel", from, channelText(c)})
			n.Channel, n.ChannelAuto, moved = c, c == 0, true
			if c == 0 {
				n.Channel = r.Channel
			}
			if rs.Band == "2.4" && (c == 12 || c == 13) {
				warn("Channels 12 and 13 are not allowed in the US and Canada, and many devices sold there can't see them.")
			}
			if IsDFS(rs.Band, c) {
				warn("Channel %d is a DFS (radar) channel: %s stays silent for about a minute before using it, and moves away on its own if it hears weather radar.", c, name)
			}
		}
		if rs.WidthMHz != nil && *rs.WidthMHz != r.WidthMHz {
			w := *rs.WidthMHz
			out.WidthMHz = &w
			from := "—"
			if r.WidthMHz > 0 {
				from = fmt.Sprintf("%d MHz", r.WidthMHz)
			}
			p.Changes = append(p.Changes, WiFiChangeLine{label + "width", from, fmt.Sprintf("%d MHz", w)})
			n.WidthMHz, moved = w, true
			if rs.Band == "2.4" && w > 20 {
				warn("40 MHz on 2.4 GHz overlaps most of the band, so it slows down your other access points and your neighbours'. 20 MHz is almost always faster in practice.")
			}
			if w == 320 {
				warn("320 MHz needs a Wi-Fi 7 access point and Wi-Fi 7 clients; others stay at 160 MHz or less.")
			}
			if w > r.WidthMHz && r.WidthMHz > 0 && rs.Band != "2.4" {
				warn("Wider channels are faster up close but reach less far, and share the air with more neighbours.")
			}
		}
		if rs.TxPowerMode != nil {
			mode := strings.ToLower(*rs.TxPowerMode)
			if !hasStr(TxPowerModes, mode) {
				return nil, fmt.Errorf("transmit power must be auto, high, medium, low or custom, not %q", *rs.TxPowerMode)
			}
			dbm := 0
			if mode == "custom" {
				if rs.TxPower == nil || *rs.TxPower < 1 || *rs.TxPower > 30 {
					return nil, fmt.Errorf("a custom transmit power must be 1 to 30 dBm")
				}
				dbm = *rs.TxPower
			}
			curMode := r.TxPowerMode
			if curMode == "" {
				curMode = "auto"
			}
			if mode != curMode || (mode == "custom" && dbm != r.TxPower) {
				out.TxPowerMode = &mode
				if mode == "custom" {
					out.TxPower = &dbm
				}
				p.Changes = append(p.Changes, WiFiChangeLine{label + "transmit power", powerText(curMode, r.TxPower), powerText(mode, dbm)})
				n.TxPowerMode = mode
				if mode == "low" || (mode == "custom" && dbm < 12) || (mode == "medium" && (curMode == "high" || curMode == "auto")) {
					if r.Clients > 0 {
						warn("Lower power shrinks %s's %s GHz coverage: some of the %s on it may drop to another access point or lose Wi-Fi at the edges.", name, rs.Band, plural(r.Clients, "client", "clients"))
					} else {
						warn("Lower power shrinks %s's %s GHz coverage.", name, rs.Band)
					}
				}
			}
		}
		if moved {
			if r.Clients > 0 {
				warn("The %s on %s's %s GHz radio drop for a few seconds while it changes channel, then reconnect.", plural(r.Clients, "client", "clients"), name, rs.Band)
			}
			for _, k := range mustKeep {
				if k.band == rs.Band {
					warn("This includes %s: the page may stop responding for a few seconds.", k.who)
				}
			}
			if rs.Band == "5" && meshParent != "" {
				parent := next5(snap, meshParent)
				if out.Channel != nil && *out.Channel != 0 && parent > 0 && *out.Channel != parent {
					return nil, fmt.Errorf("%s connects to %s over Wi-Fi (mesh) on 5 GHz channel %d. A fixed channel %d would cut it off, with everything behind it; leave it on auto or channel %d", name, names[meshParent], parent, *out.Channel, parent)
				}
				warn("%s reaches the network over Wi-Fi (mesh) through %s: it may drop off for up to a minute while the link settles.", name, names[meshParent])
			}
			if rs.Band == "5" && len(meshKids) > 0 {
				warn("%s connect%s to the network through %s over 5 GHz Wi-Fi (mesh). %s follow%s the new channel, but drop off for up to a minute with all their clients.",
					joinAnd(meshKids), map[bool]string{true: "s", false: ""}[len(meshKids) == 1], name, joinAnd(meshKids), map[bool]string{true: "s", false: ""}[len(meshKids) == 1])
				if out.Channel != nil && IsDFS("5", *out.Channel) {
					warn("A radar event on a DFS channel would also cut the mesh link to %s until the radios move.", joinAnd(meshKids))
				}
			}
		}
		if out.Channel != nil || out.WidthMHz != nil || out.TxPowerMode != nil {
			change.Radios = append(change.Radios, out)
		}
		next[rs.Band] = n
	}

	// which networks this access point broadcasts on each band
	offNow := map[string][]string{}
	offNext := map[string][]string{}
	for b, r := range radios {
		offNow[b] = append([]string(nil), r.SSIDsOff...)
		offNext[b] = append([]string(nil), r.SSIDsOff...)
	}
	touched := map[string]bool{}
	for _, t := range req.SSIDs {
		s := ssid(t.SSIDID)
		if s == nil {
			return nil, fmt.Errorf("no Wi-Fi network with id %q on %s", t.SSIDID, snap.Target)
		}
		if _, ok := radios[t.Band]; !ok {
			return nil, fmt.Errorf("%s has no %s GHz radio", name, t.Band)
		}
		isOff := hasStr(offNext[t.Band], s.ID)
		if t.On == !isOff {
			continue
		}
		if t.On && !hasStr(s.Bands, t.Band) {
			return nil, fmt.Errorf("%s is not set to use %s GHz at all; add the band to the Wi-Fi network first", s.Name, t.Band)
		}
		if t.On {
			var keep []string
			for _, id := range offNext[t.Band] {
				if id != s.ID {
					keep = append(keep, id)
				}
			}
			offNext[t.Band] = keep
		} else {
			offNext[t.Band] = append(offNext[t.Band], s.ID)
		}
		touched[t.Band] = true
		p.Changes = append(p.Changes, WiFiChangeLine{fmt.Sprintf("%s on %s GHz", s.Name, t.Band), onOff(!t.On), onOff(t.On)})
		if !t.On {
			if n := onSSIDBand[s.Name+"|"+t.Band]; n > 0 {
				msg := fmt.Sprintf("The %s on %s at %s GHz move to another band or access point, or lose Wi-Fi if they can't.", plural(n, "device", "devices"), s.Name, t.Band)
				if t.Band == "2.4" {
					msg += " Many smart plugs, bulbs and cameras only have 2.4 GHz."
				}
				p.Warnings = append(p.Warnings, msg)
			}
		}
	}
	if len(touched) > 0 {
		change.SSIDsOff = map[string][]string{}
		for b := range touched {
			sort.Strings(offNext[b])
			change.SSIDsOff[b] = append([]string{}, offNext[b]...)
		}
	}

	// refuse what would cut NCC (or the person) off, or a mesh access point
	airNext := func(band string) []string {
		var out []string
		r := next[band]
		for _, s := range snap.WiFi.SSIDs {
			if broadcasts(s, r, offNext[band]) {
				out = append(out, s.Name)
			}
		}
		return out
	}
	airNow := func(band string) int {
		n := 0
		for _, s := range snap.WiFi.SSIDs {
			if broadcasts(s, *radios[band], offNow[band]) {
				n++
			}
		}
		return n
	}
	bands := sortedBands(radios)
	anyOnNext := false
	for _, b := range bands {
		on := airNext(b)
		anyOnNext = anyOnNext || len(on) > 0
		if touched[b] && len(on) == 0 && airNow(b) > 0 {
			p.Changes = append(p.Changes, WiFiChangeLine{b + " GHz radio", "broadcasting", "no Wi-Fi networks (off)"})
			if onBand[b] > 0 {
				warn("%s stops broadcasting on %s GHz: the %s on it move to another band or access point, or lose Wi-Fi.", name, b, plural(onBand[b], "client", "clients"))
			}
			if b == "5" && (meshParent != "" || len(meshKids) > 0) {
				who := joinAnd(meshKids)
				if meshParent != "" {
					who = name + " (through " + names[meshParent] + ")"
				}
				return nil, fmt.Errorf("%s reaches the network over 5 GHz Wi-Fi (mesh). NCC won't switch off 5 GHz on %s, so the mesh can't be cut; cable it first, or change it in UniFi Network", who, name)
			}
		}
	}
	for _, k := range mustKeep {
		if !anyOnNext {
			return nil, fmt.Errorf("%s would stop broadcasting Wi-Fi altogether, which cuts %s. Leave at least one band on, or make the change from a wired connection", name, k.who)
		}
		if !hasStr(airNext(k.band), k.ssid) {
			stillHere := false
			for _, b := range bands {
				if b != k.band && hasStr(airNext(b), k.ssid) {
					stillHere = true
				}
			}
			if !stillHere && !elsewhere(snap, deviceID, k.ssid) {
				return nil, fmt.Errorf("%s is on %s through %s, and nothing else would broadcast %s after this change. Keep %s on, or make the change from a wired connection", k.who, k.ssid, name, k.ssid, k.ssid)
			}
			warn("%s is on %s at %s GHz: it drops and has to rejoin %s on another band or access point.", capFirst(k.who), k.ssid, k.band, k.ssid)
		}
	}
	if len(p.Changes) == 0 {
		return nil, fmt.Errorf("nothing to change")
	}
	if !online {
		warn("%s is offline. The router keeps the new settings and sends them when it reconnects.", name)
	}

	// findings before and after
	after := *snap
	wifi := *snap.WiFi
	wifi.Radios = append([]inventory.Radio(nil), snap.WiFi.Radios...)
	for i, r := range wifi.Radios {
		if r.DeviceID != deviceID {
			continue
		}
		n := next[r.Band]
		if n.Channel != r.Channel {
			n.Utilization = 0 // measured again on the new channel
		}
		n.SSIDsOff = offNext[r.Band]
		wifi.Radios[i] = n
	}
	after.WiFi = &wifi
	mine := func(fs []WiFiFinding) []WiFiFinding {
		out := []WiFiFinding{}
		for _, f := range fs {
			if f.DeviceID == deviceID || (f.Kind == "same-channel" && strings.Contains(", "+f.Device+", ", ", "+name+", ")) {
				out = append(out, f)
			}
		}
		return out
	}
	before, later := mine(WiFiFindings(snap)), mine(WiFiFindings(&after))
	p.Remaining, p.Resolves = later, []WiFiFinding{}
	for _, f := range before {
		kept := false
		for _, g := range later {
			kept = kept || (g.Kind == f.Kind && g.Summary == f.Summary)
		}
		if !kept {
			p.Resolves = append(p.Resolves, f)
		}
	}
	p.Change = change
	return p, nil
}

// next5 is the 5 GHz channel an access point is on now, 0 when unknown.
func next5(snap *inventory.Snapshot, deviceID string) int {
	for _, r := range snap.WiFi.Radios {
		if r.DeviceID == deviceID && r.Band == "5" {
			return r.Channel
		}
	}
	return 0
}

// elsewhere reports whether another online access point broadcasts an SSID.
func elsewhere(snap *inventory.Snapshot, deviceID, ssidName string) bool {
	for _, s := range snap.WiFi.SSIDs {
		if s.Name != ssidName {
			continue
		}
		for _, r := range snap.WiFi.Radios {
			if r.DeviceID != deviceID && r.Online && broadcasts(s, r, r.SSIDsOff) {
				return true
			}
		}
	}
	return false
}

func sortedBands(m map[string]*inventory.Radio) []string {
	out := make([]string, 0, len(m))
	for b := range m {
		out = append(out, b)
	}
	order := map[string]int{"2.4": 0, "5": 1, "6": 2}
	sort.Slice(out, func(i, j int) bool { return order[out[i]] < order[out[j]] })
	return out
}

func firstOf(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

func capFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
