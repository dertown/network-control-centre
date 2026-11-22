// Package iot keeps NCC's inventory of IoT devices: cameras, printers, desk phones, room
// systems, displays, door and badge controllers, building (HVAC) controllers, UPSs,
// sensors, smart plugs and speakers. Devices are found among the network's clients by
// vendor and name, and people add the ones NCC misses. Each device carries where it is
// (site, building, floor, room), who owns it, and whether it is on an IoT network.
package iot

import "strings"

// Device types.
const (
	TypeCamera     = "camera"     // IP cameras, NVRs, doorbells
	TypePrinter    = "printer"    // printers, label printers, scanners
	TypePhone      = "phone"      // VoIP desk and conference phones
	TypeConference = "conference" // meeting-room systems, wireless presentation
	TypeDisplay    = "display"    // signage players, TVs, media streamers
	TypeAccess     = "access"     // door controllers, badge readers, intercoms, smart locks
	TypeBuilding   = "building"   // HVAC, BMS controllers, thermostats
	TypePower      = "power"      // UPSs, PDUs, smart plugs and switches
	TypeSensor     = "sensor"     // environment, air quality, leak and occupancy sensors
	TypeLighting   = "lighting"   // smart lighting
	TypeSpeaker    = "speaker"    // voice assistants, networked speakers
	TypeOther      = "other"      // IoT, but none of the above
)

// Types lists the device types in display order.
var Types = []string{TypeCamera, TypeAccess, TypePrinter, TypePhone, TypeConference, TypeDisplay, TypeBuilding, TypeSensor,
	TypePower, TypeLighting, TypeSpeaker, TypeOther}

// ValidType reports whether t is a known type.
func ValidType(t string) bool {
	for _, x := range Types {
		if x == t {
			return true
		}
	}
	return false
}

type rule struct {
	typ   string
	words []string
}

// vendorRules map OUI vendor names to a type. A vendor that also makes laptops or phones
// (Samsung, LG, Cisco, HP...) is only counted when the name agrees, see nameRules.
var vendorRules = []rule{
	{TypeCamera, []string{"axis communications", "hikvision", "dahua", "hanwha", "vivotek", "avigilon", "verkada", "mobotix", "uniview",
		"reolink", "amcrest", "arlo", "wyze", "ezviz", "eufy", "ring llc", "milestone", "lorex", "swann", "pelco", "bosch security", "i-pro", "panasonic i-pro"}},
	{TypePrinter, []string{"brother", "xerox", "lexmark", "kyocera", "ricoh", "konica", "sharp corp", "zebra", "epson", "seiko epson", "toshiba tec",
		"oki data", "canon"}},
	{TypePhone, []string{"polycom", "poly ", "yealink", "grandstream", "snom", "avaya", "mitel", "fanvil", "htek", "gigaset", "spectralink", "obihai"}},
	{TypeConference, []string{"crestron", "extron", "barco", "neat", "owl labs", "huddly", "logitech", "jabra", "airtame", "mersive", "q-sys", "qsc", "biamp", "shure"}},
	{TypeDisplay, []string{"brightsign", "roku", "appspace", "screenly", "iadea", "philips professional"}},
	{TypeAccess, []string{"hid global", "genetec", "paxton", "brivo", "openpath", "kisi", "2n telekomunikace", "akuvox", "lenel", "gallagher",
		"suprema", "zkteco", "assa abloy", "salto", "yale", "august home", "allegion", "schlage", "nuki", "doorbird", "chamberlain", "myq"}},
	{TypeBuilding, []string{"honeywell", "resideo", "johnson controls", "siemens building", "schneider electric", "trane", "carrier", "daikin",
		"distech", "tridium", "belimo", "delta controls", "automated logic", "ecobee", "tado", "nest labs", "google nest", "mitsubishi electric",
		"lennox", "netatmo"}},
	{TypePower, []string{"american power conversion", "eaton", "cyberpower", "vertiv", "liebert", "raritan", "server technology", "tripp lite",
		"shelly", "sonoff", "itead", "meross", "kasa", "tuya", "wemo", "belkin"}},
	{TypeSensor, []string{"airthings", "awair", "kaiterra", "milesight", "disruptive", "netatmo", "aqara", "lumi united", "withings", "sensorpush",
		"monnit", "temptrax", "emporia", "senseware", "butlr"}},
	{TypeLighting, []string{"signify", "philips lighting", "lifx", "nanoleaf", "yeelight", "govee", "wiz connected", "lutron", "casambi", "enlighted"}},
	{TypeSpeaker, []string{"sonos", "amazon technologies", "bose", "denon", "bluesound", "harman"}},
	{TypeOther, []string{"espressif", "silicon labs", "nordic semi", "particle industries", "xiaomi", "broadlink", "smartthings", "irobot", "rachio", "midea"}},
}

// nameRules map words in a device's name (hostname or alias) to a type. They win over a
// vendor's type, so "lobby-display" by Samsung is a display and "hp-printer-2f" a printer.
// A word matches a whole word of the name, or the start of one when it is 4+ letters
// ("printer2f", "cameras"), so "ups" doesn't match "backups".
var nameRules = []rule{
	{TypeCamera, []string{"cam", "camera", "webcam", "nvr", "dvr", "doorbell", "ipc", "cctv"}},
	{TypePrinter, []string{"printer", "print", "mfp", "copier", "plotter", "label", "scanner", "laserjet", "officejet"}},
	{TypePhone, []string{"voip", "sip", "deskphone", "ipphone", "polycom", "yealink", "ccx", "vvx", "handset"}},
	{TypeConference, []string{"zoomroom", "mtr", "clickshare", "conf", "boardroom", "meetingroom", "huddle", "rally", "meetup"}},
	{TypeDisplay, []string{"display", "signage", "kiosk", "screen", "tv", "chromecast", "appletv", "firetv", "roku", "brightsign"}},
	{TypeAccess, []string{"door", "badge", "reader", "intercom", "acs", "turnstile", "lock", "keypad"}},
	{TypeBuilding, []string{"hvac", "bms", "bacnet", "ahu", "vav", "chiller", "boiler", "thermostat", "rtu", "fcu", "jace"}},
	{TypePower, []string{"ups", "pdu", "plug", "outlet", "smartplug"}},
	{TypeSensor, []string{"sensor", "temp", "humidity", "co2", "airq", "leak", "occupancy", "env", "probe"}},
	{TypeLighting, []string{"light", "lights", "lamp", "bulb", "dali", "lutron"}},
	{TypeSpeaker, []string{"echo", "alexa", "sonos", "speaker", "homepod", "nestmini", "googlehome"}},
	{TypeOther, []string{"iot"}},
}

// ambiguous vendors make computers and phones as well as IoT gear; they count only when the
// name says what the device is.
var ambiguous = []string{"samsung", "lg electronics", "hewlett", "hp inc", "cisco", "apple", "google", "microsoft", "dell", "lenovo",
	"intel", "raspberry", "ubiquiti", "sony", "panasonic", "huawei", "zte", "tp-link", "realtek", "azurewave", "murata", "liteon", "nvidia"}

// Classify guesses whether a network client is an IoT device, and which type, from its
// OUI vendor and its name. ok is false for computers, phones and anything unknown.
func Classify(vendor, name string) (typ string, ok bool) {
	v := strings.ToLower(vendor)
	if t := matchWords(nameRules, words(name)); t != "" {
		// a laptop named "tv-lounge" is rare; a phone named "doorbell" rarer still
		return t, true
	}
	for _, a := range ambiguous {
		if strings.Contains(v, a) {
			return "", false
		}
	}
	if t := match(vendorRules, v); t != "" {
		return t, true
	}
	return "", false
}

func match(rules []rule, s string) string {
	if s == "" {
		return ""
	}
	for _, r := range rules {
		for _, w := range r.words {
			if strings.Contains(s, w) {
				return r.typ
			}
		}
	}
	return ""
}

// words splits a name into lowercase words at anything that isn't a letter or digit, and
// also returns the whole name with separators removed ("zoom-room" gives "zoomroom").
func words(s string) []string {
	s = strings.ToLower(s)
	ws := strings.FieldsFunc(s, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') })
	if len(ws) > 1 {
		ws = append(ws, strings.Join(ws, ""))
	}
	return ws
}

// matchWords returns the type of the first word of the name that a rule knows, so
// "ups-server-room" is a UPS and "cam-boardroom" a camera.
func matchWords(rules []rule, ws []string) string {
	for _, x := range ws {
		for _, r := range rules {
			for _, w := range r.words {
				if x == w || len(w) >= 4 && strings.HasPrefix(x, w) {
					return r.typ
				}
			}
		}
	}
	return ""
}

// IsIoTNetwork guesses whether a network is meant for IoT devices from its name, e.g.
// "IoT", "Cameras", "BMS", "Building systems", "OT".
func IsIoTNetwork(name string) bool {
	for _, w := range words(name) {
		for _, k := range []string{"iot", "ot", "cctv", "camera", "cameras", "bms", "building", "facilities", "smart", "devices", "sensors"} {
			if w == k {
				return true
			}
		}
	}
	return false
}
