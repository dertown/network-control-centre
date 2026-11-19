package unifi

import "strings"

// modelNames maps UniFi model codes (the "model" field of stat/device) to product names.
// The list is best effort: when a code is missing NCC still shows the raw code and the
// device type the controller reports, so discovery never fails on an unknown model.
// Newer controllers may also send a display name, which wins over this table.
var modelNames = map[string]string{
	// Gateways and consoles
	"UDR":       "Dream Router",
	"UDR7":      "Dream Router 7",
	"UDM":       "Dream Machine",
	"UDMPRO":    "Dream Machine Pro",
	"UDMPROSE":  "Dream Machine SE",
	"UDMPROMAX": "Dream Machine Pro Max",
	"UXG":       "Gateway Lite",
	"UXGPRO":    "Gateway Pro",
	"UCGMAX":    "Cloud Gateway Max",
	"UCGULTRA":  "Cloud Gateway Ultra",
	"UGW3":      "Security Gateway",
	"UGW4":      "Security Gateway Pro",

	// Access points
	"UAP6MP":  "U6 Pro",
	"UAL6":    "U6 Lite",
	"UALR6":   "U6 Long-Range",
	"UAE6":    "U6 Enterprise",
	"U6M":     "U6 Mesh",
	"U7PG2":   "AC Pro",
	"U7LT":    "AC Lite",
	"U7LR":    "AC Long-Range",
	"U7NHD":   "nanoHD",
	"UAPA6A4": "U6 In-Wall",

	// Switches
	"USMINI":   "Flex Mini",
	"USF5P":    "Switch Flex",
	"USL8LP":   "Switch Lite 8 PoE",
	"USL16LP":  "Switch Lite 16 PoE",
	"US8":      "Switch 8",
	"US8P60":   "Switch 8 60W",
	"US8P150":  "Switch 8 150W",
	"US16P150": "Switch 16 150W",
	"US24":     "Switch 24",
	"US24P250": "Switch 24 PoE 250W",
	"US24P500": "Switch 24 PoE 500W",
	"US48":     "Switch 48",
	"US48P500": "Switch 48 PoE 500W",
	"USXG":     "Switch 16 XG",
}

// kindFor maps the controller's device "type" to an NCC kind.
func kindFor(t string) string {
	switch strings.ToLower(t) {
	case "udm", "ugw", "uxg":
		return "gateway"
	case "usw":
		return "switch"
	case "uap":
		return "ap"
	default:
		return "unknown"
	}
}

// ModelName returns the product name for a code, preferring a name the controller supplied.
func ModelName(code, fromController string) string {
	if s := strings.TrimSpace(fromController); s != "" && !strings.EqualFold(s, code) {
		return s
	}
	if n, ok := modelNames[strings.ToUpper(code)]; ok {
		return n
	}
	return code
}

// lldpVendors recognises common vendors in an LLDP system description or name.
var lldpVendors = []struct{ key, make string }{
	{"ubiquiti", "Ubiquiti"}, {"unifi", "Ubiquiti"}, {"edgeswitch", "Ubiquiti"},
	{"cisco", "Cisco"}, {"meraki", "Cisco Meraki"},
	{"netgear", "NETGEAR"}, {"tp-link", "TP-Link"}, {"tplink", "TP-Link"}, {"omada", "TP-Link"},
	{"aruba", "HPE Aruba"}, {"procurve", "HPE"}, {"hewlett", "HPE"}, {"hpe ", "HPE"},
	{"juniper", "Juniper"}, {"junos", "Juniper"}, {"mikrotik", "MikroTik"}, {"routeros", "MikroTik"},
	{"d-link", "D-Link"}, {"zyxel", "Zyxel"}, {"dell", "Dell"}, {"arista", "Arista"},
	{"fortinet", "Fortinet"}, {"fortiswitch", "Fortinet"}, {"brocade", "Brocade"}, {"ruckus", "Ruckus"},
	{"extreme", "Extreme Networks"}, {"linksys", "Linksys"}, {"synology", "Synology"}, {"qnap", "QNAP"},
}

// GuessMake picks a vendor from free text (LLDP description, client OUI vendor).
func GuessMake(texts ...string) string {
	for _, t := range texts {
		lt := strings.ToLower(t)
		for _, v := range lldpVendors {
			if strings.Contains(lt, v.key) {
				return v.make
			}
		}
	}
	return ""
}
