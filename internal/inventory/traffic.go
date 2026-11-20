package inventory

import "time"

// AppUsage is traffic for one application or category, as identified by the gateway's
// deep packet inspection (DPI). Down is traffic to the client, Up is traffic from it.
type AppUsage struct {
	Cat       int    `json:"cat"`
	App       int    `json:"app"` // -1 for a whole category
	Category  string `json:"category"`
	Name      string `json:"name"` // application name, or the category name for a category row
	DownBytes int64  `json:"down_bytes"`
	UpBytes   int64  `json:"up_bytes"`
}

// Total is down plus up.
func (a AppUsage) Total() int64 { return a.DownBytes + a.UpBytes }

// ClientTraffic is what one client has sent and received.
type ClientTraffic struct {
	MAC     string `json:"mac"`
	Name    string `json:"name"`
	IP      string `json:"ip,omitempty"`
	Vendor  string `json:"vendor,omitempty"`
	Wired   bool   `json:"wired"`
	Network string `json:"network,omitempty"`
	SSID    string `json:"ssid,omitempty"`
	// Counters since the client last connected (all traffic, local and internet).
	DownBytes int64 `json:"down_bytes"`
	UpBytes   int64 `json:"up_bytes"`
	// Current rates in bytes per second.
	DownRate int64 `json:"down_rate"`
	UpRate   int64 `json:"up_rate"`
	Uptime   int64 `json:"uptime_s,omitempty"`
	// Internet traffic per application from the gateway's DPI, largest first.
	Apps []AppUsage `json:"apps,omitempty"`
}

// TrafficReport is one target's traffic picture at one moment.
type TrafficReport struct {
	Target  string          `json:"target"`
	TakenAt time.Time       `json:"taken_at"`
	Clients []ClientTraffic `json:"clients"`
	// Site-wide DPI totals per category, largest first.
	Categories []AppUsage `json:"categories,omitempty"`
	// DPI is true when the gateway returned application data.
	DPI bool `json:"dpi"`
	// DPINote explains why DPI data is missing.
	DPINote string `json:"dpi_note,omitempty"`
}
