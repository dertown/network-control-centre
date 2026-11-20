package unifi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	inv "github.com/dertown/network-control-centre/internal/inventory"
)

// dpiCategories names the controller's DPI category ids. Codes that are missing are shown
// as "Category N"; the controller's own UI ships the names, the API only sends numbers.
var dpiCategories = map[int]string{
	0:   "Instant messaging",
	1:   "Peer-to-peer",
	3:   "File transfer",
	4:   "Streaming media",
	5:   "Mail and collaboration",
	6:   "Voice over IP",
	7:   "Database",
	8:   "Games",
	9:   "Network management",
	10:  "Remote access",
	11:  "Proxies and tunnels",
	12:  "Stock market",
	13:  "Web",
	14:  "Security updates",
	15:  "Web IM",
	17:  "Business",
	18:  "Network protocols",
	19:  "Network protocols",
	20:  "Network protocols",
	23:  "Private protocols",
	24:  "Social networks",
	255: "Unknown",
}

// CategoryName returns the name of a DPI category id.
func CategoryName(cat int) string {
	if n, ok := dpiCategories[cat]; ok {
		return n
	}
	return "Category " + strconv.Itoa(cat)
}

// Raw DPI JSON. UniFi counts bytes from the gateway's point of view: tx is sent to the
// client (download), rx is received from it (upload).
type rawDPIEntry struct {
	App     *int  `json:"app"`
	Cat     int   `json:"cat"`
	RxBytes int64 `json:"rx_bytes"`
	TxBytes int64 `json:"tx_bytes"`
}

type rawStaDPI struct {
	MAC   string        `json:"mac"`
	ByApp []rawDPIEntry `json:"by_app"`
}

type rawSiteDPI struct {
	ByCat []rawDPIEntry `json:"by_cat"`
	ByApp []rawDPIEntry `json:"by_app"`
}

func postList[T any](ctx context.Context, c *client, p string, body any) ([]T, error) {
	var env envelope[T]
	if err := c.req(ctx, http.MethodPost, c.apiPath(p), body, &env); err != nil {
		return nil, err
	}
	if env.Meta.RC != "" && env.Meta.RC != "ok" {
		return nil, fmt.Errorf("unifi: %s: %s", p, env.Meta.Msg)
	}
	return env.Data, nil
}

func usage(e rawDPIEntry) inv.AppUsage {
	u := inv.AppUsage{Cat: e.Cat, App: -1, Category: CategoryName(e.Cat), DownBytes: e.TxBytes, UpBytes: e.RxBytes}
	if e.App != nil {
		u.App = *e.App
	} else {
		u.Name = u.Category
	}
	return u
}

func sortUsage(us []inv.AppUsage) {
	sort.SliceStable(us, func(i, j int) bool { return us[i].Total() > us[j].Total() })
}

// down and up read a client's byte counters. Like DPI, UniFi counts from the
// network's side: tx is sent to the client. Wired clients may only fill the wired- fields.
func (r rawClient) down() int64 { return firstNonZero(r.TxBytes, r.WiredTxBytes) }
func (r rawClient) up() int64   { return firstNonZero(r.RxBytes, r.WiredRxBytes) }
func (r rawClient) downRate() int64 {
	return int64(firstNonZeroF(float64(r.TxRate), float64(r.WiredTxRate)))
}
func (r rawClient) upRate() int64 {
	return int64(firstNonZeroF(float64(r.RxRate), float64(r.WiredRxRate)))
}

func firstNonZero(v ...int64) int64 {
	for _, x := range v {
		if x != 0 {
			return x
		}
	}
	return 0
}

func firstNonZeroF(v ...float64) float64 {
	for _, x := range v {
		if x != 0 {
			return x
		}
	}
	return 0
}

// BuildTraffic turns stat/sta and DPI data into a traffic report. It is pure so it can be
// tested with recorded controller JSON. staDPI and siteDPI may be nil when DPI is off.
func BuildTraffic(target string, clients []rawClient, staDPI []rawStaDPI, siteDPI []rawSiteDPI, now time.Time) *inv.TrafficReport {
	rep := &inv.TrafficReport{Target: target, TakenAt: now, Clients: []inv.ClientTraffic{}}
	apps := map[string][]inv.AppUsage{}
	for _, s := range staDPI {
		mac := inv.NormMAC(s.MAC)
		for _, e := range s.ByApp {
			if e.RxBytes+e.TxBytes == 0 {
				continue
			}
			apps[mac] = append(apps[mac], usage(e))
			rep.DPI = true
		}
	}
	for _, r := range clients {
		mac := inv.NormMAC(r.MAC)
		ct := inv.ClientTraffic{
			MAC: mac, Name: firstNonEmpty(r.Name, r.Hostname, r.MAC), IP: r.IP, Vendor: r.OUI,
			Wired: r.IsWired, Network: r.Network, SSID: r.ESSID,
			DownBytes: r.down(), UpBytes: r.up(), DownRate: r.downRate(), UpRate: r.upRate(), Uptime: r.Uptime,
			Apps: apps[mac],
		}
		sortUsage(ct.Apps)
		rep.Clients = append(rep.Clients, ct)
	}
	for _, s := range siteDPI {
		for _, e := range s.ByCat {
			if e.RxBytes+e.TxBytes == 0 {
				continue
			}
			e.App = nil
			rep.Categories = append(rep.Categories, usage(e))
			rep.DPI = true
		}
	}
	sortUsage(rep.Categories)
	return rep
}

// ---- UniFi Network 9+ traffic API ----
//
// Newer consoles (e.g. the Dream Router 7) fill the dashboard's application chart from
// GET /proxy/network/v2/api/site/{site}/traffic?start=&end=&includeUnidentified=true
// (times in epoch milliseconds). The legacy stat/stadpi call still answers "ok" there but
// often with no rows, so NCC asks the v2 API first and falls back to the legacy one.

type rawV2Usage struct {
	Application      int   `json:"application"`
	Category         int   `json:"category"`
	BytesReceived    int64 `json:"bytes_received"`
	BytesTransmitted int64 `json:"bytes_transmitted"`
	TotalBytes       int64 `json:"total_bytes"`
}

type rawV2Client struct {
	Client struct {
		MAC      string `json:"mac"`
		Name     string `json:"name"`
		Hostname string `json:"hostname"`
	} `json:"client"`
	UsageByApp []rawV2Usage `json:"usage_by_app"`
}

type rawV2Traffic struct {
	ClientUsageByApp []rawV2Client `json:"client_usage_by_app"`
}

// v2StaDPI converts the v2 answer into the legacy per-client shape BuildTraffic reads.
// bytes_received is what the client received (download), bytes_transmitted what it sent.
func v2StaDPI(v rawV2Traffic) []rawStaDPI {
	var out []rawStaDPI
	for _, cl := range v.ClientUsageByApp {
		s := rawStaDPI{MAC: cl.Client.MAC}
		for _, u := range cl.UsageByApp {
			app := u.Application
			rx, tx := u.BytesTransmitted, u.BytesReceived // legacy: tx = to the client
			if rx+tx == 0 && u.TotalBytes > 0 {
				tx = u.TotalBytes
			}
			s.ByApp = append(s.ByApp, rawDPIEntry{App: &app, Cat: u.Category, RxBytes: rx, TxBytes: tx})
		}
		out = append(out, s)
	}
	return out
}

// categoriesFrom adds up per-client application rows into site-wide categories, for when
// the console gives no site-wide figures of its own.
func categoriesFrom(sta []rawStaDPI) []rawSiteDPI {
	by := map[int]*rawDPIEntry{}
	var order []int
	for _, s := range sta {
		for _, e := range s.ByApp {
			c := by[e.Cat]
			if c == nil {
				c = &rawDPIEntry{Cat: e.Cat}
				by[e.Cat] = c
				order = append(order, e.Cat)
			}
			c.RxBytes += e.RxBytes
			c.TxBytes += e.TxBytes
		}
	}
	site := rawSiteDPI{}
	for _, cat := range order {
		site.ByCat = append(site.ByCat, *by[cat])
	}
	return []rawSiteDPI{site}
}

func hasRows(sta []rawStaDPI) bool {
	for _, s := range sta {
		for _, e := range s.ByApp {
			if e.RxBytes+e.TxBytes > 0 {
				return true
			}
		}
	}
	return false
}

// collectTraffic fetches application data and builds the report. Failures are not fatal:
// the report then carries byte counters only and a note saying why.
func collectTraffic(ctx context.Context, c *client, target string, clients []rawClient) *inv.TrafficReport {
	now := time.Now().UTC()
	var notes []string

	// 1. UniFi Network 9+: the v2 traffic API, last 24 hours.
	var v2 rawV2Traffic
	q := fmt.Sprintf("traffic?start=%d&end=%d&includeUnidentified=true", now.Add(-24*time.Hour).UnixMilli(), now.UnixMilli())
	err := c.req(ctx, http.MethodGet, c.v2Path(q), nil, &v2)
	if sta := v2StaDPI(v2); err == nil && hasRows(sta) {
		rep := BuildTraffic(target, clients, sta, categoriesFrom(sta), now)
		rep.DPISource = "UniFi traffic API (last 24 hours)"
		return rep
	} else if err != nil {
		notes = append(notes, "traffic API: "+err.Error())
	} else {
		notes = append(notes, "traffic API: no application rows")
	}

	// 2. Older consoles: legacy DPI counters.
	staDPI, err1 := postList[rawStaDPI](ctx, c, "stat/stadpi", map[string]any{"type": "by_app"})
	siteDPI, err2 := postList[rawSiteDPI](ctx, c, "stat/sitedpi", map[string]any{"type": "by_cat"})
	if err2 != nil && hasRows(staDPI) {
		siteDPI = categoriesFrom(staDPI)
	}
	rep := BuildTraffic(target, clients, staDPI, siteDPI, now)
	if rep.DPI {
		rep.DPISource = "UniFi DPI counters"
		return rep
	}
	switch {
	case err1 != nil && errors.Is(err1, ErrUnauthorized):
		notes = append(notes, "DPI: the console refused the request; the NCC account may need more than View Only access")
	case err1 != nil:
		notes = append(notes, "DPI: "+err1.Error())
	default:
		notes = append(notes, "DPI: no application rows")
	}
	rep.DPINote = "the console returned no application data (" + strings.Join(notes, "; ") +
		"). Check that Traffic Identification is on in UniFi Network."
	return rep
}
