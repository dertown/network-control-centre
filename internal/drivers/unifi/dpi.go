package unifi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
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

// collectTraffic fetches DPI data and builds the report. DPI failures are not fatal:
// the report then carries byte counters only and a note saying why.
func collectTraffic(ctx context.Context, c *client, target string, clients []rawClient) *inv.TrafficReport {
	staDPI, err1 := postList[rawStaDPI](ctx, c, "stat/stadpi", map[string]any{"type": "by_app"})
	siteDPI, err2 := postList[rawSiteDPI](ctx, c, "stat/sitedpi", map[string]any{"type": "by_cat"})
	rep := BuildTraffic(target, clients, staDPI, siteDPI, time.Now().UTC())
	switch {
	case err1 != nil && errors.Is(err1, ErrUnauthorized):
		rep.DPINote = "the console refused the DPI request; the NCC account may need more than View Only access"
	case err1 != nil:
		rep.DPINote = "the console did not return DPI data: " + err1.Error()
	case err2 != nil && !rep.DPI:
		rep.DPINote = "the console did not return DPI data: " + err2.Error()
	case !rep.DPI:
		rep.DPINote = "no application data yet; turn on Traffic Identification (DPI) in UniFi Network settings"
	}
	return rep
}
