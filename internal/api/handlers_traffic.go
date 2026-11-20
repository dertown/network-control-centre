package api

import (
	"net/http"
	"sort"
	"time"

	"github.com/dertown/network-control-centre/internal/dnslog"
	"github.com/dertown/network-control-centre/internal/inventory"
)

// trafficWindows are the periods the Traffic page offers. "session" means since each
// client last connected, straight from the controller's counters.
var trafficWindows = map[string]time.Duration{
	"session": 0,
	"1h":      time.Hour,
	"24h":     24 * time.Hour,
	"7d":      7 * 24 * time.Hour,
}

// staleTraffic is how old a target's report may be before the page ignores it.
const staleTraffic = 10 * time.Minute

// TrafficClient is one row of the Traffic page.
type TrafficClient struct {
	inventory.ClientTraffic
	Online bool `json:"online"`
	// WindowDown and WindowUp are the bytes moved in the chosen window.
	WindowDown int64              `json:"window_down"`
	WindowUp   int64              `json:"window_up"`
	Sites      []dnslog.SiteCount `json:"sites,omitempty"`
}

// TrafficView is the response of GET /api/traffic.
type TrafficView struct {
	Window     string               `json:"window"`
	TakenAt    *time.Time           `json:"taken_at,omitempty"`
	DPI        bool                 `json:"dpi"`
	DPINotes   []string             `json:"dpi_notes,omitempty"`
	Categories []inventory.AppUsage `json:"categories"`
	Clients    []TrafficClient      `json:"clients"`
	Sites      []dnslog.SiteCount   `json:"sites"`
	// UnmatchedSites are lookups from addresses that are not a known client, e.g. the
	// router forwarding everyone's queries.
	UnmatchedSites []string      `json:"unmatched_sources,omitempty"`
	DNSLog         dnslog.Status `json:"dns_log"`
}

func (s *Server) traffic(w http.ResponseWriter, r *http.Request) {
	win := r.URL.Query().Get("window")
	if win == "" {
		win = "24h"
	}
	d, ok := trafficWindows[win]
	if !ok {
		writeErr(w, 400, "window must be session, 1h, 24h or 7d")
		return
	}
	view := TrafficView{Window: win, Categories: []inventory.AppUsage{}, Clients: []TrafficClient{}, Sites: []dnslog.SiteCount{}}
	var current []inventory.ClientTraffic
	cats := map[int]*inventory.AppUsage{}
	if s.Traffic != nil {
		for _, rep := range s.Traffic.Latest() {
			if time.Since(rep.TakenAt) > staleTraffic {
				continue // the target was disabled, deleted or has stopped answering
			}
			if view.TakenAt == nil || rep.TakenAt.After(*view.TakenAt) {
				t := rep.TakenAt
				view.TakenAt = &t
			}
			view.DPI = view.DPI || rep.DPI
			if rep.DPINote != "" {
				view.DPINotes = append(view.DPINotes, rep.Target+": "+rep.DPINote)
			}
			current = append(current, rep.Clients...)
			for _, c := range rep.Categories {
				if a := cats[c.Cat]; a != nil {
					a.DownBytes += c.DownBytes
					a.UpBytes += c.UpBytes
				} else {
					cc := c
					cats[c.Cat] = &cc
				}
			}
		}
	}
	for _, c := range cats {
		view.Categories = append(view.Categories, *c)
	}
	sort.Slice(view.Categories, func(i, j int) bool { return view.Categories[i].Total() > view.Categories[j].Total() })

	byMAC := map[string]*TrafficClient{}
	for _, c := range current {
		tc := &TrafficClient{ClientTraffic: c, Online: true, WindowDown: c.DownBytes, WindowUp: c.UpBytes}
		byMAC[c.MAC] = tc
	}
	if d > 0 && s.Traffic != nil {
		used, err := s.Traffic.UsageSince(r.Context(), time.Now().Add(-d), current)
		if err != nil {
			s.fail(w, err)
			return
		}
		for _, tc := range byMAC {
			tc.WindowDown, tc.WindowUp = 0, 0
		}
		for mac, u := range used {
			tc := byMAC[mac]
			if tc == nil {
				if u.DownBytes+u.UpBytes == 0 {
					continue
				}
				tc = &TrafficClient{ClientTraffic: inventory.ClientTraffic{MAC: mac, Name: u.Name, IP: u.IP}}
				byMAC[mac] = tc
			}
			tc.WindowDown, tc.WindowUp = u.DownBytes, u.UpBytes
		}
	}

	view.DNSLog = s.DNSLog.Status()
	if s.DNSLog != nil {
		since := time.Now().Add(-d)
		if d == 0 {
			since = time.Now().Add(-24 * time.Hour)
		}
		sites, err := s.DNSLog.TopSites(r.Context(), since, 15)
		if err != nil {
			s.fail(w, err)
			return
		}
		view.Sites = append(view.Sites, sites[""]...)
		ipToClient := map[string]*TrafficClient{}
		for _, tc := range byMAC {
			if tc.IP != "" {
				ipToClient[tc.IP] = tc
			}
		}
		for ip, l := range sites {
			if ip == "" {
				continue
			}
			if tc := ipToClient[ip]; tc != nil {
				tc.Sites = l
			} else {
				view.UnmatchedSites = append(view.UnmatchedSites, ip)
			}
		}
		sort.Strings(view.UnmatchedSites)
	}

	for _, tc := range byMAC {
		view.Clients = append(view.Clients, *tc)
	}
	sort.Slice(view.Clients, func(i, j int) bool {
		a, b := view.Clients[i], view.Clients[j]
		if ta, tb := a.WindowDown+a.WindowUp, b.WindowDown+b.WindowUp; ta != tb {
			return ta > tb
		}
		return a.Name < b.Name
	})
	writeJSON(w, 200, view)
}
