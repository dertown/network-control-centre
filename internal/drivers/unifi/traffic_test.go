package unifi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/drivers"
	"github.com/dertown/network-control-centre/internal/mocklab"
	"github.com/dertown/network-control-centre/internal/vault"
)

func TestBuildTraffic(t *testing.T) {
	var sta envelope[rawStaDPI]
	var site envelope[rawSiteDPI]
	if err := json.Unmarshal(mocklab.StatStaDPI, &sta); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(mocklab.StatSiteDPI, &site); err != nil {
		t.Fatal(err)
	}
	rep := BuildTraffic("home", load[rawClient](t, "stat_sta.json"), sta.Data, site.Data, time.Now())
	if !rep.DPI {
		t.Fatal("DPI data not recognised")
	}
	by := map[string]int{}
	for i, c := range rep.Clients {
		by[c.Name] = i
	}
	tv := rep.Clients[by["tv"]]
	// wired client: only wired- counters are filled; tx (to the client) is download
	if tv.DownBytes != 32212254720 || tv.UpBytes != 858993459 || tv.DownRate != 3100000 {
		t.Errorf("tv counters: %+v", tv)
	}
	if len(tv.Apps) != 3 || tv.Apps[0].Category != "Streaming media" || tv.Apps[0].DownBytes != 25769803776 {
		t.Errorf("tv apps: %+v", tv.Apps)
	}
	nas := rep.Clients[by["nas"]]
	if nas.UpBytes <= nas.DownBytes {
		t.Errorf("nas uploads more than it downloads: %+v", nas)
	}
	if len(rep.Categories) != 8 || rep.Categories[0].Name != "Streaming media" || rep.Categories[0].App != -1 {
		t.Errorf("categories: %+v", rep.Categories)
	}
	if CategoryName(4242) != "Category 4242" {
		t.Error("unknown category name")
	}
}

func TestCollectReturnsTraffic(t *testing.T) {
	srv := httptest.NewTLSServer(mocklab.UniFi())
	defer srv.Close()
	res, err := Driver{}.Test(context.Background(), drivers.Target{Name: "mock", Address: srv.URL, Options: map[string]string{}},
		vault.Secret{"username": "ncc", "password": "demo-password"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Traffic == nil || !res.Traffic.DPI || res.Traffic.DPINote != "" || len(res.Traffic.Clients) != len(res.Snapshot.Clients)+1 {
		t.Fatalf("traffic: %+v", res.Traffic)
	}
	// the mock behaves like Network 9+: data comes from the v2 traffic API
	if res.Traffic.DPISource != "UniFi traffic API (last 24 hours)" {
		t.Errorf("source: %q", res.Traffic.DPISource)
	}
	for _, c := range res.Traffic.Clients {
		if c.Name == "tv" && (len(c.Apps) != 3 || c.Apps[0].Category != "Streaming media" || c.Apps[0].DownBytes != 25769803776 || c.Apps[0].UpBytes != 429496729) {
			t.Errorf("tv apps from v2: %+v", c.Apps)
		}
	}
	if len(res.Traffic.Categories) == 0 || res.Traffic.Categories[0].Category != "Streaming media" {
		t.Errorf("categories built from client rows: %+v", res.Traffic.Categories)
	}
}

// An older console without the v2 traffic API: legacy DPI counters are used.
func TestCollectLegacyDPI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /proxy/network/v2/api/site/default/traffic", http.NotFound)
	legacy := func(b []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { w.Write(b) }
	}
	mux.HandleFunc("POST /proxy/network/api/s/default/stat/stadpi", legacy(mocklab.StatStaDPI))
	mux.HandleFunc("POST /proxy/network/api/s/default/stat/sitedpi", legacy(mocklab.StatSiteDPI))
	mux.Handle("/", mocklab.UniFi())
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	res, err := Driver{}.Test(context.Background(), drivers.Target{Name: "old", Address: srv.URL, Options: map[string]string{}},
		vault.Secret{"username": "ncc", "password": "demo-password"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Traffic.DPI || res.Traffic.DPISource != "UniFi DPI counters" || len(res.Traffic.Categories) != 8 {
		t.Fatalf("legacy traffic: %+v", res.Traffic)
	}
}

func TestCollectWithoutDPI(t *testing.T) {
	srv := fakeConsole(t, false) // no DPI endpoints: polling must still work
	defer srv.Close()
	res, err := Driver{}.Test(context.Background(), drivers.Target{Address: srv.URL, Options: map[string]string{}},
		vault.Secret{"username": "ncc", "password": "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Traffic == nil || res.Traffic.DPI || !strings.Contains(res.Traffic.DPINote, "Traffic Identification") {
		t.Fatalf("expected a DPI note: %+v", res.Traffic)
	}
}

// The admin typed the site name shown in UniFi ("Home"); the API wants "default".
func TestCollectResolvesSiteName(t *testing.T) {
	srv := httptest.NewTLSServer(mocklab.UniFi())
	defer srv.Close()
	res, err := Driver{}.Test(context.Background(), drivers.Target{Address: srv.URL, Options: map[string]string{OptSite: "home"}},
		vault.Secret{"username": "ncc", "password": "demo-password"})
	if err != nil {
		t.Fatal(err)
	}
	if res.OptionUpdates[OptSite] != "default" || len(res.Snapshot.Devices) == 0 {
		t.Fatalf("site not resolved: %+v", res.OptionUpdates)
	}
}

func TestPickSite(t *testing.T) {
	sites := []rawSite{{Name: "default", Desc: "Home"}, {Name: "x7k2p", Desc: "Cabin"}}
	for want, got := range map[string]string{"default": "default", "Home": "default", "cabin": "x7k2p", "office": ""} {
		if p := pickSite(want, sites); p != got {
			t.Errorf("pickSite(%q) = %q, want %q", want, p, got)
		}
	}
	if pickSite("home", []rawSite{{Name: "default", Desc: "Default"}}) != "default" {
		t.Error("a console with one site should use it")
	}
}
