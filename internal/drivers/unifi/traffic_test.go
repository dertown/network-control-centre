package unifi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
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
}

func TestCollectWithoutDPI(t *testing.T) {
	srv := fakeConsole(t, false) // no DPI endpoints: polling must still work
	defer srv.Close()
	res, err := Driver{}.Test(context.Background(), drivers.Target{Address: srv.URL, Options: map[string]string{}},
		vault.Secret{"username": "ncc", "password": "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Traffic == nil || res.Traffic.DPI || res.Traffic.DPINote == "" {
		t.Fatalf("expected a DPI note: %+v", res.Traffic)
	}
}
