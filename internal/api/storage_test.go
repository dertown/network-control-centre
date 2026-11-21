package api_test

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/mocklab"

	_ "github.com/dertown/network-control-centre/internal/storage/nfs"
	_ "github.com/dertown/network-control-centre/internal/storage/qnap"
	_ "github.com/dertown/network-control-centre/internal/storage/synology"
)

type storageView struct {
	Sources []struct {
		ID        int64  `json:"id"`
		Name      string `json:"name"`
		LastError string `json:"last_error"`
		Inventory *struct {
			System struct {
				Model  string `json:"model"`
				Health string `json:"health"`
			} `json:"system"`
			Shares    []map[string]any      `json:"shares"`
			Volumes   []struct{ ID string } `json:"volumes"`
			Snapshots []struct {
				ID     string `json:"id"`
				Share  string `json:"share"`
				Locked bool   `json:"locked"`
			} `json:"snapshots"`
			Alerts []map[string]any `json:"alerts"`
		} `json:"inventory"`
	} `json:"sources"`
}

func TestStorage(t *testing.T) {
	ncc, _ := newNCC(t)
	defer ncc.Close()
	syn := httptest.NewTLSServer(mocklab.Synology("pw"))
	defer syn.Close()
	qn := httptest.NewTLSServer(mocklab.QNAP("pw"))
	defer qn.Close()

	jar, _ := cookiejar.New(nil)
	c := &client{t: t, base: ncc.URL, hc: &http.Client{Jar: jar}}
	c.do("POST", "/api/setup", map[string]string{"username": "derek", "password": "a-long-password", "vault_passphrase": "vault passphrase 1"}, nil)
	var login struct {
		CSRF string `json:"csrf"`
	}
	c.do("POST", "/api/login", map[string]string{"username": "derek", "password": "a-long-password"}, &login)
	c.csrf = login.CSRF

	if code := c.do("POST", "/api/targets", map[string]any{"kind": "nfs", "category": "storage", "name": "bad", "address": "has space"}, nil); code != 400 {
		t.Fatalf("bad NFS address accepted: %d", code)
	}
	if code := c.do("POST", "/api/targets", map[string]any{"kind": "qnap", "category": "storage", "name": "bad", "address": "192.168.1.50",
		"credentials": map[string]string{"username": "a", "password": "b"}}, nil); code != 400 {
		t.Fatalf("QNAP without a URL accepted: %d", code)
	}
	// NFS needs no credentials
	var nfs core.Target
	if code := c.do("POST", "/api/targets", map[string]any{"kind": "nfs", "category": "storage", "name": "nfs1", "address": "127.0.0.1"}, &nfs); code != 201 {
		t.Fatalf("nfs create: %d", code)
	}
	var ds, nas core.Target
	if code := c.do("POST", "/api/targets", map[string]any{"kind": "synology", "category": "storage", "name": "ds", "address": syn.URL,
		"credentials": map[string]string{"username": "ncc", "password": "pw"}}, &ds); code != 201 {
		t.Fatalf("create: %d", code)
	}
	if code := c.do("POST", "/api/targets", map[string]any{"kind": "qnap", "category": "storage", "name": "nas", "address": qn.URL,
		"credentials": map[string]string{"username": "admin", "password": "pw"}}, &nas); code != 201 {
		t.Fatalf("create: %d", code)
	}
	var v storageView
	ready := func() bool {
		n := 0
		for _, s := range v.Sources {
			if s.Inventory != nil {
				n++
			}
		}
		return n >= 2
	}
	for i := 0; i < 50 && !ready(); i++ {
		c.do("POST", "/api/targets/"+itoa(ds.ID)+"/poll", nil, nil)
		c.do("POST", "/api/targets/"+itoa(nas.ID)+"/poll", nil, nil)
		if code := c.do("GET", "/api/storage", nil, &v); code != 200 {
			t.Fatalf("storage: %d", code)
		}
	}
	if len(v.Sources) != 3 || !ready() {
		t.Fatalf("sources: %+v", v.Sources)
	}
	src := map[string]int{}
	for i, s := range v.Sources {
		src[s.Name] = i
	}
	d := v.Sources[src["ds"]].Inventory
	if d.System.Model != "DS920+" || len(d.Shares) != 4 || len(d.Snapshots) != 4 {
		t.Fatalf("ds: %+v", d)
	}
	if q := v.Sources[src["nas"]].Inventory; q.System.Model != "TS-464" || len(q.Alerts) == 0 {
		t.Fatalf("nas: %+v", q)
	}

	// changes
	if code := c.do("POST", "/api/storage/power", map[string]any{"id": ds.ID, "action": "restart", "confirm": "wrong"}, nil); code != 400 {
		t.Fatalf("restart without the name: %d", code)
	}
	if code := c.do("POST", "/api/storage/power", map[string]any{"id": ds.ID, "action": "explode", "confirm": "ds"}, nil); code != 400 {
		t.Fatalf("bad action: %d", code)
	}
	if code := c.do("POST", "/api/storage/power", map[string]any{"id": ds.ID, "action": "restart", "confirm": "ds"}, nil); code != 200 {
		t.Fatalf("restart: %d", code)
	}
	if code := c.do("POST", "/api/storage/shares", map[string]any{"id": ds.ID, "name": "../etc", "volume": "/volume1"}, nil); code != 400 {
		t.Fatalf("bad share name: %d", code)
	}
	if code := c.do("POST", "/api/storage/shares", map[string]any{"id": ds.ID, "name": "photo", "volume": "/volume1"}, nil); code != 409 {
		t.Fatalf("duplicate share: %d", code)
	}
	if code := c.do("POST", "/api/storage/shares", map[string]any{"id": ds.ID, "name": "backups", "volume": "/volume9"}, nil); code != 400 {
		t.Fatalf("unknown volume: %d", code)
	}
	if code := c.do("POST", "/api/storage/shares", map[string]any{"id": ds.ID, "name": "backups", "volume": "/volume1", "comment": "Time Machine"}, nil); code != 200 {
		t.Fatalf("create share: %d", code)
	}
	if code := c.do("POST", "/api/storage/shares", map[string]any{"id": nas.ID, "name": "backups", "volume": "1"}, nil); code != 501 {
		t.Fatalf("QNAP share create should be unsupported: %d", code)
	}
	if code := c.do("POST", "/api/storage/folders", map[string]any{"id": nas.ID, "share": "Public", "path": "scans/2024"}, nil); code != 200 {
		t.Fatalf("folder: %d", code)
	}
	if code := c.do("POST", "/api/storage/folders", map[string]any{"id": nas.ID, "share": "Nope", "path": "x"}, nil); code != 404 {
		t.Fatalf("folder in unknown share: %d", code)
	}
	if code := c.do("POST", "/api/storage/snapshots", map[string]any{"id": ds.ID, "share": "docker", "comment": "before upgrade"}, nil); code != 200 {
		t.Fatalf("snapshot: %d", code)
	}
	var locked, free string
	for _, s := range d.Snapshots {
		if s.Locked {
			locked = s.ID
		} else if s.Share == "photo" {
			free = s.ID
		}
	}
	if code := c.do("POST", "/api/storage/snapshots/delete", map[string]any{"id": ds.ID, "share": "photo", "snapshot": locked}, nil); code != 409 {
		t.Fatalf("deleting a locked snapshot: %d", code)
	}
	if code := c.do("POST", "/api/storage/snapshots/delete", map[string]any{"id": ds.ID, "share": "photo", "snapshot": "GMT+00-1999.01.01-00.00.00"}, nil); code != 404 {
		t.Fatalf("unknown snapshot: %d", code)
	}
	if code := c.do("POST", "/api/storage/snapshots/delete", map[string]any{"id": ds.ID, "share": "photo", "snapshot": free}, nil); code != 200 {
		t.Fatalf("delete snapshot: %d", code)
	}
	var hist struct {
		Volumes []struct {
			Volume string `json:"volume"`
			Points []any  `json:"points"`
		} `json:"volumes"`
	}
	if code := c.do("GET", "/api/storage/"+itoa(ds.ID)+"/history", nil, &hist); code != 200 || len(hist.Volumes) != 1 || len(hist.Volumes[0].Points) == 0 {
		t.Fatalf("history: %d %+v", code, hist)
	}

	var log []struct {
		Action string `json:"action"`
	}
	c.do("GET", "/api/audit", nil, &log)
	seen := map[string]int{}
	for _, e := range log {
		seen[e.Action]++
	}
	for _, a := range []string{"storage.power", "storage.share.create", "storage.folder.create", "storage.snapshot.create", "storage.snapshot.delete"} {
		if seen[a] == 0 {
			t.Errorf("no %s in the audit log: %v", a, seen)
		}
	}
}
