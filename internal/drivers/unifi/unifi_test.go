package unifi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/drivers"
	inv "github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/mocklab"
	"github.com/dertown/network-control-centre/internal/vault"
)

func load[T any](t *testing.T, file string) []T {
	t.Helper()
	b := map[string][]byte{"stat_device.json": mocklab.StatDevice, "stat_sta.json": mocklab.StatSta}[file]
	var env envelope[T]
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	return env.Data
}

func deviceByID(s *inv.Snapshot, id string) *inv.Device {
	for i := range s.Devices {
		if s.Devices[i].ID == id {
			return &s.Devices[i]
		}
	}
	return nil
}

func TestBuildDiscoversMakeAndModel(t *testing.T) {
	snap := Build("home", load[rawDevice](t, "stat_device.json"), load[rawClient](t, "stat_sta.json"), nil, time.Now())

	cases := []struct{ id, kind, make, model string }{
		{"aa:bb:cc:00:00:01", inv.KindGateway, "Ubiquiti", "Dream Router 7"},
		{"aa:bb:cc:00:00:02", inv.KindAP, "Ubiquiti", "U6 Pro"},
		{"aa:bb:cc:00:00:04", inv.KindSwitch, "Ubiquiti", "Switch Lite 16 PoE"},
		{"aa:bb:cc:00:00:05", inv.KindSwitch, "Ubiquiti", "USZZ99"}, // unknown code falls back to the raw code
		{"10:20:30:40:50:60", inv.KindSwitch, "NETGEAR", "NETGEAR GS308E ProSAFE Plus Switch"},
	}
	for _, c := range cases {
		d := deviceByID(snap, c.id)
		if d == nil {
			t.Fatalf("device %s missing", c.id)
		}
		if d.Kind != c.kind || d.Make != c.make || d.Model != c.model {
			t.Errorf("%s: got kind=%q make=%q model=%q, want %q %q %q", c.id, d.Kind, d.Make, d.Model, c.kind, c.make, c.model)
		}
	}
	if d := deviceByID(snap, "10:20:30:40:50:60"); d.Discovery != inv.SourceLLDP || d.IP != "192.168.1.40" {
		t.Errorf("LLDP switch: discovery=%q ip=%q", d.Discovery, d.IP)
	}
	if d := deviceByID(snap, "aa:bb:cc:00:00:03"); d.Online {
		t.Error("garage AP should be offline (state 0)")
	}
	if d := deviceByID(snap, "aa:bb:cc:00:00:01"); d.Ports[2].PoEWatts != 5.2 {
		t.Errorf("poe_power string not parsed: %v", d.Ports[2].PoEWatts)
	}

	// Printer and TV share rack switch port 5, so an unmanaged switch is inferred there.
	inf := deviceByID(snap, "inferred:aa:bb:cc:00:00:04:5")
	if inf == nil || inf.Kind != inv.KindUnmanaged || inf.Clients != 2 {
		t.Fatalf("inferred switch: %+v", inf)
	}

	parents := map[string]string{}
	for _, c := range snap.Clients {
		parents[c.Name] = c.ParentID
	}
	want := map[string]string{
		"nas": "aa:bb:cc:00:00:01", "Printer": inf.ID, "tv": inf.ID,
		"phone": "aa:bb:cc:00:00:02", "desk-pc": "10:20:30:40:50:60",
	}
	for n, p := range want {
		if parents[n] != p {
			t.Errorf("client %s parent = %q, want %q", n, parents[n], p)
		}
	}
	if _, isClient := parents["office-sw"]; isClient {
		t.Error("the LLDP switch must not also be listed as a client")
	}

	links := map[string]inv.Link{}
	for _, l := range snap.Links {
		links[l.A+">"+l.B] = l
	}
	if l, ok := links["aa:bb:cc:00:00:01>aa:bb:cc:00:00:02"]; !ok || l.APort != "Port 3" || l.Medium != "wired" {
		t.Errorf("router→lounge AP link: %+v ok=%v", l, ok)
	}
	if l, ok := links["aa:bb:cc:00:00:02>aa:bb:cc:00:00:03"]; !ok || l.Medium != "wireless" {
		t.Errorf("mesh link: %+v ok=%v", l, ok)
	}
	if _, ok := links["aa:bb:cc:00:00:01>10:20:30:40:50:60"]; !ok {
		t.Error("LLDP link to the Netgear switch missing")
	}
}

// fakeConsole emulates a UniFi OS console (login + classic API) over TLS.
func fakeConsole(t *testing.T, apiKeyOnlyIntegration bool) *httptest.Server {
	t.Helper()
	dev, sta := mocklab.StatDevice, mocklab.StatSta
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["username"] != "ncc" || in["password"] != "s3cret" {
			w.WriteHeader(401)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "tok", Path: "/"})
		w.Header().Set("X-Csrf-Token", "csrf1")
		w.Write([]byte(`{}`))
	})
	mux.HandleFunc("POST /api/auth/logout", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) })
	authed := func(r *http.Request) bool {
		if k := r.Header.Get("X-API-KEY"); k != "" {
			return !apiKeyOnlyIntegration && k == "key1"
		}
		c, err := r.Cookie("TOKEN")
		return err == nil && c.Value == "tok"
	}
	mux.HandleFunc("GET /proxy/network/api/s/default/stat/device", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			w.WriteHeader(401)
			return
		}
		w.Write(dev)
	})
	mux.HandleFunc("GET /proxy/network/api/s/default/stat/sta", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			w.WriteHeader(401)
			return
		}
		w.Write(sta)
	})
	mux.HandleFunc("GET /proxy/network/integration/v1/sites", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[{"id":"s1","internalReference":"default","name":"Default"}]}`))
	})
	mux.HandleFunc("GET /proxy/network/integration/v1/sites/s1/devices", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[{"id":"d1","name":"Dream Router 7","model":"UDR7","macAddress":"AA:BB:CC:00:00:01","ipAddress":"192.168.1.1","state":"ONLINE","features":["switching","gateway"]}]}`))
	})
	mux.HandleFunc("GET /proxy/network/integration/v1/sites/s1/clients", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[{"type":"WIRED","name":"nas","macAddress":"de:ad:00:00:00:01","ipAddress":"192.168.1.50","uplinkDeviceId":"d1"}]}`))
	})
	return httptest.NewTLSServer(mux)
}

func TestCollectPinsCertificateOnFirstUse(t *testing.T) {
	srv := fakeConsole(t, false)
	defer srv.Close()
	ctx := context.Background()
	tgt := drivers.Target{Name: "home", Kind: "unifi", Address: srv.URL, Options: map[string]string{}}

	res, err := Driver{}.Collect(ctx, tgt, vault.Secret{"username": "ncc", "password": "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Snapshot.Devices) < 5 {
		t.Fatalf("got %d devices", len(res.Snapshot.Devices))
	}
	fp := res.OptionUpdates[OptFingerprint]
	if len(fp) != 64 {
		t.Fatalf("expected a pinned fingerprint, got %q", fp)
	}

	// Pinned: works again with the same cert, fails with a different pin.
	tgt.Options[OptFingerprint] = fp
	if _, err := (Driver{}).Collect(ctx, tgt, vault.Secret{"username": "ncc", "password": "s3cret"}); err != nil {
		t.Fatalf("pinned collect: %v", err)
	}
	tgt.Options[OptFingerprint] = "00" + fp[2:]
	if _, err := (Driver{}).Collect(ctx, tgt, vault.Secret{"username": "ncc", "password": "s3cret"}); err == nil {
		t.Fatal("expected a fingerprint mismatch error")
	}

	// Strict CA verification refuses the self-signed console.
	tgt.Options = map[string]string{OptTLS: "verify"}
	if _, err := (Driver{}).Collect(ctx, tgt, vault.Secret{"username": "ncc", "password": "s3cret"}); err == nil {
		t.Fatal("expected TLS verification to fail on a self-signed cert")
	}
}

func TestCollectBadPassword(t *testing.T) {
	srv := fakeConsole(t, false)
	defer srv.Close()
	_, err := Driver{}.Collect(context.Background(), drivers.Target{Address: srv.URL, Options: map[string]string{}},
		vault.Secret{"username": "ncc", "password": "wrong"})
	if err == nil {
		t.Fatal("expected an auth error")
	}
}

func TestCollectAPIKey(t *testing.T) {
	for _, integOnly := range []bool{false, true} {
		srv := fakeConsole(t, integOnly)
		res, err := Driver{}.Collect(context.Background(), drivers.Target{Address: srv.URL, Options: map[string]string{}},
			vault.Secret{"api_key": "key1"})
		srv.Close()
		if err != nil {
			t.Fatalf("integOnly=%v: %v", integOnly, err)
		}
		d := deviceByID(res.Snapshot, "aa:bb:cc:00:00:01")
		if d == nil || d.Model != "Dream Router 7" || d.Kind != inv.KindGateway {
			t.Fatalf("integOnly=%v: router = %+v", integOnly, d)
		}
	}
}

func TestCollectReusesSession(t *testing.T) {
	logins := 0
	expire := false
	inner := mocklab.UniFi()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/login" {
			logins++
		}
		if expire && r.Method == http.MethodGet {
			expire = false
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	defer srv.Close()
	tgt := drivers.Target{ID: 42, Name: "home", Address: srv.URL, Options: map[string]string{OptTLS: "pin"}}
	creds := vault.Secret{"username": "ncc", "password": "demo-password"}
	for i := 0; i < 3; i++ {
		if _, err := (Driver{}).Collect(context.Background(), tgt, creds); err != nil {
			t.Fatal(err)
		}
	}
	if logins != 1 {
		t.Fatalf("expected one login for three polls, got %d", logins)
	}
	expire = true // console drops the session
	if _, err := (Driver{}).Collect(context.Background(), tgt, creds); err != nil {
		t.Fatalf("re-login after expiry: %v", err)
	}
	if logins != 2 {
		t.Fatalf("expected a second login after expiry, got %d", logins)
	}
}
