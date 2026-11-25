package splunk

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/siem"
)

// fakeSplunk is a HTTP Event Collector and REST API in one server.
type fakeSplunk struct {
	token, restToken string
	es               bool
	got              []map[string]any
}

func (f *fakeSplunk) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/services/collector/event":
		if r.Header.Get("Authorization") != "Splunk "+f.token {
			w.WriteHeader(403)
			io.WriteString(w, `{"text":"Invalid token","code":4}`)
			return
		}
		b, _ := io.ReadAll(r.Body)
		if len(bytes.TrimSpace(b)) == 0 {
			w.WriteHeader(400)
			io.WriteString(w, `{"text":"No data","code":5}`)
			return
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			var ev map[string]any
			if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
				w.WriteHeader(400)
				io.WriteString(w, `{"text":"Invalid data format","code":6}`)
				return
			}
			f.got = append(f.got, ev)
		}
		io.WriteString(w, `{"text":"Success","code":0}`)
	case strings.HasPrefix(r.URL.Path, "/services/"):
		if r.Header.Get("Authorization") != "Bearer "+f.restToken {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/services/server/info":
			io.WriteString(w, `{"entry":[{"content":{"version":"9.3.1","serverName":"sh1"}}]}`)
		case "/services/apps/local/" + esApp:
			if !f.es {
				w.WriteHeader(404)
				return
			}
			io.WriteString(w, `{"entry":[{"content":{"version":"8.0.2","disabled":false}}]}`)
		default:
			w.WriteHeader(404)
		}
	default:
		w.WriteHeader(404)
	}
}

func TestSplunk(t *testing.T) {
	f := &fakeSplunk{token: "hec-1", restToken: "rest-1", es: true}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	ctx := context.Background()
	tg := siem.Target{Name: "splunk", Kind: "splunk", Address: srv.URL, Options: map[string]string{"tls": "pin", OptIndex: "ncc", OptRestURL: srv.URL}}
	creds := map[string]string{SecretHEC: "hec-1", SecretRestToken: "rest-1"}

	res, err := Provider{}.Test(ctx, tg, creds)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Info, "Splunk 9.3.1") || !strings.Contains(res.Info, "Enterprise Security 8.0.2 installed") {
		t.Errorf("info %q", res.Info)
	}
	fp := res.OptionUpdates[siem.OptFingerprint]
	if fp == "" || !strings.HasSuffix(res.OptionUpdates[OptRestPin], " "+fp) {
		t.Errorf("pins %v", res.OptionUpdates)
	}
	tg.Options[siem.OptFingerprint] = fp
	tg.Options[OptRestPin] = res.OptionUpdates[OptRestPin]

	f.es = false
	if res, err = (Provider{}).Test(ctx, tg, creds); err != nil || !strings.Contains(res.Info, "not installed") {
		t.Errorf("without ES: %v %q", err, res.Info)
	}
	if _, err := (Provider{}).Test(ctx, tg, map[string]string{SecretHEC: "wrong"}); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("bad token: %v", err)
	}

	evs := []siem.Event{
		{ID: 1, Source: siem.SourceAudit, Time: time.Unix(1700000000, 0), Type: "target.create", Severity: 3, Actor: "admin", Target: "target/udm", Message: "m1"},
		{ID: 7, Source: siem.SourceNetwork, Time: time.Unix(1700000001, 0), Type: "connection.down", Severity: 7, Message: "m2"},
	}
	if _, err := (Provider{}).Send(ctx, tg, creds, evs); err != nil {
		t.Fatal(err)
	}
	if len(f.got) != 2 {
		t.Fatalf("got %d events", len(f.got))
	}
	if f.got[0]["sourcetype"] != "ncc:audit" || f.got[1]["sourcetype"] != "ncc:network" || f.got[0]["index"] != "ncc" {
		t.Errorf("metadata %v", f.got[0])
	}
	ev := f.got[0]["event"].(map[string]any)
	if ev["user"] != "admin" || ev["action"] != "target.create" || ev["dest"] != "target/udm" {
		t.Errorf("event %v", ev)
	}

	// a changed certificate is refused, not silently trusted
	tg.Options[siem.OptFingerprint] = strings.Repeat("0", 64)
	if _, err := (Provider{}).Send(ctx, tg, creds, evs); err == nil {
		t.Error("send with a wrong pin should fail")
	}
}
