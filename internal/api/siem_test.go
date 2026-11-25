package api_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/dertown/network-control-centre/internal/siem/elastic"
	_ "github.com/dertown/network-control-centre/internal/siem/graylog"
	_ "github.com/dertown/network-control-centre/internal/siem/sentinel"
	_ "github.com/dertown/network-control-centre/internal/siem/splunk"
	_ "github.com/dertown/network-control-centre/internal/siem/syslog"
)

// fakeHEC is a Splunk HTTP Event Collector that keeps the events it is sent.
type fakeHEC struct {
	mu     sync.Mutex
	events []map[string]any
}

func (f *fakeHEC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/services/collector/event" || r.Header.Get("Authorization") != "Splunk hec-token" {
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
	f.mu.Lock()
	for sc.Scan() {
		var ev map[string]any
		_ = json.Unmarshal(sc.Bytes(), &ev)
		f.events = append(f.events, ev["event"].(map[string]any))
	}
	f.mu.Unlock()
	io.WriteString(w, `{"text":"Success","code":0}`)
}

func (f *fakeHEC) actions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range f.events {
		out = append(out, fmt.Sprint(e["action"]))
	}
	return out
}

func TestSIEM(t *testing.T) {
	_, srv := newNCCServer(t)
	ncc := httptest.NewServer(srv.Handler())
	defer ncc.Close()
	hec := &fakeHEC{}
	splunk := httptest.NewTLSServer(hec)
	defer splunk.Close()

	jar, _ := cookiejar.New(nil)
	c := &client{t: t, base: ncc.URL, hc: &http.Client{Jar: jar}}
	c.do("POST", "/api/setup", map[string]string{"username": "derek", "password": "a-long-password", "vault_passphrase": "vault passphrase 1"}, nil)
	var login struct {
		CSRF string `json:"csrf"`
	}
	c.do("POST", "/api/login", map[string]string{"username": "derek", "password": "a-long-password"}, &login)
	c.csrf = login.CSRF

	// the wizard offers a SIEM group with Splunk first
	var cat struct {
		Groups  []struct{ ID string } `json:"groups"`
		Vendors []struct {
			ID     string   `json:"id"`
			Kind   string   `json:"kind"`
			Groups []string `json:"groups"`
			Fields []struct {
				Key string `json:"key"`
			} `json:"fields"`
		} `json:"vendors"`
	}
	c.do("GET", "/api/catalog", nil, &cat)
	var siemVendors []string
	for _, v := range cat.Vendors {
		if len(v.Groups) == 1 && v.Groups[0] == "siem" {
			siemVendors = append(siemVendors, v.ID)
			hasCommon := false
			for _, f := range v.Fields {
				hasCommon = hasCommon || f.Key == "forward_audit"
			}
			if !hasCommon {
				t.Errorf("%s has no forwarding settings", v.ID)
			}
		}
	}
	if got := strings.Join(siemVendors, ","); got != "splunk,sentinel,elastic,qradar,graylog,arcsight,syslog" {
		t.Errorf("SIEM vendors %s", got)
	}
	if cat.Groups[len(cat.Groups)-1].ID != "siem" {
		t.Errorf("groups %+v", cat.Groups)
	}

	// add Splunk the way the wizard does
	var tgt struct {
		ID       int64  `json:"id"`
		Category string `json:"category"`
	}
	if code := c.do("POST", "/api/targets", map[string]any{"vendor": "splunk", "name": "splunk-es", "address": splunk.URL,
		"options":     map[string]string{"tls": "pin", "forward_audit": "on", "forward_network": "on", "min_severity": "0"},
		"credentials": map[string]string{"hec_token": "hec-token"}}, &tgt); code != 201 || tgt.Category != "siem" {
		t.Fatalf("create: %d %+v", code, tgt)
	}
	// the first connection test runs in the background after saving; run one ourselves
	code := 0
	for i := 0; i < 100 && code != 200; i++ {
		var out map[string]any
		if code = c.do("POST", fmt.Sprintf("/api/targets/%d/poll", tgt.ID), nil, &out); code != 200 {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if code != 200 {
		t.Fatalf("connection test: %d", code)
	}

	// QRadar is the syslog provider with LEEF fixed
	var q struct {
		Kind    string            `json:"kind"`
		Options map[string]string `json:"options"`
	}
	if code := c.do("POST", "/api/targets", map[string]any{"vendor": "qradar", "name": "qradar", "address": "127.0.0.1:1",
		"options": map[string]string{"transport": "udp", "format": "cef"}}, &q); code != 201 || q.Kind != "syslog" || q.Options["format"] != "leef" || q.Options["vendor"] != "qradar" {
		t.Errorf("qradar: %d %+v", code, q)
	}

	var view struct {
		Sources []struct {
			ID        int64  `json:"id"`
			Vendor    string `json:"vendor"`
			LastError string `json:"last_error"`
			Status    struct {
				Sent int64  `json:"sent"`
				Info string `json:"info"`
			} `json:"status"`
		} `json:"sources"`
		Events []map[string]any `json:"events"`
	}
	c.do("GET", "/api/siem", nil, &view)
	if len(view.Sources) != 2 {
		t.Fatalf("sources %+v", view.Sources)
	}
	sp := view.Sources[1] // sorted by name: qradar, splunk-es
	if sp.Vendor != "Splunk Enterprise Security" || sp.LastError != "" || !strings.Contains(sp.Status.Info, "accepts the token") {
		t.Errorf("splunk source %+v", sp)
	}

	// the forwarder starts at the end of the audit log, then sends what happens next
	ctx := context.Background()
	srv.SIEM.FlushAll(ctx)
	if code := c.do("POST", fmt.Sprintf("/api/siem/%d/test", tgt.ID), nil, nil); code != 200 {
		t.Fatalf("send test: %d", code)
	}
	srv.SIEM.FlushAll(ctx)
	if got := strings.Join(hec.actions(), ","); got != "ncc.test,siem.test" {
		t.Errorf("Splunk received %s", got)
	}
	c.do("GET", "/api/siem", nil, &view)
	if view.Sources[1].Status.Sent != 2 {
		t.Errorf("sent %d", view.Sources[1].Status.Sent)
	}

	if code := c.do("POST", "/api/siem/99999/test", nil, nil); code != 404 {
		t.Errorf("unknown connection: %d", code)
	}
}
