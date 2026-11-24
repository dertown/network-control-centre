package api_test

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestReadyMetricsAndAuditExport(t *testing.T) {
	c := adminClient(t)
	var ready map[string]string
	if code := c.do("GET", "/api/ready", nil, &ready); code != 200 || ready["database"] != "ok" || ready["vault"] != "unsealed" {
		t.Fatalf("ready: %d %v", code, ready)
	}
	// /metrics is off unless configured
	if code := c.do("GET", "/metrics", nil, nil); code == 200 {
		t.Fatal("/metrics served without being turned on")
	}

	resp, err := c.hc.Get(c.base + "/api/audit/export?format=csv")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(string(body), "id,ts,actor,action") || !strings.Contains(string(body), "login") {
		t.Fatalf("export: %d %s", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Request-ID") == "" {
		t.Fatal("no request id")
	}
	resp, _ = c.hc.Get(c.base + "/api/audit/export?format=jsonl")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `"action":"audit.export"`) {
		t.Fatalf("jsonl: %s", body)
	}
	// a caller's request id is echoed when it is plain, replaced when it isn't
	req, _ := http.NewRequest("GET", c.base+"/api/health", nil)
	req.Header.Set("X-Request-ID", "abc-123")
	resp, _ = c.hc.Do(req)
	resp.Body.Close()
	if resp.Header.Get("X-Request-ID") != "abc-123" {
		t.Fatalf("request id %q", resp.Header.Get("X-Request-ID"))
	}
	req.Header.Set("X-Request-ID", "bad id <script>")
	resp, _ = c.hc.Do(req)
	resp.Body.Close()
	if got := resp.Header.Get("X-Request-ID"); got == "" || strings.ContainsAny(got, " <") {
		t.Fatalf("request id %q", got)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	_, srv := newNCCServer(t)
	srv.MetricsEnabled, srv.MetricsToken, srv.Version = true, "scrape-me", "v9"
	ts := httptestServer(t, srv)
	resp, _ := http.Get(ts + "/metrics")
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("no token: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", ts+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer scrape-me")
	resp, _ = http.DefaultClient.Do(req)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, want := range []string{`ncc_build_info{version="v9"} 1`, `ncc_http_requests_total{method="GET",code="401"} 1`, `ncc_connections{category="dns",state="ok"} 0`, "ncc_vault_sealed"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %s in:\n%s", want, body)
		}
	}
}
