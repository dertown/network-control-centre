package sentinel

import (
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

func TestSentinel(t *testing.T) {
	var rows []map[string]any
	allowed := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/tenant-1/oauth2/v2.0/token":
			_ = r.ParseForm()
			if r.Form.Get("client_secret") != "s3cret" || r.Form.Get("scope") != scope {
				w.WriteHeader(401)
				io.WriteString(w, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}`)
				return
			}
			io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
		case r.URL.Path == "/dataCollectionRules/dcr-abc/streams/Custom-NCCEvents_CL":
			if r.Header.Get("Authorization") != "Bearer tok" || r.URL.Query().Get("api-version") != apiVersion {
				w.WriteHeader(401)
				return
			}
			if !allowed {
				w.WriteHeader(403)
				io.WriteString(w, `{"error":{"code":"OperationFailed","message":"The authentication token provided does not have access to ingest data"}}`)
				return
			}
			var in []map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			if len(in) == 0 {
				w.WriteHeader(400)
				return
			}
			rows = append(rows, in...)
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	tg := siem.Target{Kind: "sentinel", Address: srv.URL, Options: map[string]string{
		OptTenant: "tenant-1", OptClient: "app-1", OptDCR: "dcr-abc", OptAuthority: srv.URL}}
	creds := map[string]string{SecretClient: "s3cret"}

	if res, err := (Provider{}).Test(ctx, tg, creds); err != nil || !strings.Contains(res.Info, "dcr-abc") {
		t.Fatalf("test: %v %+v", err, res)
	}
	if _, err := (Provider{}).Test(ctx, tg, map[string]string{SecretClient: "nope"}); err == nil || !strings.Contains(err.Error(), "Invalid client secret") {
		t.Errorf("bad secret: %v", err)
	}
	evs := []siem.Event{{ID: 3, Source: siem.SourceAudit, Time: time.Unix(1700000000, 0), Type: "login", Severity: 3, Actor: "bob",
		Message: "m", Detail: `{"ip":"192.0.2.1"}`}}
	if _, err := (Provider{}).Send(ctx, tg, creds, evs); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["Actor"] != "bob" || rows[0]["SrcIp"] != "192.0.2.1" || rows[0]["EventId"] != "audit-3" {
		t.Errorf("rows %v", rows)
	}
	allowed = false
	if _, err := (Provider{}).Send(ctx, tg, creds, evs); err == nil || !strings.Contains(err.Error(), "Monitoring Metrics Publisher") {
		t.Errorf("forbidden: %v", err)
	}
	tg.Options[OptDCR] = "dcr-missing"
	if _, err := (Provider{}).Test(ctx, tg, creds); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("missing rule: %v", err)
	}
}
