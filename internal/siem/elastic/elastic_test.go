package elastic

import (
	"bufio"
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

func TestElastic(t *testing.T) {
	seen := map[string]bool{}
	var docs []map[string]any
	reject := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "ApiKey k3y" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/":
			io.WriteString(w, `{"cluster_name":"sec","version":{"number":"8.15.0"}}`)
		case "/_bulk":
			if r.Header.Get("Content-Type") != "application/x-ndjson" {
				w.WriteHeader(400)
				return
			}
			sc := bufio.NewScanner(r.Body)
			sc.Buffer(nil, 1<<20)
			var items []string
			for sc.Scan() {
				var action map[string]map[string]string
				_ = json.Unmarshal(sc.Bytes(), &action)
				sc.Scan()
				var doc map[string]any
				_ = json.Unmarshal(sc.Bytes(), &doc)
				c := action["create"]
				switch {
				case c["_index"] != "logs-ncc.events-default":
					items = append(items, `{"create":{"status":400,"error":{"type":"bad_index","reason":"x"}}}`)
				case reject:
					items = append(items, `{"create":{"status":400,"error":{"type":"mapper_parsing_exception","reason":"bad field"}}}`)
				case seen[c["_id"]]:
					items = append(items, `{"create":{"status":409,"error":{"type":"version_conflict_engine_exception","reason":"exists"}}}`)
				default:
					seen[c["_id"]] = true
					docs = append(docs, doc)
					items = append(items, `{"create":{"status":201}}`)
				}
			}
			errs := strings.Contains(strings.Join(items, ""), `"error"`)
			b, _ := json.Marshal(errs)
			io.WriteString(w, `{"errors":`+string(b)+`,"items":[`+strings.Join(items, ",")+`]}`)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	tg := siem.Target{Kind: "elastic", Address: srv.URL, Options: map[string]string{"tls": "pin"}}
	creds := map[string]string{SecretAPIKey: "k3y"}
	res, err := Provider{}.Test(ctx, tg, creds)
	if err != nil || res.Info != "Elasticsearch 8.15.0 · cluster sec" || res.OptionUpdates[siem.OptFingerprint] == "" {
		t.Fatalf("test: %v %+v", err, res)
	}
	evs := []siem.Event{{ID: 1, Source: siem.SourceAudit, Time: time.Unix(1700000000, 0), Type: "login.failed", Severity: 7, Actor: "x", Message: "m"}}
	if _, err := (Provider{}).Send(ctx, tg, creds, evs); err != nil {
		t.Fatal(err)
	}
	// sending the same batch again (a retry) is harmless
	if _, err := (Provider{}).Send(ctx, tg, creds, evs); err != nil {
		t.Fatalf("resend: %v", err)
	}
	if len(docs) != 1 || docs[0]["@timestamp"] == nil {
		t.Fatalf("docs %v", docs)
	}
	reject = true
	evs[0].ID = 2
	if _, err := (Provider{}).Send(ctx, tg, creds, evs); err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception") {
		t.Errorf("rejected: %v", err)
	}
	if _, err := (Provider{}).Test(ctx, tg, map[string]string{}); err == nil {
		t.Error("no credentials should fail")
	}
}
