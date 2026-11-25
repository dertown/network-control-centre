package graylog

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/siem"
)

func TestGraylog(t *testing.T) {
	var got []map[string]any
	limit := 100
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/gelf" && r.Method == "POST":
			if len(got) >= limit {
				w.WriteHeader(503)
				return
			}
			var m map[string]any
			_ = json.NewDecoder(r.Body).Decode(&m)
			got = append(got, m)
			w.WriteHeader(202)
		case r.URL.Path == "/gelf":
			w.WriteHeader(405)
		case r.URL.Path == "/api/system":
			u, p, _ := r.BasicAuth()
			if u != "tok" || p != "token" {
				w.WriteHeader(401)
				return
			}
			w.Write([]byte(`{"version":"6.1.2"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	tg := siem.Target{Kind: "graylog", Address: srv.URL, Options: map[string]string{OptAPIURL: srv.URL}}
	res, err := Provider{}.Test(ctx, tg, map[string]string{SecretAPI: "tok"})
	if err != nil || !strings.Contains(res.Info, "Graylog 6.1.2") {
		t.Fatalf("test: %v %+v", err, res)
	}
	evs := []siem.Event{
		{ID: 1, Source: siem.SourceAudit, Time: time.Unix(1700000000, 0), Type: "login", Severity: 3, Actor: "a", Message: "one"},
		{ID: 2, Source: siem.SourceAudit, Time: time.Unix(1700000001, 0), Type: "logout", Severity: 3, Actor: "a", Message: "two"},
		{ID: 3, Source: siem.SourceAudit, Time: time.Unix(1700000002, 0), Type: "login", Severity: 3, Actor: "b", Message: "three"},
	}
	if _, err := (Provider{}).Send(ctx, tg, nil, evs[:1]); err != nil {
		t.Fatal(err)
	}
	if got[0]["short_message"] != "one" || got[0]["_user"] != "a" || got[0]["version"] != "1.1" {
		t.Errorf("gelf %v", got[0])
	}
	limit = 2 // the input stops taking messages after the second
	_, err = Provider{}.Send(ctx, tg, nil, evs[1:])
	var pe *siem.PartialError
	if !errors.As(err, &pe) || pe.Sent != 1 {
		t.Errorf("want a partial delivery of 1, got %v", err)
	}
}
