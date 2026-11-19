package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeKV emulates the parts of HashiCorp Vault's KV v2 API and AppRole login NCC uses.
func fakeKV(t *testing.T) *httptest.Server {
	var mu sync.Mutex
	data := map[string]map[string]string{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/v1/auth/approle/login" {
			json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "t1", "lease_duration": 3600}})
			return
		}
		if r.URL.Path == "/v1/sys/health" {
			w.Write([]byte(`{"sealed":false}`))
			return
		}
		if r.Header.Get("X-Vault-Token") != "t1" {
			w.WriteHeader(403)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/secret/data/"):
			p := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")
			switch r.Method {
			case http.MethodPost:
				var in struct {
					Data map[string]string `json:"data"`
				}
				json.NewDecoder(r.Body).Decode(&in)
				data[p] = in.Data
				w.Write([]byte(`{"data":{"version":1}}`))
			case http.MethodGet:
				d, ok := data[p]
				if !ok {
					w.WriteHeader(404)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": d}})
			}
		case strings.HasPrefix(r.URL.Path, "/v1/secret/metadata/"):
			p := strings.TrimPrefix(r.URL.Path, "/v1/secret/metadata/")
			if r.Method == http.MethodDelete {
				delete(data, p)
				w.WriteHeader(204)
				return
			}
			if r.Method == "LIST" {
				seen := map[string]bool{}
				var keys []string
				for k := range data {
					if !strings.HasPrefix(k, p+"/") {
						continue
					}
					rest := strings.TrimPrefix(k, p+"/")
					if i := strings.Index(rest, "/"); i >= 0 {
						rest = rest[:i+1]
					}
					if !seen[rest] {
						seen[rest] = true
						keys = append(keys, rest)
					}
				}
				if len(keys) == 0 {
					w.WriteHeader(404)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": keys}})
			}
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestHashiCorpAppRole(t *testing.T) {
	srv := fakeKV(t)
	defer srv.Close()
	h, err := NewHashiCorp(HashiCorpOptions{Address: srv.URL, Prefix: "ncc", RoleID: "r", SecretID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := h.Put(ctx, "targets/dns/pdns", Secret{"api_key": "k"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Put(ctx, "certs/www", Secret{"private_key": "pem"}); err != nil {
		t.Fatal(err)
	}
	s, err := h.Get(ctx, "targets/dns/pdns")
	if err != nil || s["api_key"] != "k" {
		t.Fatalf("get: %v %v", s, err)
	}
	ps, err := h.List(ctx, "")
	if err != nil || len(ps) != 2 || ps[0] != "certs/www" || ps[1] != "targets/dns/pdns" {
		t.Fatalf("list: %v %v", ps, err)
	}
	if err := h.Delete(ctx, "certs/www"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Get(ctx, "certs/www"); err != ErrNotFound {
		t.Fatalf("after delete: %v", err)
	}
	if st := h.Status(ctx); st.Sealed || st.Detail != "" {
		t.Fatalf("status: %+v", st)
	}
}
