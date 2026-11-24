package api

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGzipCompressesLargeJSONOnly(t *testing.T) {
	big := `{"x":"` + strings.Repeat("a", 5000) + `"}`
	h := withGzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			writeJSON(w, 200, map[string]string{"x": strings.Repeat("a", 5000)})
		case "/small":
			writeJSON(w, 200, map[string]string{"ok": "1"})
		case "/err":
			writeJSON(w, 404, map[string]string{"error": strings.Repeat("b", 5000)})
		case "/empty":
			w.WriteHeader(204)
		}
	}))
	get := func(path, enc string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		if enc != "" {
			req.Header.Set("Accept-Encoding", enc)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	rec := get("/big", "gzip, deflate")
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("big JSON not compressed: %v", rec.Header())
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(zr)
	if strings.TrimSpace(string(b)) != big {
		t.Fatalf("round trip changed the body: %d bytes", len(b))
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type %q", ct)
	}

	if rec := get("/big", ""); rec.Header().Get("Content-Encoding") != "" || strings.TrimSpace(rec.Body.String()) != big {
		t.Fatal("compressed for a client that did not ask for it")
	}
	if rec := get("/small", "gzip"); rec.Header().Get("Content-Encoding") != "" || !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Fatalf("small answer: %v %q", rec.Header(), rec.Body.String())
	}
	if rec := get("/err", "gzip"); rec.Code != 404 || rec.Header().Get("Content-Encoding") != "" {
		t.Fatalf("error answer: %d %v", rec.Code, rec.Header())
	}
	if rec := get("/empty", "gzip"); rec.Code != 204 || rec.Body.Len() != 0 {
		t.Fatalf("empty answer: %d %q", rec.Code, rec.Body.String())
	}
}
