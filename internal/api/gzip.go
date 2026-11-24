package api

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
)

// gzipMinSize is the smallest response worth compressing; below it the gzip header and the
// CPU cost outweigh the saving.
const gzipMinSize = 1024

var gzipPool = sync.Pool{New: func() any {
	w, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
	return w
}}

// compressible lists the content types worth compressing: API answers (topology, devices and
// clients run to hundreds of kilobytes on a big network) and the UI's scripts and styles.
func compressible(ct string) bool {
	ct = strings.ToLower(ct)
	for _, p := range []string{"application/json", "text/javascript", "application/javascript", "text/css", "text/html", "image/svg+xml", "text/plain"} {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	return false
}

// withGzip compresses responses for browsers that accept gzip. The live event stream is left
// alone (it must flush every event as it happens), and so are range requests.
func withGzip(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/events" || r.Header.Get("Range") != "" || r.Method == http.MethodHead ||
			!strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Accept-Encoding")
		gw := &gzipWriter{ResponseWriter: w}
		defer gw.close()
		next.ServeHTTP(gw, r)
	})
}

// gzipWriter buffers the first gzipMinSize bytes, then decides: a small or incompressible
// answer goes out as it is, anything else is compressed.
type gzipWriter struct {
	http.ResponseWriter
	code    int
	buf     []byte
	decided bool
	gz      *gzip.Writer
}

func (g *gzipWriter) WriteHeader(code int) {
	if g.code == 0 {
		g.code = code
	}
}

func (g *gzipWriter) Write(b []byte) (int, error) {
	if g.code == 0 {
		g.code = http.StatusOK
	}
	if g.decided {
		if g.gz != nil {
			return g.gz.Write(b)
		}
		return g.ResponseWriter.Write(b)
	}
	g.buf = append(g.buf, b...)
	if len(g.buf) >= gzipMinSize {
		if err := g.decide(); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

// decide sends the headers and whatever was buffered, compressed or not.
func (g *gzipWriter) decide() error {
	g.decided = true
	h := g.ResponseWriter.Header()
	if h.Get("Content-Type") == "" && len(g.buf) > 0 {
		h.Set("Content-Type", http.DetectContentType(g.buf))
	}
	if len(g.buf) >= gzipMinSize && g.code == http.StatusOK && h.Get("Content-Encoding") == "" && compressible(h.Get("Content-Type")) {
		h.Del("Content-Length")
		h.Set("Content-Encoding", "gzip")
		g.gz = gzipPool.Get().(*gzip.Writer)
		g.gz.Reset(g.ResponseWriter)
		g.ResponseWriter.WriteHeader(g.code)
		_, err := g.gz.Write(g.buf)
		g.buf = nil
		return err
	}
	g.ResponseWriter.WriteHeader(g.code)
	_, err := g.ResponseWriter.Write(g.buf)
	g.buf = nil
	return err
}

func (g *gzipWriter) close() {
	if !g.decided {
		if g.code == 0 {
			return // the handler wrote nothing; net/http sends its default 200
		}
		_ = g.decide()
	}
	if g.gz != nil {
		_ = g.gz.Close()
		gzipPool.Put(g.gz)
		g.gz = nil
	}
}

// Unwrap lets http.ResponseController reach the real writer.
func (g *gzipWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }
