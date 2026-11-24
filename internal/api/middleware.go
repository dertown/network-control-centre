package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// reqInfo travels with each request: its id, the real client address and (once the session
// is checked) the user, for the access log and the audit log.
type reqInfo struct {
	id   string
	ip   string
	user string
}

const infoKey ctxKey = 2

func infoFrom(r *http.Request) *reqInfo {
	i, _ := r.Context().Value(infoKey).(*reqInfo)
	return i
}

// statusWriter remembers the status code and size for the access log.
type statusWriter struct {
	http.ResponseWriter
	code  int
	bytes int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

// Flush keeps the live event stream working through the wrapper.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// validRequestID accepts a caller's X-Request-ID only when it is short and plain, so it can
// go into logs as it is.
func validRequestID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c == '-' || c == '_' || c == '.' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return true
}

// realIP is the client's address: the connection's, or with a trusted reverse proxy in front,
// the last address in X-Forwarded-For that isn't one of the trusted proxies.
func realIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	isTrusted := func(s string) bool {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return false
		}
		a = a.Unmap()
		for _, p := range trusted {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	if len(trusted) == 0 || !isTrusted(host) {
		return host
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		h := strings.TrimSpace(hops[i])
		if h == "" {
			continue
		}
		if _, err := netip.ParseAddr(h); err != nil {
			break // garbage: stop believing the header
		}
		if !isTrusted(h) {
			return h
		}
	}
	return host
}

// observe gives every request an id (X-Request-ID, echoed back), works out the real client
// address, counts it for /metrics and writes one access log line. Changes (anything but GET
// and HEAD) and failures log at info level or above; reads and static files at debug, so a
// busy dashboard doesn't flood the log.
func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := r.Header.Get("X-Request-ID")
		if !validRequestID(id) {
			id = newRequestID()
		}
		info := &reqInfo{id: id, ip: realIP(r, s.TrustedProxies)}
		w.Header().Set("X-Request-ID", id)
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), infoKey, info)))
		if sw.code == 0 {
			sw.code = http.StatusOK
		}
		d := time.Since(start)
		s.metrics().request(r.Method, sw.code, d)
		if s.Log == nil {
			return
		}
		level := slog.LevelDebug
		switch {
		case sw.code >= 500:
			level = slog.LevelWarn
		case r.Method != http.MethodGet && r.Method != http.MethodHead, sw.code == 401 || sw.code == 403:
			level = slog.LevelInfo
		}
		if r.URL.Path == "/api/health" || r.URL.Path == "/api/ready" || r.URL.Path == "/metrics" {
			level = slog.LevelDebug
		}
		s.Log.LogAttrs(r.Context(), level, "http request",
			slog.String("request_id", id), slog.String("method", r.Method), slog.String("path", r.URL.Path),
			slog.Int("status", sw.code), slog.Int64("bytes", sw.bytes), slog.Duration("duration", d),
			slog.String("client", info.ip), slog.String("user", info.user))
	})
}
