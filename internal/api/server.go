// Package api is the NCC HTTP API and static UI server.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dertown/network-control-centre/internal/audit"
	"github.com/dertown/network-control-centre/internal/auth"
	"github.com/dertown/network-control-centre/internal/certdeploy"
	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/dnslog"
	"github.com/dertown/network-control-centre/internal/pki"
	"github.com/dertown/network-control-centre/internal/store"
	"github.com/dertown/network-control-centre/internal/vault"
)

// Server holds every dependency the handlers need.
type Server struct {
	Store   *store.Store
	Auth    *auth.Service
	Audit   *audit.Log
	Vault   vault.Store
	Targets *core.Targets
	Poller  *core.Poller
	Hub     *core.Hub
	Certs   *pki.Inventory
	Deploy  *certdeploy.Service // certificate deployment to servers; nil disables it
	Traffic *core.Traffic       // per-client traffic; nil disables the Traffic page data
	DNSLog  *dnslog.Collector   // DNS query log receiver; nil when dns_log is not configured
	UI      fs.FS               // built web UI; nil serves a placeholder
	Log     *slog.Logger
	// SecureCookies sets the Secure flag; true unless running plain HTTP in development.
	SecureCookies bool

	limiter *loginLimiter
}

const cookieName = "ncc_session"

type ctxKey int

const sessKey ctxKey = 1

func sessionFrom(r *http.Request) *auth.Session {
	s, _ := r.Context().Value(sessKey).(*auth.Session)
	return s
}

func actor(r *http.Request) string {
	if s := sessionFrom(r); s != nil {
		return s.User.Username
	}
	return "anonymous"
}

// Handler builds the HTTP handler.
func (s *Server) Handler() http.Handler {
	s.limiter = &loginLimiter{hits: map[string][]time.Time{}}
	mux := http.NewServeMux()

	// public
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /api/setup", s.getSetup)
	mux.HandleFunc("POST /api/setup", s.postSetup)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)

	// any logged-in user
	v := func(h http.HandlerFunc) http.Handler { return s.authed(auth.RoleViewer, h) }
	o := func(h http.HandlerFunc) http.Handler { return s.authed(auth.RoleOperator, h) }
	a := func(h http.HandlerFunc) http.Handler { return s.authed(auth.RoleAdmin, h) }

	mux.Handle("GET /api/me", v(s.me))
	mux.Handle("POST /api/me/mfa/start", v(s.mfaStart))
	mux.Handle("POST /api/me/mfa/confirm", v(s.mfaConfirm))
	mux.Handle("POST /api/me/password", v(s.changePassword))
	mux.Handle("GET /api/events", v(s.events))
	mux.Handle("GET /api/drivers", v(s.listDrivers))

	mux.Handle("GET /api/vault/status", v(s.vaultStatus))
	mux.Handle("POST /api/vault/unseal", a(s.vaultUnseal))
	mux.Handle("POST /api/vault/seal", a(s.vaultSeal))
	mux.Handle("GET /api/vault/secrets", a(s.vaultList))
	mux.Handle("GET /api/vault/secrets/{path...}", a(s.vaultGet))
	mux.Handle("PUT /api/vault/secrets/{path...}", a(s.vaultPut))
	mux.Handle("DELETE /api/vault/secrets/{path...}", a(s.vaultDelete))
	mux.Handle("POST /api/vault/reveal", a(s.vaultReveal))

	mux.Handle("GET /api/targets", v(s.listTargets))
	mux.Handle("POST /api/targets", a(s.createTarget))
	mux.Handle("PATCH /api/targets/{id}", a(s.updateTarget))
	mux.Handle("DELETE /api/targets/{id}", a(s.deleteTarget))
	mux.Handle("PUT /api/targets/{id}/credentials", a(s.setTargetCredentials))
	mux.Handle("POST /api/targets/{id}/poll", o(s.pollTarget))

	mux.Handle("GET /api/devices", v(s.listDevices))
	mux.Handle("GET /api/clients", v(s.listClients))
	mux.Handle("GET /api/topology", v(s.topology))
	mux.Handle("GET /api/loops", v(s.loops))
	mux.Handle("GET /api/firewall", v(s.firewall))
	mux.Handle("GET /api/traffic", v(s.traffic))
	mux.Handle("GET /api/vlans", v(s.listVLANs))
	mux.Handle("POST /api/vlans/networks", a(s.createVLAN))
	mux.Handle("POST /api/vlans/plan", v(s.planVLANMove))
	mux.Handle("POST /api/vlans/move", a(s.moveVLANClients))
	mux.Handle("GET /api/vms", v(s.listVMs))
	mux.Handle("POST /api/vms/power", o(s.vmPower))
	mux.Handle("POST /api/vms/settings", a(s.vmSettings))
	mux.Handle("POST /api/vms/delete", a(s.vmDelete))
	mux.Handle("GET /api/storage", v(s.listStorage))
	mux.Handle("GET /api/storage/{id}/history", v(s.storageHistory))
	mux.Handle("POST /api/storage/power", a(s.storagePower))
	mux.Handle("POST /api/storage/shares", a(s.storageCreateShare))
	mux.Handle("POST /api/storage/folders", o(s.storageCreateFolder))
	mux.Handle("POST /api/storage/snapshots", o(s.storageCreateSnapshot))
	mux.Handle("POST /api/storage/snapshots/delete", a(s.storageDeleteSnapshot))

	mux.Handle("GET /api/dns/{server}/zones", v(s.dnsZones))
	mux.Handle("GET /api/dns/{server}/zones/{zone}/records", v(s.dnsRecords))
	mux.Handle("POST /api/dns/{server}/zones/{zone}/changes", o(s.dnsChanges))

	mux.Handle("GET /api/certs", v(s.listCerts))
	mux.Handle("POST /api/certs", a(s.importCert))
	mux.Handle("GET /api/certs/{id}/pem", v(s.certPEM))
	mux.Handle("DELETE /api/certs/{id}", a(s.deleteCert))
	mux.Handle("PUT /api/certs/{id}/chain", a(s.setCertChain))

	mux.Handle("GET /api/certdeploy/kinds", v(s.deployKinds))
	mux.Handle("GET /api/certdeploy/targets", v(s.deployTargets))
	mux.Handle("POST /api/certdeploy/targets", a(s.createDeployTarget))
	mux.Handle("PATCH /api/certdeploy/targets/{id}", a(s.updateDeployTarget))
	mux.Handle("DELETE /api/certdeploy/targets/{id}", a(s.deleteDeployTarget))
	mux.Handle("GET /api/certdeploy/targets/{id}/served", v(s.deployServed))
	mux.Handle("POST /api/certdeploy/plan", a(s.deployPlan))
	mux.Handle("POST /api/certdeploy/deploy", a(s.deployRun))
	mux.Handle("GET /api/certdeploy/deployments", v(s.deployHistory))
	mux.Handle("GET /api/certdeploy/deployments/{id}", v(s.deployment))

	mux.Handle("GET /api/audit", a(s.listAudit))
	mux.Handle("GET /api/audit/verify", a(s.verifyAudit))
	mux.Handle("GET /api/users", a(s.listUsers))
	mux.Handle("POST /api/users", a(s.createUser))
	mux.Handle("PUT /api/users/{id}/password", a(s.resetPassword))
	mux.Handle("DELETE /api/users/{id}", a(s.deleteUser))

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { writeErr(w, 404, "no such endpoint") })
	mux.Handle("/", s.static())
	return s.secHeaders(mux)
}

func (s *Server) secHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// authed checks the session cookie, the role and (for writes) the CSRF header.
func (s *Server) authed(role string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			writeErr(w, 401, "log in first")
			return
		}
		sess, err := s.Auth.Lookup(r.Context(), c.Value)
		if err != nil {
			writeErr(w, 401, "session expired")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if got := r.Header.Get("X-CSRF-Token"); got == "" || got != sess.CSRF {
				writeErr(w, 403, "missing or wrong CSRF token")
				return
			}
		}
		if !auth.Allows(sess.User.Role, role) {
			writeErr(w, 403, "your role ("+sess.User.Role+") cannot do this; needs "+role)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), sessKey, sess)))
	})
}

func (s *Server) static() http.Handler {
	if s.UI == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><title>NCC</title><p>The web UI was not built into this binary. Run <code>make web</code> then rebuild.</p>`))
		})
	}
	files := http.FileServer(http.FS(s.UI))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" {
			if _, err := fs.Stat(s.UI, p); err == nil {
				if strings.HasPrefix(p, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				files.ServeHTTP(w, r)
				return
			}
		}
		// single-page app: unknown paths get index.html
		b, err := fs.ReadFile(s.UI, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(b)
	})
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, 400, "bad JSON: "+err.Error())
		return false
	}
	return true
}

// errCode maps well-known errors to HTTP codes.
func (s *Server) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, vault.ErrSealed):
		writeErr(w, 423, "the vault is sealed; unseal it first")
	case errors.Is(err, vault.ErrNotFound), errors.Is(err, core.ErrNoTarget):
		writeErr(w, 404, err.Error())
	default:
		s.Log.Warn("request failed", "err", err)
		writeErr(w, 502, err.Error())
	}
}

// ---- login rate limiting: 10 attempts per IP per 5 minutes ----

type loginLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func (l *loginLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := time.Now().Add(-5 * time.Minute)
	keep := l.hits[ip][:0]
	for _, t := range l.hits[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) >= 10 {
		l.hits[ip] = keep
		return false
	}
	l.hits[ip] = append(keep, time.Now())
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
