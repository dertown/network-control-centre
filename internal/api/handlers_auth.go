package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/dertown/network-control-centre/internal/auth"
	"github.com/dertown/network-control-centre/internal/vault"
)

func (s *Server) setCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/", HttpOnly: true,
		Secure: s.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: maxAge,
	})
}

func (s *Server) getSetup(w http.ResponseWriter, r *http.Request) {
	n, err := s.Auth.CountUsers(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"needs_admin": n == 0, "vault": s.Vault.Status(r.Context())})
}

// postSetup creates the first admin (and initialises the local vault). Only works on an empty install.
func (s *Server) postSetup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		VaultPassphrase string `json:"vault_passphrase"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	ctx := r.Context()
	n, err := s.Auth.CountUsers(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	if n > 0 {
		writeErr(w, 409, "setup is already done")
		return
	}
	if u, ok := s.Vault.(vault.Unsealer); ok && !s.Vault.Status(ctx).Initialized {
		if err := u.Initialize(ctx, in.VaultPassphrase); err != nil {
			writeErr(w, 400, "vault: "+err.Error())
			return
		}
	}
	user, err := s.Auth.CreateUser(ctx, in.Username, in.Password, auth.RoleAdmin)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	_ = s.Audit.Record(ctx, user.Username, "setup", "ncc", map[string]string{"vault": s.Vault.Backend()})
	writeJSON(w, 201, user)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allow(clientIP(r)) {
		writeErr(w, 429, "too many login attempts; wait a few minutes")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	u, err := s.Auth.Authenticate(r.Context(), in.Username, in.Password, in.Code)
	if err != nil {
		_ = s.Audit.Record(r.Context(), in.Username, "login.failed", "ncc", map[string]string{"ip": clientIP(r)})
		writeErr(w, 401, auth.ErrBadLogin.Error())
		return
	}
	tok, csrf, err := s.Auth.StartSession(r.Context(), u)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.setCookie(w, tok, int(s.Auth.SessionTTL/time.Second))
	_ = s.Audit.Record(r.Context(), u.Username, "login", "ncc", map[string]string{"ip": clientIP(r)})
	writeJSON(w, 200, map[string]any{"user": u, "csrf": csrf})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		_ = s.Auth.EndSession(r.Context(), c.Value)
	}
	s.setCookie(w, "", -1)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	writeJSON(w, 200, map[string]any{"user": sess.User, "csrf": sess.CSRF})
}

func (s *Server) mfaStart(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	secret := auth.NewTOTPSecret()
	writeJSON(w, 200, map[string]string{"secret": secret, "uri": auth.TOTPURI("NCC", sess.User.Username, secret)})
}

func (s *Server) mfaConfirm(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !auth.CheckTOTP(in.Secret, in.Code, time.Now()) {
		writeErr(w, 400, "that code does not match; check the time on your phone and try again")
		return
	}
	sess := sessionFrom(r)
	if err := s.Auth.SetTOTP(r.Context(), sess.User.ID, in.Secret); err != nil {
		s.fail(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), sess.User.Username, "mfa.enabled", "user/"+strconv.FormatInt(sess.User.ID, 10), nil)
	writeJSON(w, 200, map[string]bool{"mfa": true})
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	us, err := s.Auth.ListUsers(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, us)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	u, err := s.Auth.CreateUser(r.Context(), in.Username, in.Password, in.Role)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "user.create", "user/"+u.Username, map[string]string{"role": u.Role})
	writeJSON(w, 201, u)
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	es, err := s.Audit.List(r.Context(), limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, es)
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	bad, err := s.Audit.Verify(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"intact": bad == 0, "first_broken_id": bad})
}
