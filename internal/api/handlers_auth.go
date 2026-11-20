package api

import (
	"errors"
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

// changePassword lets any logged-in user change their own password. It needs the current
// password, and every other session of the user is logged out.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	// the current password is a guessable secret, so rate-limit attempts like logins
	if !s.limiter.allow("pw/" + strconv.FormatInt(sess.User.ID, 10)) {
		writeErr(w, 429, "too many attempts; wait a few minutes")
		return
	}
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	var keep string
	if c, err := r.Cookie(cookieName); err == nil {
		keep = c.Value
	}
	target := "user/" + sess.User.Username
	switch err := s.Auth.ChangePassword(r.Context(), sess.User.ID, in.CurrentPassword, in.NewPassword, keep); {
	case errors.Is(err, auth.ErrWrongPassword):
		_ = s.Audit.Record(r.Context(), sess.User.Username, "password.change.failed", target, map[string]string{"ip": clientIP(r)})
		writeErr(w, 403, err.Error())
		return
	case errors.Is(err, auth.ErrWeakPassword), errors.Is(err, auth.ErrSamePassword):
		writeErr(w, 400, err.Error())
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), sess.User.Username, "password.change", target, map[string]string{"ip": clientIP(r)})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func userID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "bad user id")
		return 0, false
	}
	return id, true
}

// resetPassword lets an admin set another user's password; that user is logged out everywhere.
// Admins change their own password with POST /api/me/password, which asks for the current one.
func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := userID(w, r)
	if !ok {
		return
	}
	if id == sessionFrom(r).User.ID {
		writeErr(w, 400, "use Change my password for your own account")
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	u, err := s.Auth.GetUser(r.Context(), id)
	if errors.Is(err, auth.ErrNoUser) {
		writeErr(w, 404, err.Error())
		return
	} else if err != nil {
		s.fail(w, err)
		return
	}
	switch err := s.Auth.ResetPassword(r.Context(), id, in.Password); {
	case errors.Is(err, auth.ErrWeakPassword):
		writeErr(w, 400, err.Error())
		return
	case errors.Is(err, auth.ErrNoUser):
		writeErr(w, 404, err.Error())
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "user.password_reset", "user/"+u.Username, nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := userID(w, r)
	if !ok {
		return
	}
	if id == sessionFrom(r).User.ID {
		writeErr(w, 400, "you cannot delete your own account")
		return
	}
	u, err := s.Auth.DeleteUser(r.Context(), id)
	switch {
	case errors.Is(err, auth.ErrNoUser):
		writeErr(w, 404, err.Error())
		return
	case errors.Is(err, auth.ErrLastAdmin):
		writeErr(w, 409, err.Error())
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "user.delete", "user/"+u.Username, map[string]string{"role": u.Role})
	writeJSON(w, 200, map[string]bool{"ok": true})
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
