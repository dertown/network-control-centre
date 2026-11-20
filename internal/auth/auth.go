// Package auth handles NCC users, password hashing, TOTP and sessions.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Roles, lowest to highest.
const (
	RoleViewer   = "viewer"   // read everything except secret values
	RoleOperator = "operator" // DNS changes, device reads
	RoleAdmin    = "admin"    // device targets, vault, users
)

var roleRank = map[string]int{RoleViewer: 1, RoleOperator: 2, RoleAdmin: 3}

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool { _, ok := roleRank[r]; return ok }

// Allows reports whether role has at least the rights of need.
func Allows(role, need string) bool { return roleRank[role] >= roleRank[need] && roleRank[need] > 0 }

// User is an NCC account.
type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	MFA      bool   `json:"mfa"`
	totp     string
}

// Service manages users and sessions.
type Service struct {
	db         *sql.DB
	SessionTTL time.Duration
}

// New returns an auth service.
func New(db *sql.DB) *Service { return &Service{db: db, SessionTTL: 12 * time.Hour} }

// ErrBadLogin hides whether the user or the password was wrong.
var ErrBadLogin = errors.New("invalid username, password or code")

// Errors returned by the user-management calls.
var (
	ErrNoUser        = errors.New("no such user")
	ErrWrongPassword = errors.New("your current password is wrong")
	ErrSamePassword  = errors.New("the new password must be different from the current one")
	ErrLastAdmin     = errors.New("cannot remove the last admin account")
	ErrWeakPassword  = errors.New("password must be at least 12 characters")
)

// MinPasswordLen is the shortest password NCC accepts.
const MinPasswordLen = 12

// ---- password hashing (Argon2id, PHC string format) ----

// HashPassword returns an Argon2id PHC string.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	const t, m, p = 3, 64 * 1024, 2
	key := argon2.IDKey([]byte(pw), salt, t, m, p, 32)
	b := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", m, t, p, b.EncodeToString(salt), b.EncodeToString(key)), nil
}

// CheckPassword verifies pw against a PHC string.
func CheckPassword(phc, pw string) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	b := base64.RawStdEncoding
	salt, err1 := b.DecodeString(parts[4])
	want, err2 := b.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ---- TOTP (RFC 6238, SHA-1, 6 digits, 30 s) ----

// NewTOTPSecret returns a random base32 secret.
func NewTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// TOTPCode computes the code for secret at time t.
func TOTPCode(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1_000_000), nil
}

// CheckTOTP accepts the current code and one step either side.
func CheckTOTP(secret, code string, now time.Time) bool {
	for _, d := range []time.Duration{0, -30 * time.Second, 30 * time.Second} {
		c, err := TOTPCode(secret, now.Add(d))
		if err == nil && subtle.ConstantTimeCompare([]byte(c), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// TOTPURI returns an otpauth:// URI for authenticator apps.
func TOTPURI(issuer, user, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuer, user, secret, issuer)
}

// ---- users ----

// CountUsers returns the number of accounts.
func (s *Service) CountUsers(ctx context.Context) (int, error) {
	var n int
	return n, s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
}

// CreateUser adds an account.
func (s *Service) CreateUser(ctx context.Context, username, password, role string) (*User, error) {
	username = strings.TrimSpace(username)
	if username == "" || len(password) < MinPasswordLen {
		return nil, errors.New("username required and password must be at least 12 characters")
	}
	if !ValidRole(role) {
		return nil, fmt.Errorf("unknown role %q", role)
	}
	h, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO users (username, password_hash, role) VALUES (?,?,?)`, username, h, role)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &User{ID: id, Username: username, Role: role}, nil
}

// ListUsers returns all accounts.
func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, role, totp_secret FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.totp); err != nil {
			return nil, err
		}
		u.MFA = u.totp != ""
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetTOTP enables (secret != "") or disables MFA for a user.
func (s *Service) SetTOTP(ctx context.Context, userID int64, secret string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET totp_secret = ? WHERE id = ?`, secret, userID)
	return err
}

// GetUser returns one account by id.
func (s *Service) GetUser(ctx context.Context, id int64) (*User, error) {
	var u User
	err := s.db.QueryRowContext(ctx, `SELECT id, username, role, totp_secret FROM users WHERE id = ?`, id).
		Scan(&u.ID, &u.Username, &u.Role, &u.totp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoUser
	}
	if err != nil {
		return nil, err
	}
	u.MFA = u.totp != ""
	return &u, nil
}

// ChangePassword is the self-service change: it needs the current password, and it ends
// every other session of the user so a stolen cookie stops working. keepToken is the raw
// cookie token of the session making the change; that one stays logged in.
func (s *Service) ChangePassword(ctx context.Context, userID int64, current, next, keepToken string) error {
	if len(next) < MinPasswordLen {
		return ErrWeakPassword
	}
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id = ?`, userID).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNoUser
	}
	if err != nil {
		return err
	}
	if !CheckPassword(hash, current) {
		return ErrWrongPassword
	}
	if current == next {
		return ErrSamePassword
	}
	return s.setPassword(ctx, userID, next, keepToken)
}

// ResetPassword is the admin reset of another user's password. It ends all of that
// user's sessions.
func (s *Service) ResetPassword(ctx context.Context, userID int64, next string) error {
	if len(next) < MinPasswordLen {
		return ErrWeakPassword
	}
	return s.setPassword(ctx, userID, next, "")
}

func (s *Service) setPassword(ctx context.Context, userID int64, next, keepToken string) error {
	h, err := HashPassword(next)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, h, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoUser
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?`,
		userID, tokenHash(keepToken)); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteUser removes an account and its sessions. It refuses to remove the last admin.
func (s *Service) DeleteUser(ctx context.Context, userID int64) (*User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var u User
	err = tx.QueryRowContext(ctx, `SELECT id, username, role FROM users WHERE id = ?`, userID).Scan(&u.ID, &u.Username, &u.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoUser
	}
	if err != nil {
		return nil, err
	}
	if u.Role == RoleAdmin {
		var admins int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = ?`, RoleAdmin).Scan(&admins); err != nil {
			return nil, err
		}
		if admins <= 1 {
			return nil, ErrLastAdmin
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID); err != nil {
		return nil, err
	}
	return &u, tx.Commit()
}

// Authenticate checks credentials (and TOTP if enabled).
func (s *Service) Authenticate(ctx context.Context, username, password, code string) (*User, error) {
	var u User
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT id, username, role, password_hash, totp_secret FROM users WHERE username = ?`,
		username).Scan(&u.ID, &u.Username, &u.Role, &hash, &u.totp)
	if errors.Is(err, sql.ErrNoRows) {
		CheckPassword("$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", password) // equalise timing
		return nil, ErrBadLogin
	}
	if err != nil {
		return nil, err
	}
	if !CheckPassword(hash, password) {
		return nil, ErrBadLogin
	}
	if u.totp != "" && !CheckTOTP(u.totp, strings.TrimSpace(code), time.Now()) {
		return nil, ErrBadLogin
	}
	u.MFA = u.totp != ""
	return &u, nil
}

// ---- sessions ----

func tokenHash(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Session is a logged-in browser session.
type Session struct {
	User User
	CSRF string
}

// StartSession creates a session; the raw token goes in the cookie, only its hash is stored.
func (s *Service) StartSession(ctx context.Context, u *User) (token, csrf string, err error) {
	token, csrf = randToken(), randToken()
	_, err = s.db.ExecContext(ctx, `INSERT INTO sessions (token_hash, user_id, csrf, expires_at) VALUES (?,?,?,?)`,
		tokenHash(token), u.ID, csrf, time.Now().Add(s.SessionTTL).UTC())
	return token, csrf, err
}

// Lookup returns the session for a cookie token.
func (s *Service) Lookup(ctx context.Context, token string) (*Session, error) {
	if token == "" {
		return nil, ErrBadLogin
	}
	var sess Session
	var exp time.Time
	err := s.db.QueryRowContext(ctx, `SELECT u.id, u.username, u.role, u.totp_secret, s.csrf, s.expires_at
		FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?`, tokenHash(token)).
		Scan(&sess.User.ID, &sess.User.Username, &sess.User.Role, &sess.User.totp, &sess.CSRF, &exp)
	if err != nil {
		return nil, ErrBadLogin
	}
	if time.Now().After(exp) {
		_ = s.EndSession(ctx, token)
		return nil, ErrBadLogin
	}
	sess.User.MFA = sess.User.totp != ""
	return &sess, nil
}

// EndSession logs out.
func (s *Service) EndSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash(token))
	return err
}

// PurgeExpired removes stale sessions.
func (s *Service) PurgeExpired(ctx context.Context) {
	_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, time.Now().UTC())
}
