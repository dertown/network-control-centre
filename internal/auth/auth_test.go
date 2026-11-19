package auth

import (
	"context"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/store"
)

func TestTOTPRFC6238Vector(t *testing.T) {
	// RFC 6238 appendix B, SHA-1 secret "12345678901234567890", T=59 -> 94287082 (8 digits); 6 digits = 287082
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code, err := TOTPCode(secret, time.Unix(59, 0))
	if err != nil || code != "287082" {
		t.Fatalf("got %q %v", code, err)
	}
	if !CheckTOTP(secret, "287082", time.Unix(59+30, 0)) {
		t.Fatal("one step of clock skew should be accepted")
	}
	if CheckTOTP(secret, "287082", time.Unix(59+120, 0)) {
		t.Fatal("stale code accepted")
	}
}

func TestUsersSessionsRoles(t *testing.T) {
	st, _ := store.OpenPath(":memory:")
	s := New(st.DB)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "derek", "short", RoleAdmin); err == nil {
		t.Fatal("short password accepted")
	}
	u, err := s.CreateUser(ctx, "derek", "a-long-password", RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "derek", "wrong-password!", ""); err == nil {
		t.Fatal("wrong password accepted")
	}
	secret := NewTOTPSecret()
	_ = s.SetTOTP(ctx, u.ID, secret)
	if _, err := s.Authenticate(ctx, "derek", "a-long-password", ""); err == nil {
		t.Fatal("missing TOTP accepted")
	}
	code, _ := TOTPCode(secret, time.Now())
	u2, err := s.Authenticate(ctx, "derek", "a-long-password", code)
	if err != nil || !u2.MFA {
		t.Fatalf("login with TOTP: %v", err)
	}
	tok, csrf, err := s.StartSession(ctx, u2)
	if err != nil || csrf == "" {
		t.Fatal(err)
	}
	sess, err := s.Lookup(ctx, tok)
	if err != nil || sess.User.Username != "derek" {
		t.Fatalf("lookup: %v", err)
	}
	_ = s.EndSession(ctx, tok)
	if _, err := s.Lookup(ctx, tok); err == nil {
		t.Fatal("session survived logout")
	}
	if !Allows(RoleAdmin, RoleOperator) || Allows(RoleViewer, RoleOperator) || Allows(RoleOperator, "bogus") {
		t.Fatal("role ranking wrong")
	}
}
