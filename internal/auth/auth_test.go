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

func TestChangeResetDelete(t *testing.T) {
	st, _ := store.OpenPath(":memory:")
	s := New(st.DB)
	ctx := context.Background()
	admin, _ := s.CreateUser(ctx, "derek", "first-password-1", RoleAdmin)
	other, _ := s.CreateUser(ctx, "guest", "guest-password-1", RoleViewer)

	here, _, _ := s.StartSession(ctx, admin)
	elsewhere, _, _ := s.StartSession(ctx, admin)
	guestTok, _, _ := s.StartSession(ctx, other)

	if err := s.ChangePassword(ctx, admin.ID, "not-my-password", "second-password-2", here); err != ErrWrongPassword {
		t.Fatalf("wrong current password: %v", err)
	}
	if err := s.ChangePassword(ctx, admin.ID, "first-password-1", "short", here); err != ErrWeakPassword {
		t.Fatalf("short new password: %v", err)
	}
	if err := s.ChangePassword(ctx, admin.ID, "first-password-1", "first-password-1", here); err != ErrSamePassword {
		t.Fatalf("same password: %v", err)
	}
	if err := s.ChangePassword(ctx, admin.ID, "first-password-1", "second-password-2", here); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "derek", "first-password-1", ""); err == nil {
		t.Fatal("old password still works")
	}
	if _, err := s.Authenticate(ctx, "derek", "second-password-2", ""); err != nil {
		t.Fatal("new password refused")
	}
	if _, err := s.Lookup(ctx, here); err != nil {
		t.Fatal("the session that changed the password was logged out")
	}
	if _, err := s.Lookup(ctx, elsewhere); err == nil {
		t.Fatal("other session survived a password change")
	}
	if _, err := s.Lookup(ctx, guestTok); err != nil {
		t.Fatal("another user's session was ended")
	}

	// admin reset ends all of that user's sessions
	if err := s.ResetPassword(ctx, other.ID, "short"); err != ErrWeakPassword {
		t.Fatalf("short reset: %v", err)
	}
	if err := s.ResetPassword(ctx, 9999, "reset-password-3"); err != ErrNoUser {
		t.Fatalf("reset missing user: %v", err)
	}
	if err := s.ResetPassword(ctx, other.ID, "reset-password-3"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup(ctx, guestTok); err == nil {
		t.Fatal("session survived an admin reset")
	}
	if _, err := s.Authenticate(ctx, "guest", "reset-password-3", ""); err != nil {
		t.Fatal("reset password refused")
	}

	// delete
	if _, err := s.DeleteUser(ctx, admin.ID); err != ErrLastAdmin {
		t.Fatalf("deleted the last admin: %v", err)
	}
	guestTok, _, _ = s.StartSession(ctx, other)
	if u, err := s.DeleteUser(ctx, other.ID); err != nil || u.Username != "guest" {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.Lookup(ctx, guestTok); err == nil {
		t.Fatal("deleted user's session survived")
	}
	if _, err := s.DeleteUser(ctx, other.ID); err != ErrNoUser {
		t.Fatalf("delete twice: %v", err)
	}
	second, _ := s.CreateUser(ctx, "second-admin", "admin-password-4", RoleAdmin)
	if _, err := s.DeleteUser(ctx, second.ID); err != nil {
		t.Fatalf("delete one of two admins: %v", err)
	}
}
