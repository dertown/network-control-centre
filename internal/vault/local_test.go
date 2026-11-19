package vault_test

import (
	"context"
	"errors"
	"testing"

	"github.com/dertown/network-control-centre/internal/store"
	"github.com/dertown/network-control-centre/internal/vault"
)

func TestLocalVaultLifecycle(t *testing.T) {
	st, err := store.OpenPath(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	v := vault.NewLocal(st.DB)

	if _, err := v.Put(ctx, "a/b", vault.Secret{"x": "1"}); !errors.Is(err, vault.ErrSealed) {
		t.Fatalf("put while uninitialised: %v", err)
	}
	if err := v.Initialize(ctx, "short"); err == nil {
		t.Fatal("short passphrase accepted")
	}
	if err := v.Initialize(ctx, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if ver, err := v.Put(ctx, "targets/device/home", vault.Secret{"username": "ncc", "password": "p@ss"}); err != nil || ver != 1 {
		t.Fatalf("put: %v %d", err, ver)
	}
	if ver, _ := v.Put(ctx, "targets/device/home", vault.Secret{"username": "ncc", "password": "p@ss2"}); ver != 2 {
		t.Fatalf("version not bumped: %d", ver)
	}

	// ciphertext must not contain the plaintext
	var ct []byte
	_ = st.DB.QueryRow(`SELECT ciphertext FROM local_secrets WHERE path = 'targets/device/home'`).Scan(&ct)
	if string(ct) == "" || containsBytes(ct, "p@ss2") {
		t.Fatal("secret stored in clear")
	}

	v.Seal()
	if _, err := v.Get(ctx, "targets/device/home"); !errors.Is(err, vault.ErrSealed) {
		t.Fatalf("get while sealed: %v", err)
	}
	if err := v.Unseal(ctx, "wrong passphrase!!"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if err := v.Unseal(ctx, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	s, err := v.Get(ctx, "targets/device/home")
	if err != nil || s["password"] != "p@ss2" {
		t.Fatalf("get: %v %v", s, err)
	}

	// moving ciphertext to another path breaks authentication (path is the AAD)
	_, _ = st.DB.Exec(`INSERT INTO local_secrets SELECT 'stolen', version, wrapped_key, nonce, ciphertext, updated_at FROM local_secrets WHERE path='targets/device/home'`)
	if _, err := v.Get(ctx, "stolen"); err == nil {
		t.Fatal("copied ciphertext decrypted under another path")
	}

	ps, _ := v.List(ctx, "targets")
	if len(ps) != 1 || ps[0] != "targets/device/home" {
		t.Fatalf("list: %v", ps)
	}
	if _, err := v.Get(ctx, "../etc"); err == nil {
		t.Fatal("path traversal accepted")
	}
	if err := v.Delete(ctx, "targets/device/home"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get(ctx, "targets/device/home"); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}

func containsBytes(b []byte, s string) bool {
	for i := 0; i+len(s) <= len(b); i++ {
		if string(b[i:i+len(s)]) == s {
			return true
		}
	}
	return false
}
