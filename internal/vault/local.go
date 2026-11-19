package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Local is the built-in encrypted vault. Secrets are envelope-encrypted:
// each secret has its own random AES-256-GCM data key, and that key is
// wrapped by a master key derived from the unseal passphrase with Argon2id.
// The master key only ever lives in memory.
type Local struct {
	db     *sql.DB
	mu     sync.RWMutex
	master []byte // nil while sealed
}

// Argon2id parameters (OWASP-recommended range).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 2
	keyLen       = 32
	checkPlain   = "ncc-local-vault-v1"
)

// NewLocal returns a sealed local vault on db.
func NewLocal(db *sql.DB) *Local { return &Local{db: db} }

// Backend implements Store.
func (l *Local) Backend() string { return "local" }

func (l *Local) meta(ctx context.Context, k string) ([]byte, error) {
	var v []byte
	err := l.db.QueryRowContext(ctx, `SELECT v FROM vault_meta WHERE k = ?`, k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return v, err
}

func derive(pass string, salt []byte) []byte {
	return argon2.IDKey([]byte(pass), salt, argonTime, argonMemory, argonThreads, keyLen)
}

func seal(key, plain, aad []byte) (nonce, ct []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plain, aad), nil
}

func open(key, nonce, ct, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, aad)
}

// Initialize sets the passphrase on a new vault and leaves it unsealed.
func (l *Local) Initialize(ctx context.Context, passphrase string) error {
	if len(passphrase) < 12 {
		return errors.New("passphrase must be at least 12 characters")
	}
	if salt, err := l.meta(ctx, "salt"); err != nil {
		return err
	} else if salt != nil {
		return errors.New("vault already initialized")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := derive(passphrase, salt)
	nonce, ct, err := seal(key, []byte(checkPlain), []byte("check"))
	if err != nil {
		return err
	}
	_, err = l.db.ExecContext(ctx,
		`INSERT INTO vault_meta (k, v) VALUES ('salt', ?), ('check_nonce', ?), ('check', ?)`, salt, nonce, ct)
	if err != nil {
		return err
	}
	l.mu.Lock()
	l.master = key
	l.mu.Unlock()
	return nil
}

// Unseal derives the master key and checks it against the stored verifier.
func (l *Local) Unseal(ctx context.Context, passphrase string) error {
	salt, err := l.meta(ctx, "salt")
	if err != nil {
		return err
	}
	if salt == nil {
		return errors.New("vault not initialized")
	}
	nonce, _ := l.meta(ctx, "check_nonce")
	ct, _ := l.meta(ctx, "check")
	key := derive(passphrase, salt)
	plain, err := open(key, nonce, ct, []byte("check"))
	if err != nil || subtle.ConstantTimeCompare(plain, []byte(checkPlain)) != 1 {
		return errors.New("wrong passphrase")
	}
	l.mu.Lock()
	l.master = key
	l.mu.Unlock()
	return nil
}

// Seal forgets the master key.
func (l *Local) Seal() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.master {
		l.master[i] = 0
	}
	l.master = nil
}

// Status implements Store.
func (l *Local) Status(ctx context.Context) Status {
	salt, _ := l.meta(ctx, "salt")
	l.mu.RLock()
	sealed := l.master == nil
	l.mu.RUnlock()
	return Status{Backend: "local", Initialized: salt != nil, Sealed: sealed}
}

func (l *Local) key() ([]byte, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.master == nil {
		return nil, ErrSealed
	}
	k := make([]byte, len(l.master))
	copy(k, l.master)
	return k, nil
}

// Put implements Store.
func (l *Local) Put(ctx context.Context, path string, s Secret) (int, error) {
	path, err := CleanPath(path)
	if err != nil {
		return 0, err
	}
	master, err := l.key()
	if err != nil {
		return 0, err
	}
	plain, err := json.Marshal(s)
	if err != nil {
		return 0, err
	}
	dek := make([]byte, keyLen)
	if _, err := rand.Read(dek); err != nil {
		return 0, err
	}
	aad := []byte(path)
	nonce, ct, err := seal(dek, plain, aad)
	if err != nil {
		return 0, err
	}
	wnonce, wct, err := seal(master, dek, aad)
	if err != nil {
		return 0, err
	}
	wrapped := append(wnonce, wct...)
	var version int
	err = l.db.QueryRowContext(ctx, `SELECT version FROM local_secrets WHERE path = ?`, path).Scan(&version)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	version++
	_, err = l.db.ExecContext(ctx, `INSERT INTO local_secrets (path, version, wrapped_key, nonce, ciphertext, updated_at)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(path) DO UPDATE SET version=excluded.version, wrapped_key=excluded.wrapped_key,
		nonce=excluded.nonce, ciphertext=excluded.ciphertext, updated_at=excluded.updated_at`,
		path, version, wrapped, nonce, ct, time.Now().UTC())
	return version, err
}

// Get implements Store.
func (l *Local) Get(ctx context.Context, path string) (Secret, error) {
	path, err := CleanPath(path)
	if err != nil {
		return nil, err
	}
	master, err := l.key()
	if err != nil {
		return nil, err
	}
	var wrapped, nonce, ct []byte
	err = l.db.QueryRowContext(ctx, `SELECT wrapped_key, nonce, ciphertext FROM local_secrets WHERE path = ?`, path).
		Scan(&wrapped, &nonce, &ct)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	aad := []byte(path)
	if len(wrapped) < 12 {
		return nil, errors.New("corrupt wrapped key")
	}
	dek, err := open(master, wrapped[:12], wrapped[12:], aad)
	if err != nil {
		return nil, fmt.Errorf("unwrap key: %w", err)
	}
	plain, err := open(dek, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt secret: %w", err)
	}
	var s Secret
	return s, json.Unmarshal(plain, &s)
}

// List implements Store. It works while sealed: paths are not secret.
func (l *Local) List(ctx context.Context, prefix string) ([]string, error) {
	prefix = strings.Trim(prefix, "/")
	rows, err := l.db.QueryContext(ctx, `SELECT path FROM local_secrets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		if prefix == "" || p == prefix || strings.HasPrefix(p, prefix+"/") {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, rows.Err()
}

// Delete implements Store.
func (l *Local) Delete(ctx context.Context, path string) error {
	path, err := CleanPath(path)
	if err != nil {
		return err
	}
	if _, err := l.key(); err != nil {
		return err
	}
	_, err = l.db.ExecContext(ctx, `DELETE FROM local_secrets WHERE path = ?`, path)
	return err
}
