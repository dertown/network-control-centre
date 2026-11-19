// Package vault stores secrets (device logins, API keys, TSIG keys, private keys)
// behind one interface with pluggable backends.
package vault

import (
	"context"
	"errors"
	"strings"
)

// Secret is a set of named string values, e.g. {"username": "...", "password": "..."}.
type Secret map[string]string

// ErrNotFound is returned when a path holds no secret.
var ErrNotFound = errors.New("secret not found")

// ErrSealed is returned by a sealed local vault.
var ErrSealed = errors.New("vault is sealed")

// Store is the backend-neutral secret store.
type Store interface {
	Backend() string
	Put(ctx context.Context, path string, s Secret) (version int, err error)
	Get(ctx context.Context, path string) (Secret, error)
	List(ctx context.Context, prefix string) ([]string, error)
	Delete(ctx context.Context, path string) error
	Status(ctx context.Context) Status
}

// Status reports whether the backend is usable.
type Status struct {
	Backend     string `json:"backend"`
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	Detail      string `json:"detail,omitempty"`
}

// Unsealer is implemented by backends that start sealed (the local vault).
type Unsealer interface {
	Initialize(ctx context.Context, passphrase string) error
	Unseal(ctx context.Context, passphrase string) error
	Seal()
}

// CleanPath normalises a secret path and rejects traversal.
func CleanPath(p string) (string, error) {
	p = strings.Trim(strings.TrimSpace(p), "/")
	if p == "" {
		return "", errors.New("empty secret path")
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("invalid secret path")
		}
	}
	return p, nil
}

// Redact returns the secret's keys with values hidden, safe to send to a browser.
func Redact(s Secret) map[string]string {
	out := make(map[string]string, len(s))
	for k := range s {
		out[k] = "••••••"
	}
	return out
}
