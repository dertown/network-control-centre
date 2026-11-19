// Package netutil has shared HTTP client helpers.
package netutil

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// TLSMode chooses how a target's certificate is checked.
//
//   - "verify" (default): normal CA verification.
//   - "pin": trust exactly the certificate whose SHA-256 fingerprint is pinned;
//     if nothing is pinned yet, trust on first use and report the fingerprint so it can be saved.
//
// UniFi consoles such as the Dream Router ship a self-signed certificate, so "pin" is the
// safe choice for them rather than turning verification off.
type TLSMode string

// Pinner records the fingerprint seen on the last connection.
type Pinner struct {
	mu   sync.Mutex
	seen string
}

// Seen returns the leaf fingerprint observed on the last handshake.
func (p *Pinner) Seen() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.seen
}

// Fingerprint is the colon-free lowercase hex SHA-256 of a DER certificate.
func Fingerprint(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

// NormFingerprint strips colons and spaces.
func NormFingerprint(s string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(s))
}

// NewClient builds an HTTP client for a target. mode "pin" with an empty pin means trust-on-first-use.
func NewClient(mode, pin string, timeout time.Duration) (*http.Client, *Pinner) {
	p := &Pinner{}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if mode == "pin" {
		want := NormFingerprint(pin)
		cfg.InsecureSkipVerify = true // replaced by the fingerprint check below
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificate")
			}
			got := Fingerprint(cs.PeerCertificates[0].Raw)
			p.mu.Lock()
			p.seen = got
			p.mu.Unlock()
			if want != "" && got != want {
				return fmt.Errorf("certificate fingerprint changed: pinned %s, got %s", want, got)
			}
			return nil
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg
	return &http.Client{Timeout: timeout, Transport: tr}, p
}
