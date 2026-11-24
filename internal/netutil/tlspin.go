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
//
// Drivers build a client on every poll, so the transport (and with it the pool of open
// connections and TLS sessions) is shared between clients with the same certificate settings:
// a poll every 30 seconds reuses the previous poll's connection instead of a new TCP and TLS
// handshake, and old transports don't pile up idle connections. Trust-on-first-use clients
// (mode "pin" with no pin yet) always get a fresh transport, because their Pinner must report
// the certificate of this target's server and not another one's. Each call returns a new
// http.Client, so callers may set Jar or other client fields freely.
func NewClient(mode, pin string, timeout time.Duration) (*http.Client, *Pinner) {
	if mode == "pin" && NormFingerprint(pin) == "" {
		cfg, p := TLSConfig(mode, pin)
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = cfg
		return &http.Client{Timeout: timeout, Transport: tr}, p
	}
	tr, p := sharedTransport(mode, pin)
	return &http.Client{Timeout: timeout, Transport: tr}, p
}

type transportKey struct{ mode, pin string }

type sharedTr struct {
	tr *http.Transport
	p  *Pinner
}

var (
	trMu       sync.Mutex
	transports = map[transportKey]sharedTr{}
)

// sharedTransport returns the one transport for these certificate settings. With a pin set,
// the Pinner reports the pinned certificate (any other is refused), so sharing it is safe.
func sharedTransport(mode, pin string) (*http.Transport, *Pinner) {
	if mode != "pin" {
		mode = "" // "verify", "" and anything else all mean normal CA checks
		pin = ""
	}
	k := transportKey{mode, NormFingerprint(pin)}
	trMu.Lock()
	defer trMu.Unlock()
	if s, ok := transports[k]; ok {
		return s.tr, s.p
	}
	cfg, p := TLSConfig(k.mode, k.pin)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg
	tr.MaxIdleConnsPerHost = 4
	if len(transports) >= 256 { // pins change rarely; never let a long-running server grow without bound
		for key, s := range transports {
			s.tr.CloseIdleConnections()
			delete(transports, key)
		}
	}
	transports[k] = sharedTr{tr, p}
	return tr, p
}

// TLSConfig builds the TLS settings NewClient uses, for clients that bring their own transport.
func TLSConfig(mode, pin string) (*tls.Config, *Pinner) {
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
	return cfg, p
}
