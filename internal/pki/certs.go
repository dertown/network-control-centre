// Package pki keeps the certificate inventory: imported certificates with their
// private keys stored in the vault, and expiry tracking.
package pki

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/vault"
)

// Cert is one certificate in the inventory.
type Cert struct {
	ID            int64     `json:"id"`
	Name          string    `json:"name"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	SANs          []string  `json:"sans"`
	Serial        string    `json:"serial"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	Fingerprint   string    `json:"fingerprint"`
	HasKey        bool      `json:"has_key"`
	DaysLeft      int       `json:"days_left"`
	Status        string    `json:"status"` // ok | expiring | critical | expired
	ChainLength   int       `json:"chain_length"`
	keySecretPath string
}

// Inventory stores certificates.
type Inventory struct {
	DB    *sql.DB
	Vault vault.Store
}

// Status thresholds in days.
const (
	WarnDays     = 30
	CriticalDays = 7
)

func status(days int) string {
	switch {
	case days < 0:
		return "expired"
	case days <= CriticalDays:
		return "critical"
	case days <= WarnDays:
		return "expiring"
	default:
		return "ok"
	}
}

// ParseChain decodes PEM certificates (leaf first).
func ParseChain(certPEM string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(certPEM)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no CERTIFICATE blocks found")
	}
	return out, nil
}

func checkKeyMatches(leaf *x509.Certificate, keyPEM string) error {
	b, _ := pem.Decode([]byte(keyPEM))
	if b == nil {
		return errors.New("private key is not PEM")
	}
	var key any
	var err error
	switch b.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(b.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(b.Bytes)
	default:
		return fmt.Errorf("unsupported key type %q", b.Type)
	}
	if err != nil {
		return err
	}
	type eq interface{ Equal(crypto.PublicKey) bool }
	signer, ok := key.(crypto.Signer)
	if !ok {
		return errors.New("key has no public half")
	}
	if e, ok := signer.Public().(eq); !ok || !e.Equal(leaf.PublicKey) {
		return errors.New("private key does not match the certificate")
	}
	return nil
}

// Import adds a certificate (and optional private key, which goes to the vault).
func (inv *Inventory) Import(ctx context.Context, name, certPEM, keyPEM string) (*Cert, error) {
	name = strings.TrimSpace(name)
	chain, err := ParseChain(certPEM)
	if err != nil {
		return nil, err
	}
	leaf := chain[0]
	if name == "" {
		name = leaf.Subject.CommonName
	}
	if name == "" && len(leaf.DNSNames) > 0 {
		name = leaf.DNSNames[0]
	}
	if name == "" {
		return nil, errors.New("give the certificate a name")
	}
	keyPath := ""
	if strings.TrimSpace(keyPEM) != "" {
		if err := checkKeyMatches(leaf, keyPEM); err != nil {
			return nil, err
		}
		keyPath = "certs/" + strings.NewReplacer("/", "_", " ", "_").Replace(name)
		if _, err := inv.Vault.Put(ctx, keyPath, vault.Secret{"private_key": keyPEM}); err != nil {
			return nil, fmt.Errorf("store key in vault: %w", err)
		}
	}
	fp := sha256.Sum256(leaf.Raw)
	sans := append([]string{}, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		sans = append(sans, ip.String())
	}
	_, err = inv.DB.ExecContext(ctx, `INSERT INTO certificates
		(name, subject, issuer, sans, serial, not_before, not_after, fingerprint, cert_pem, key_secret_path)
		VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET subject=excluded.subject, issuer=excluded.issuer, sans=excluded.sans,
		serial=excluded.serial, not_before=excluded.not_before, not_after=excluded.not_after,
		fingerprint=excluded.fingerprint, cert_pem=excluded.cert_pem,
		key_secret_path=CASE WHEN excluded.key_secret_path != '' THEN excluded.key_secret_path ELSE certificates.key_secret_path END`,
		name, leaf.Subject.String(), leaf.Issuer.String(), strings.Join(sans, ","), leaf.SerialNumber.Text(16),
		leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339),
		hex.EncodeToString(fp[:]), certPEM, keyPath)
	if err != nil {
		return nil, err
	}
	certs, err := inv.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range certs {
		if c.Name == name {
			return &c, nil
		}
	}
	return nil, errors.New("certificate vanished after import")
}

// List returns the inventory, soonest expiry first.
func (inv *Inventory) List(ctx context.Context) ([]Cert, error) {
	rows, err := inv.DB.QueryContext(ctx, `SELECT id, name, subject, issuer, sans, serial, not_before, not_after,
		fingerprint, key_secret_path, cert_pem FROM certificates ORDER BY not_after ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now()
	var out []Cert
	for rows.Next() {
		var c Cert
		var sans, nb, na, pemText string
		if err := rows.Scan(&c.ID, &c.Name, &c.Subject, &c.Issuer, &sans, &c.Serial, &nb, &na, &c.Fingerprint, &c.keySecretPath, &pemText); err != nil {
			return nil, err
		}
		c.NotBefore, _ = time.Parse(time.RFC3339, nb)
		c.NotAfter, _ = time.Parse(time.RFC3339, na)
		if sans != "" {
			c.SANs = strings.Split(sans, ",")
		}
		c.HasKey = c.keySecretPath != ""
		c.DaysLeft = int(c.NotAfter.Sub(now).Hours() / 24)
		if c.NotAfter.Before(now) {
			c.DaysLeft = -1
		}
		c.Status = status(c.DaysLeft)
		c.ChainLength = strings.Count(pemText, "BEGIN CERTIFICATE")
		out = append(out, c)
	}
	return out, rows.Err()
}

// PEM returns the stored certificate chain.
func (inv *Inventory) PEM(ctx context.Context, id int64) (string, error) {
	var p string
	err := inv.DB.QueryRowContext(ctx, `SELECT cert_pem FROM certificates WHERE id = ?`, id).Scan(&p)
	return p, err
}

// Delete removes a certificate and its key.
func (inv *Inventory) Delete(ctx context.Context, id int64) error {
	var keyPath string
	if err := inv.DB.QueryRowContext(ctx, `SELECT key_secret_path FROM certificates WHERE id = ?`, id).Scan(&keyPath); err != nil {
		return err
	}
	if keyPath != "" {
		if err := inv.Vault.Delete(ctx, keyPath); err != nil && !errors.Is(err, vault.ErrNotFound) {
			return err
		}
	}
	_, err := inv.DB.ExecContext(ctx, `DELETE FROM certificates WHERE id = ?`, id)
	return err
}

// Get returns one certificate from the inventory.
func (inv *Inventory) Get(ctx context.Context, id int64) (*Cert, error) {
	certs, err := inv.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range certs {
		if certs[i].ID == id {
			return &certs[i], nil
		}
	}
	return nil, sql.ErrNoRows
}

// Material returns a certificate's PEM chain and its private key from the vault, for
// deploying it to a server. The key is empty when the certificate was imported without one.
func (inv *Inventory) Material(ctx context.Context, id int64) (certPEM, keyPEM string, err error) {
	var keyPath string
	if err := inv.DB.QueryRowContext(ctx, `SELECT cert_pem, key_secret_path FROM certificates WHERE id = ?`, id).Scan(&certPEM, &keyPath); err != nil {
		return "", "", err
	}
	if keyPath == "" {
		return certPEM, "", nil
	}
	s, err := inv.Vault.Get(ctx, keyPath)
	if err != nil {
		return "", "", fmt.Errorf("read private key from vault: %w", err)
	}
	return certPEM, s["private_key"], nil
}

// Fingerprint is the inventory's SHA-256 fingerprint (lower-case hex) of a certificate.
func Fingerprint(c *x509.Certificate) string {
	fp := sha256.Sum256(c.Raw)
	return hex.EncodeToString(fp[:])
}
