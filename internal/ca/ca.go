// Package ca is NCC's internal certificate authority: a self-signed root (and optional
// intermediates) whose private keys live only in the vault, the server and client
// certificates they sign, renewal, revocation and the certificate revocation list (CRL).
//
// Issued certificates go into the certificate inventory (internal/pki) with their keys in
// the vault, so Certificate Deployment installs them like any other certificate. Each CA's
// own certificate is added to the inventory too (without a key), so it can be downloaded and
// pushed to servers' trust stores.
package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // Windows thumbprints are SHA-1 by definition
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/pki"
	"github.com/dertown/network-control-centre/internal/vault"
)

// Service runs the internal CAs.
type Service struct {
	DB    *sql.DB
	Vault vault.Store
	Certs *pki.Inventory
	// Now can be replaced in tests.
	Now func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Key types NCC can make. RSA is the default because every device and old Java or embedded
// client accepts it; ECDSA keys are smaller and faster where everything is modern.
var KeyTypes = []string{"rsa-2048", "rsa-3072", "rsa-4096", "ecdsa-p256", "ecdsa-p384"}

// Limits.
const (
	// MaxLeafDays is the longest server certificate Apple devices accept (and the CA/Browser
	// Forum's old limit): 825 days.
	MaxLeafDays     = 825
	DefaultLeafDays = 397
	MaxCAYears      = 30
	crlLife         = 7 * 24 * time.Hour
)

// SecretPrefix is the vault folder holding CA private keys. The vault API refuses to reveal,
// replace or delete anything under it.
const SecretPrefix = "ca/"

// ErrNotFound is returned for unknown CAs and issued certificates.
var ErrNotFound = errors.New("not found")

// CA is one certificate authority.
type CA struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	ParentID    int64     `json:"parent_id"`
	Parent      string    `json:"parent,omitempty"`
	Root        bool      `json:"root"`
	CommonName  string    `json:"common_name"`
	Subject     string    `json:"subject"`
	KeyType     string    `json:"key_type"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	DaysLeft    int       `json:"days_left"`
	Fingerprint string    `json:"fingerprint"` // SHA-256, lower-case hex
	Thumbprint  string    `json:"thumbprint"`  // SHA-1, upper-case (what Windows shows)
	Serial      string    `json:"serial"`
	MaxPathLen  int       `json:"max_path_len"`
	// PermittedDomains are the name constraints: the only DNS names this CA can sign for.
	PermittedDomains []string `json:"permitted_domains"`
	CRLURL           string   `json:"crl_url"`
	CRLNumber        int64    `json:"crl_number"`
	// InventoryName is the CA certificate's entry in the certificate inventory.
	InventoryName string `json:"inventory_name"`
	InventoryID   int64  `json:"inventory_id"`
	Active        int    `json:"active"`  // issued, valid and not revoked
	Revoked       int    `json:"revoked"` // revoked and not yet expired
	CreatedBy     string `json:"created_by"`
	// Issuing is true for the CA new certificates are signed by by default: the newest
	// intermediate, or the root when there is none.
	Issuing bool `json:"issuing"`

	cert    *x509.Certificate
	certPEM string
	keyPath string
}

// Cert returns the CA certificate.
func (c *CA) Cert() *x509.Certificate { return c.cert }

// PEM returns the CA certificate in PEM.
func (c *CA) PEM() string { return c.certPEM }

// ---- keys ----

func generateKey(kt string) (crypto.Signer, error) {
	switch kt {
	case "rsa-2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa-3072":
		return rsa.GenerateKey(rand.Reader, 3072)
	case "rsa-4096":
		return rsa.GenerateKey(rand.Reader, 4096)
	case "ecdsa-p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	}
	return nil, fmt.Errorf("unknown key type %q (use one of %s)", kt, strings.Join(KeyTypes, ", "))
}

func encodeKey(k crypto.Signer) (string, error) {
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})), nil
}

func decodeKey(p string) (crypto.Signer, error) {
	b, _ := pem.Decode([]byte(p))
	if b == nil {
		return nil, errors.New("CA key in the vault is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("CA key in the vault cannot sign")
	}
	return s, nil
}

func certPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func newSerial() (*big.Int, error) {
	// 127 random bits: always positive, at least 64 bits of entropy as the Baseline Requirements ask
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func subjectKeyID(pub crypto.PublicKey) []byte {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	h := sha1.Sum(b) //nolint:gosec // RFC 5280 method 1 key identifier
	return h[:]
}

// ---- validation ----

var (
	caNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,62}$`)
	labelRe  = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)
)

// CleanDNSName lower-cases a host name, drops a trailing dot and checks it. A leading "*."
// (wildcard) is allowed when wildcard is true.
func CleanDNSName(n string, wildcard bool) (string, error) {
	n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
	if n == "" {
		return "", errors.New("empty name")
	}
	body := n
	if strings.HasPrefix(n, "*.") {
		if !wildcard {
			return "", fmt.Errorf("%s: a wildcard is not allowed here", n)
		}
		body = n[2:]
	}
	if len(body) > 253 {
		return "", fmt.Errorf("%s: too long", n)
	}
	for _, l := range strings.Split(body, ".") {
		if !labelRe.MatchString(l) {
			return "", fmt.Errorf("%q is not a valid host name", n)
		}
	}
	return n, nil
}

func cleanDomains(in []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, d := range in {
		d = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(d), "*"), ".")
		if d == "" {
			continue
		}
		c, err := CleanDNSName(d, false)
		if err != nil {
			return nil, err
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out, nil
}

func cleanCRLURL(u string) (string, error) {
	u = strings.TrimSpace(u)
	if u == "" {
		return "", nil
	}
	p, err := url.Parse(u)
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
		return "", errors.New("the CRL address must be an http:// or https:// URL")
	}
	return u, nil
}

// inDomains reports whether a DNS name falls under one of the permitted domains (RFC 5280
// name constraints: the domain itself and every name under it).
func inDomains(name string, domains []string) bool {
	if len(domains) == 0 {
		return true
	}
	name = strings.TrimPrefix(name, "*.")
	for _, d := range domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// ---- reading ----

const caCols = `id, name, parent_id, cert_pem, key_secret_path, key_type, inventory_name, crl_url, crl_number, created_by`

func (s *Service) scan(sc interface{ Scan(...any) error }) (*CA, error) {
	var c CA
	if err := sc.Scan(&c.ID, &c.Name, &c.ParentID, &c.certPEM, &c.keyPath, &c.KeyType, &c.InventoryName, &c.CRLURL, &c.CRLNumber, &c.CreatedBy); err != nil {
		return nil, err
	}
	certs, err := pki.ParseChain(c.certPEM)
	if err != nil {
		return nil, fmt.Errorf("CA %s: %w", c.Name, err)
	}
	x := certs[0]
	c.cert = x
	c.Root = c.ParentID == 0
	c.CommonName = x.Subject.CommonName
	c.Subject = x.Subject.String()
	c.NotBefore, c.NotAfter = x.NotBefore, x.NotAfter
	c.DaysLeft = int(x.NotAfter.Sub(s.now()).Hours() / 24)
	c.Fingerprint = pki.Fingerprint(x)
	t := sha1.Sum(x.Raw) //nolint:gosec
	c.Thumbprint = strings.ToUpper(hex.EncodeToString(t[:]))
	c.Serial = x.SerialNumber.Text(16)
	c.MaxPathLen = x.MaxPathLen
	if x.MaxPathLenZero {
		c.MaxPathLen = 0
	}
	c.PermittedDomains = append([]string{}, x.PermittedDNSDomains...)
	return &c, nil
}

// List returns every CA, roots first, each followed by its intermediates.
func (s *Service) List(ctx context.Context) ([]CA, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+caCols+` FROM cas ORDER BY id`)
	if err != nil {
		return nil, err
	}
	var all []*CA
	for rows.Next() {
		c, err := s.scan(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		all = append(all, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	byID := map[int64]*CA{}
	for _, c := range all {
		byID[c.ID] = c
	}
	now := s.now().UTC().Format(time.RFC3339)
	for _, c := range all {
		if p := byID[c.ParentID]; p != nil {
			c.Parent = p.Name
		}
		_ = s.DB.QueryRowContext(ctx, `SELECT
			COALESCE(SUM(CASE WHEN revoked_at = '' AND replaced_by = 0 AND not_after > ? THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN revoked_at != '' AND not_after > ? THEN 1 ELSE 0 END), 0)
			FROM ca_issued WHERE ca_id = ?`, now, now, c.ID).Scan(&c.Active, &c.Revoked)
		var fp string
		if err := s.DB.QueryRowContext(ctx, `SELECT id, fingerprint FROM certificates WHERE name = ?`, c.InventoryName).Scan(&c.InventoryID, &fp); err != nil || fp != c.Fingerprint {
			c.InventoryID = 0
		}
	}
	// issuing CA: the newest usable intermediate, else the newest root
	if iss := pickIssuing(all, s.now()); iss != nil {
		iss.Issuing = true
	}
	out := []CA{}
	for _, c := range all {
		if c.ParentID != 0 {
			continue
		}
		out = append(out, *c)
		for _, k := range all {
			if k.ParentID == c.ID {
				out = append(out, *k)
			}
		}
	}
	return out, nil
}

func pickIssuing(all []*CA, now time.Time) *CA {
	var best *CA
	for _, c := range all {
		if c.NotAfter.Before(now) {
			continue
		}
		switch {
		case best == nil:
			best = c
		case best.Root && !c.Root:
			best = c
		case best.Root == c.Root && c.ID > best.ID:
			best = c
		}
	}
	return best
}

// Get loads one CA.
func (s *Service) Get(ctx context.Context, id int64) (*CA, error) {
	all, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].ID == id {
			return &all[i], nil
		}
	}
	return nil, ErrNotFound
}

// Chain returns a CA and its parents, up to the root (the CA first).
func (s *Service) Chain(ctx context.Context, id int64) ([]*CA, error) {
	var out []*CA
	for range 8 {
		c, err := s.scan(s.DB.QueryRowContext(ctx, `SELECT `+caCols+` FROM cas WHERE id = ?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		if c.ParentID == 0 {
			return out, nil
		}
		id = c.ParentID
	}
	return nil, errors.New("CA chain is too long")
}

// signer reads a CA's private key from the vault.
func (s *Service) signer(ctx context.Context, c *CA) (crypto.Signer, error) {
	sec, err := s.Vault.Get(ctx, c.keyPath)
	if err != nil {
		if errors.Is(err, vault.ErrSealed) {
			return nil, err
		}
		return nil, fmt.Errorf("read the CA key for %s from the vault: %w", c.Name, err)
	}
	k, err := decodeKey(sec["private_key"])
	if err != nil {
		return nil, err
	}
	type eq interface{ Equal(crypto.PublicKey) bool }
	if e, ok := k.Public().(eq); !ok || !e.Equal(c.cert.PublicKey) {
		return nil, fmt.Errorf("the key in the vault at %s does not match %s's certificate", c.keyPath, c.Name)
	}
	return k, nil
}

// ---- creating CAs ----

// RootRequest asks for a new self-signed root CA.
type RootRequest struct {
	Name             string   `json:"name"`
	CommonName       string   `json:"common_name"`
	Organization     string   `json:"organization"`
	KeyType          string   `json:"key_type"`
	Years            int      `json:"years"`
	PermittedDomains []string `json:"permitted_domains"`
	CRLURL           string   `json:"crl_url"`
}

// IntermediateRequest asks for a CA signed by another NCC CA.
type IntermediateRequest struct {
	Name         string `json:"name"`
	CommonName   string `json:"common_name"`
	Organization string `json:"organization"`
	KeyType      string `json:"key_type"`
	Years        int    `json:"years"`
	CRLURL       string `json:"crl_url"`
}

func (s *Service) checkNewName(ctx context.Context, name string) error {
	if !caNameRe.MatchString(name) {
		return errors.New("the CA name may use letters, digits, spaces, dot, dash, underscore and brackets (max 63)")
	}
	var n int
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM cas WHERE name = ?`, name).Scan(&n)
	if n > 0 {
		return fmt.Errorf("a CA called %q already exists", name)
	}
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM certificates WHERE name = ?`, name).Scan(&n)
	if n > 0 {
		return fmt.Errorf("the certificate list already has an entry called %q; pick another CA name", name)
	}
	return nil
}

func keyPathFor(name string) string {
	return SecretPrefix + strings.NewReplacer(" ", "_", "/", "_", "(", "", ")", "").Replace(name)
}

// CreateRoot makes a self-signed root CA. Its key goes straight into the vault.
func (s *Service) CreateRoot(ctx context.Context, r RootRequest, actor string) (*CA, error) {
	r.Name = strings.TrimSpace(r.Name)
	if err := s.checkNewName(ctx, r.Name); err != nil {
		return nil, err
	}
	if r.CommonName = strings.TrimSpace(r.CommonName); r.CommonName == "" {
		r.CommonName = r.Name
	}
	if r.KeyType == "" {
		r.KeyType = "rsa-4096"
	}
	if r.Years == 0 {
		r.Years = 10
	}
	if r.Years < 1 || r.Years > MaxCAYears {
		return nil, fmt.Errorf("a root CA can be valid for 1 to %d years", MaxCAYears)
	}
	domains, err := cleanDomains(r.PermittedDomains)
	if err != nil {
		return nil, fmt.Errorf("allowed domains: %w", err)
	}
	crlURL, err := cleanCRLURL(r.CRLURL)
	if err != nil {
		return nil, err
	}
	key, err := generateKey(r.KeyType)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := s.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject(r.CommonName, r.Organization),
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(r.Years, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1, // root -> intermediate -> leaf
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          subjectKeyID(key.Public()),
	}
	if len(domains) > 0 {
		tmpl.PermittedDNSDomainsCritical = true
		tmpl.PermittedDNSDomains = domains
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return s.store(ctx, r.Name, 0, der, key, r.KeyType, crlURL, actor, nil)
}

// CreateIntermediate makes a CA signed by parentID. It inherits the parent's allowed domains.
func (s *Service) CreateIntermediate(ctx context.Context, parentID int64, r IntermediateRequest, actor string) (*CA, error) {
	chain, err := s.Chain(ctx, parentID)
	if err != nil {
		return nil, err
	}
	parent := chain[0]
	if !parent.Root {
		return nil, errors.New("intermediates are signed by the root CA; pick the root")
	}
	r.Name = strings.TrimSpace(r.Name)
	if err := s.checkNewName(ctx, r.Name); err != nil {
		return nil, err
	}
	if r.CommonName = strings.TrimSpace(r.CommonName); r.CommonName == "" {
		r.CommonName = r.Name
	}
	if r.Organization == "" && len(parent.cert.Subject.Organization) > 0 {
		r.Organization = parent.cert.Subject.Organization[0]
	}
	if r.KeyType == "" {
		r.KeyType = parent.KeyType
	}
	if r.Years == 0 {
		r.Years = 5
	}
	if r.Years < 1 || r.Years > MaxCAYears {
		return nil, fmt.Errorf("an intermediate CA can be valid for 1 to %d years", MaxCAYears)
	}
	crlURL, err := cleanCRLURL(r.CRLURL)
	if err != nil {
		return nil, err
	}
	psigner, err := s.signer(ctx, parent)
	if err != nil {
		return nil, err
	}
	key, err := generateKey(r.KeyType)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := s.now()
	notAfter := now.AddDate(r.Years, 0, 0)
	if notAfter.After(parent.NotAfter) {
		notAfter = parent.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject(r.CommonName, r.Organization),
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true, // signs only end-entity certificates
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          subjectKeyID(key.Public()),
	}
	if d := parent.cert.PermittedDNSDomains; len(d) > 0 {
		tmpl.PermittedDNSDomainsCritical = true
		tmpl.PermittedDNSDomains = d
	}
	if parent.CRLURL != "" {
		tmpl.CRLDistributionPoints = []string{parent.CRLURL}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, key.Public(), psigner)
	if err != nil {
		return nil, err
	}
	return s.store(ctx, r.Name, parent.ID, der, key, r.KeyType, crlURL, actor, chain)
}

func subject(cn, org string) pkix.Name {
	n := pkix.Name{CommonName: cn}
	if org = strings.TrimSpace(org); org != "" {
		n.Organization = []string{org}
	}
	return n
}

// store saves a new CA: key to the vault, row to the database, certificate to the inventory.
func (s *Service) store(ctx context.Context, name string, parentID int64, der []byte, key crypto.Signer, keyType, crlURL, actor string, parents []*CA) (*CA, error) {
	keyPEM, err := encodeKey(key)
	if err != nil {
		return nil, err
	}
	path := keyPathFor(name)
	if _, err := s.Vault.Get(ctx, path); err == nil {
		return nil, fmt.Errorf("the vault already holds a key at %s; NCC will not overwrite it", path)
	} else if !errors.Is(err, vault.ErrNotFound) {
		return nil, err
	}
	if _, err := s.Vault.Put(ctx, path, vault.Secret{"private_key": keyPEM, "ca": name}); err != nil {
		return nil, fmt.Errorf("store the CA key in the vault: %w", err)
	}
	pemText := certPEM(der)
	res, err := s.DB.ExecContext(ctx, `INSERT INTO cas (name, parent_id, cert_pem, key_secret_path, key_type, inventory_name, crl_url, created_by)
		VALUES (?,?,?,?,?,?,?,?)`, name, parentID, pemText, path, keyType, name, crlURL, actor)
	if err != nil {
		_ = s.Vault.Delete(ctx, path)
		return nil, err
	}
	id, _ := res.LastInsertId()
	// the CA certificate (with its parents) goes into the inventory without a key, so it can be
	// downloaded and deployed to trust stores
	var bundle strings.Builder
	for _, p := range parents {
		bundle.WriteString(p.certPEM)
	}
	if _, err := s.Certs.Import(ctx, name, pemText, "", bundle.String()); err != nil {
		return nil, fmt.Errorf("CA created, but adding it to the certificate list failed: %w", err)
	}
	c, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if _, err := s.RefreshCRL(ctx, id); err != nil {
		return nil, fmt.Errorf("CA created, but its first CRL failed: %w", err)
	}
	return c, nil
}

// SetCRLURL changes the CRL address written into certificates signed from now on.
func (s *Service) SetCRLURL(ctx context.Context, id int64, u string) (*CA, error) {
	u, err := cleanCRLURL(u)
	if err != nil {
		return nil, err
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE cas SET crl_url = ? WHERE id = ?`, u, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}
	return s.Get(ctx, id)
}

// Delete removes a CA and its key. It refuses while the CA has intermediates or certificates
// that are still valid and not revoked, since those would stop being renewable or revocable.
func (s *Service) Delete(ctx context.Context, id int64) (*CA, error) {
	c, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	var kids int
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM cas WHERE parent_id = ?`, id).Scan(&kids)
	if kids > 0 {
		return nil, errors.New("delete its intermediate CAs first")
	}
	if c.Active > 0 {
		return nil, fmt.Errorf("%s still has %d valid certificate(s); revoke them first", c.Name, c.Active)
	}
	if err := s.Vault.Delete(ctx, c.keyPath); err != nil && !errors.Is(err, vault.ErrNotFound) {
		return nil, err
	}
	if c.InventoryID != 0 {
		_ = s.Certs.Delete(ctx, c.InventoryID)
	}
	_, err = s.DB.ExecContext(ctx, `DELETE FROM cas WHERE id = ?`, id)
	return c, err
}

// fingerprint is the inventory's fingerprint of DER bytes.
func fingerprint(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

func ipList(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}
