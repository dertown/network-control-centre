package ca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/pki"
)

// IssueRequest asks an NCC CA for a certificate.
type IssueRequest struct {
	// Name is the certificate's name in the inventory; it defaults to the first host name.
	Name       string   `json:"name"`
	CommonName string   `json:"common_name"`
	DNSNames   []string `json:"dns_names"`
	IPs        []string `json:"ips"`
	Days       int      `json:"days"`
	KeyType    string   `json:"key_type"`
	// Usage is server (TLS web server), client (TLS client) or server+client.
	Usage string `json:"usage"`
}

// Issued is one certificate an NCC CA signed.
type Issued struct {
	ID          int64     `json:"id"`
	CAID        int64     `json:"ca_id"`
	CAName      string    `json:"ca_name"`
	Serial      string    `json:"serial"`
	CertName    string    `json:"cert_name"`
	CommonName  string    `json:"common_name"`
	SANs        []string  `json:"sans"`
	Usage       string    `json:"usage"`
	KeyType     string    `json:"key_type"`
	Days        int       `json:"days"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	DaysLeft    int       `json:"days_left"`
	Fingerprint string    `json:"fingerprint"`
	IssuedBy    string    `json:"issued_by"`
	IssuedAt    time.Time `json:"issued_at"`
	ReplacedBy  int64     `json:"replaced_by"`
	RevokedAt   string    `json:"revoked_at,omitempty"`
	// Reason is the RFC 5280 revocation reason code.
	Reason int `json:"revoke_reason,omitempty"`
	// Status: active | expiring | expired | revoked | replaced
	Status string `json:"status"`
	// InventoryID is the inventory entry holding this exact certificate (0 once renewed).
	InventoryID int64 `json:"inventory_id"`
}

// IssueResult is what Issue and Renew return.
type IssueResult struct {
	Issued *Issued   `json:"issued"`
	Cert   *pki.Cert `json:"cert"`
	Notes  []string  `json:"notes"`
}

// Revocation reasons NCC offers (RFC 5280 CRLReason).
var Reasons = map[int]string{
	0: "unspecified",
	1: "key compromise",
	4: "superseded",
	5: "cessation of operation",
}

func (s *Service) normalise(r *IssueRequest) error {
	var dns []string
	seen := map[string]bool{}
	for _, n := range r.DNSNames {
		if strings.TrimSpace(n) == "" {
			continue
		}
		c, err := CleanDNSName(n, true)
		if err != nil {
			return err
		}
		if !seen[c] {
			seen[c] = true
			dns = append(dns, c)
		}
	}
	var ips []string
	for _, ip := range r.IPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		p := net.ParseIP(ip)
		if p == nil {
			return fmt.Errorf("%q is not an IP address", ip)
		}
		if !seen[p.String()] {
			seen[p.String()] = true
			ips = append(ips, p.String())
		}
	}
	if len(dns)+len(ips) == 0 {
		return errors.New("give at least one host name or IP address")
	}
	if len(dns)+len(ips) > 100 {
		return errors.New("at most 100 names per certificate")
	}
	r.DNSNames, r.IPs = dns, ips
	if r.Days == 0 {
		r.Days = DefaultLeafDays
	}
	if r.Days < 1 || r.Days > MaxLeafDays {
		return fmt.Errorf("validity must be 1 to %d days (Apple devices reject longer server certificates)", MaxLeafDays)
	}
	if r.KeyType == "" {
		r.KeyType = "rsa-2048"
	}
	switch r.Usage {
	case "":
		r.Usage = "server"
	case "server", "client", "server+client":
	default:
		return fmt.Errorf("usage must be server, client or server+client")
	}
	r.CommonName = strings.TrimSpace(r.CommonName)
	if r.CommonName == "" {
		if len(dns) > 0 {
			r.CommonName = dns[0]
		} else {
			r.CommonName = ips[0]
		}
	}
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		r.Name = strings.Replace(r.CommonName, "*", "wildcard", 1)
	}
	if len(r.Name) > 100 || strings.ContainsAny(r.Name, "/\\\x00\n") {
		return errors.New("the certificate name may not contain slashes or line breaks (max 100)")
	}
	return nil
}

// Issue signs a new certificate with CA caID (0 = the issuing CA) and adds it, with its key
// in the vault, to the certificate inventory.
func (s *Service) Issue(ctx context.Context, caID int64, r IssueRequest, actor string) (*IssueResult, error) {
	if err := s.normalise(&r); err != nil {
		return nil, err
	}
	var n int
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM certificates WHERE name = ?`, r.Name).Scan(&n)
	if n > 0 {
		var mine int
		_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM ca_issued WHERE cert_name = ?`, r.Name).Scan(&mine)
		if mine > 0 {
			return nil, fmt.Errorf("%s already exists; renew it instead, or pick another name", r.Name)
		}
		return nil, fmt.Errorf("a certificate called %s is already in the list; pick another name", r.Name)
	}
	return s.issue(ctx, caID, r, actor)
}

func (s *Service) issuingCA(ctx context.Context, caID int64) (int64, error) {
	if caID != 0 {
		return caID, nil
	}
	all, err := s.List(ctx)
	if err != nil {
		return 0, err
	}
	for _, c := range all {
		if c.Issuing {
			return c.ID, nil
		}
	}
	return 0, errors.New("create an internal CA first")
}

func (s *Service) issue(ctx context.Context, caID int64, r IssueRequest, actor string) (*IssueResult, error) {
	caID, err := s.issuingCA(ctx, caID)
	if err != nil {
		return nil, err
	}
	chain, err := s.Chain(ctx, caID)
	if err != nil {
		return nil, err
	}
	ca := chain[0]
	now := s.now()
	if ca.NotAfter.Before(now) {
		return nil, fmt.Errorf("%s has expired", ca.Name)
	}
	for _, d := range r.DNSNames {
		if !inDomains(d, ca.cert.PermittedDNSDomains) {
			return nil, fmt.Errorf("%s is outside the domains %s may sign for (%s)", d, ca.Name, strings.Join(ca.cert.PermittedDNSDomains, ", "))
		}
	}
	signer, err := s.signer(ctx, ca)
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
	res := &IssueResult{Notes: []string{}}
	notAfter := now.Add(time.Duration(r.Days) * 24 * time.Hour)
	if notAfter.After(ca.NotAfter) {
		notAfter = ca.NotAfter
		res.Notes = append(res.Notes, fmt.Sprintf("Shortened to end with %s on %s.", ca.Name, ca.NotAfter.Format("2 Jan 2006")))
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: r.CommonName},
		DNSNames:              r.DNSNames,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SubjectKeyId:          subjectKeyID(key.Public()),
	}
	if len(ca.cert.Subject.Organization) > 0 {
		tmpl.Subject.Organization = ca.cert.Subject.Organization
	}
	if _, ok := key.(*rsa.PrivateKey); ok {
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	for _, ip := range r.IPs {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	var eku []x509.ExtKeyUsage
	switch r.Usage {
	case "server":
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "client":
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	tmpl.ExtKeyUsage = eku
	if ca.CRLURL != "" {
		tmpl.CRLDistributionPoints = []string{ca.CRLURL}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), signer)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	// check it the way a client will: up to the root, with the name constraints applied
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	var bundle strings.Builder
	for _, c := range chain {
		if c.Root {
			roots.AddCert(c.cert)
		} else {
			inter.AddCert(c.cert)
		}
		bundle.WriteString(c.certPEM)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: eku}); err != nil {
		return nil, fmt.Errorf("the new certificate does not check out against %s: %w", ca.Name, err)
	}
	keyPEM, err := encodeKey(key)
	if err != nil {
		return nil, err
	}
	cert, err := s.Certs.Import(ctx, r.Name, certPEM(der), keyPEM, bundle.String())
	if err != nil {
		return nil, fmt.Errorf("store the certificate: %w", err)
	}
	sans := append(append([]string{}, r.DNSNames...), r.IPs...)
	ins, err := s.DB.ExecContext(ctx, `INSERT INTO ca_issued (ca_id, serial, cert_name, common_name, sans, usage, key_type, days,
		not_before, not_after, fingerprint, issued_by, issued_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ca.ID, serial.Text(16), r.Name, r.CommonName, strings.Join(sans, ","), r.Usage, r.KeyType, r.Days,
		leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339), fingerprint(der), actor,
		now.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	id, _ := ins.LastInsertId()
	res.Issued, err = s.GetIssued(ctx, id)
	if err != nil {
		return nil, err
	}
	res.Cert = cert
	return res, nil
}

// Renew signs a fresh certificate with the same names, usage, key type and validity, under the
// same inventory name, so servers set up to receive it get the new one on their next deploy.
// The old certificate stays valid until it expires unless revoke is set.
func (s *Service) Renew(ctx context.Context, issuedID int64, revokeOld bool, actor string) (*IssueResult, error) {
	old, err := s.GetIssued(ctx, issuedID)
	if err != nil {
		return nil, err
	}
	if old.ReplacedBy != 0 {
		return nil, errors.New("this certificate was already renewed; renew the newest one")
	}
	r := IssueRequest{Name: old.CertName, CommonName: old.CommonName, Days: old.Days, KeyType: old.KeyType, Usage: old.Usage}
	for _, n := range old.SANs {
		if net.ParseIP(n) != nil {
			r.IPs = append(r.IPs, n)
		} else {
			r.DNSNames = append(r.DNSNames, n)
		}
	}
	if err := s.normalise(&r); err != nil {
		return nil, err
	}
	res, err := s.issue(ctx, old.CAID, r, actor)
	if err != nil {
		return nil, err
	}
	_, _ = s.DB.ExecContext(ctx, `UPDATE ca_issued SET replaced_by = ? WHERE id = ?`, res.Issued.ID, old.ID)
	if revokeOld && old.RevokedAt == "" {
		if _, err := s.Revoke(ctx, old.ID, 4); err != nil {
			res.Notes = append(res.Notes, "The new certificate is ready, but revoking the old one failed: "+err.Error())
		} else {
			res.Notes = append(res.Notes, "The old certificate is revoked (superseded).")
		}
	}
	return res, nil
}

// Revoke marks a certificate revoked and signs a new CRL.
func (s *Service) Revoke(ctx context.Context, issuedID int64, reason int) (*Issued, error) {
	is, err := s.GetIssued(ctx, issuedID)
	if err != nil {
		return nil, err
	}
	if is.RevokedAt != "" {
		return nil, errors.New("already revoked")
	}
	if _, ok := Reasons[reason]; !ok {
		return nil, errors.New("unknown revocation reason")
	}
	// make sure the CRL can be signed before recording anything
	chain, err := s.Chain(ctx, is.CAID)
	if err != nil {
		return nil, err
	}
	if _, err := s.signer(ctx, chain[0]); err != nil {
		return nil, err
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE ca_issued SET revoked_at = ?, revoke_reason = ? WHERE id = ?`,
		s.now().UTC().Format(time.RFC3339), reason, issuedID); err != nil {
		return nil, err
	}
	if _, err := s.RefreshCRL(ctx, is.CAID); err != nil {
		return nil, err
	}
	return s.GetIssued(ctx, issuedID)
}

const issuedCols = `i.id, i.ca_id, c.name, i.serial, i.cert_name, i.common_name, i.sans, i.usage, i.key_type, i.days, i.not_before,
	i.not_after, i.fingerprint, i.issued_by, i.issued_at, i.replaced_by, i.revoked_at, i.revoke_reason,
	COALESCE((SELECT k.id FROM certificates k WHERE k.name = i.cert_name AND k.fingerprint = i.fingerprint), 0)`

func (s *Service) scanIssued(sc interface{ Scan(...any) error }) (*Issued, error) {
	var is Issued
	var sans, nb, na, at string
	if err := sc.Scan(&is.ID, &is.CAID, &is.CAName, &is.Serial, &is.CertName, &is.CommonName, &sans, &is.Usage, &is.KeyType, &is.Days,
		&nb, &na, &is.Fingerprint, &is.IssuedBy, &at, &is.ReplacedBy, &is.RevokedAt, &is.Reason, &is.InventoryID); err != nil {
		return nil, err
	}
	is.SANs = strings.Split(sans, ",")
	is.NotBefore, _ = time.Parse(time.RFC3339, nb)
	is.NotAfter, _ = time.Parse(time.RFC3339, na)
	is.IssuedAt, _ = time.Parse(time.RFC3339, at)
	now := s.now()
	is.DaysLeft = int(is.NotAfter.Sub(now).Hours() / 24)
	switch {
	case is.RevokedAt != "":
		is.Status = "revoked"
	case is.NotAfter.Before(now):
		is.Status, is.DaysLeft = "expired", -1
	case is.ReplacedBy != 0:
		is.Status = "replaced"
	case is.DaysLeft <= pki.WarnDays:
		is.Status = "expiring"
	default:
		is.Status = "active"
	}
	return &is, nil
}

// GetIssued loads one issued certificate.
func (s *Service) GetIssued(ctx context.Context, id int64) (*Issued, error) {
	is, err := s.scanIssued(s.DB.QueryRowContext(ctx, `SELECT `+issuedCols+` FROM ca_issued i JOIN cas c ON c.id = i.ca_id WHERE i.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return is, err
}

// ListIssued returns issued certificates, newest first (caID 0 = every CA).
func (s *Service) ListIssued(ctx context.Context, caID int64) ([]Issued, error) {
	q := `SELECT ` + issuedCols + ` FROM ca_issued i JOIN cas c ON c.id = i.ca_id`
	var args []any
	if caID != 0 {
		q += ` WHERE i.ca_id = ?`
		args = append(args, caID)
	}
	rows, err := s.DB.QueryContext(ctx, q+` ORDER BY i.id DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Issued{}
	for rows.Next() {
		is, err := s.scanIssued(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *is)
	}
	return out, rows.Err()
}

// ---- CRL ----

// RefreshCRL signs a new CRL for a CA and keeps it (needs the vault unsealed).
func (s *Service) RefreshCRL(ctx context.Context, caID int64) ([]byte, error) {
	chain, err := s.Chain(ctx, caID)
	if err != nil {
		return nil, err
	}
	ca := chain[0]
	signer, err := s.signer(ctx, ca)
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT serial, revoked_at, revoke_reason FROM ca_issued WHERE ca_id = ? AND revoked_at != '' ORDER BY id`, caID)
	if err != nil {
		return nil, err
	}
	var entries []x509.RevocationListEntry
	for rows.Next() {
		var serial, at string
		var reason int
		if err := rows.Scan(&serial, &at, &reason); err != nil {
			rows.Close()
			return nil, err
		}
		n, ok := new(big.Int).SetString(serial, 16)
		if !ok {
			continue
		}
		t, _ := time.Parse(time.RFC3339, at)
		entries = append(entries, x509.RevocationListEntry{SerialNumber: n, RevocationTime: t, ReasonCode: reason})
	}
	rows.Close()
	now := s.now()
	num := ca.CRLNumber + 1
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(num),
		ThisUpdate:                now.Add(-5 * time.Minute),
		NextUpdate:                now.Add(crlLife),
		RevokedCertificateEntries: entries,
	}, ca.cert, signer)
	if err != nil {
		return nil, err
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE cas SET crl_der = ?, crl_number = ?, crl_next = ? WHERE id = ?`,
		der, num, now.Add(crlLife).UTC().Format(time.RFC3339), caID); err != nil {
		return nil, err
	}
	return der, nil
}

// CRL returns a CA's current CRL (DER). A CRL past half its life is re-signed when the vault
// is open; otherwise the last one is served as it is.
func (s *Service) CRL(ctx context.Context, caID int64) ([]byte, error) {
	var der []byte
	var next string
	err := s.DB.QueryRowContext(ctx, `SELECT crl_der, crl_next FROM cas WHERE id = ?`, caID).Scan(&der, &next)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t, _ := time.Parse(time.RFC3339, next)
	if len(der) == 0 || s.now().After(t.Add(-crlLife/2)) {
		if fresh, err := s.RefreshCRL(ctx, caID); err == nil {
			return fresh, nil
		} else if len(der) == 0 {
			return nil, err
		}
	}
	return der, nil
}
