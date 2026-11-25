package certdeploy

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // Windows certificate thumbprints are SHA-1 by definition
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/dertown/network-control-centre/internal/pki"
)

// Material is a certificate ready to install: the leaf, its intermediates and its key,
// in the shapes the different servers want.
type Material struct {
	Name    string // certificate name in the inventory
	Leaf    *x509.Certificate
	Chain   []*x509.Certificate // intermediates (and root if it was imported), leaf excluded
	Key     crypto.Signer
	KeyPEM  string
	LeafPEM string
	// ChainPEM is the intermediates only; FullChainPEM is the leaf followed by the intermediates.
	// Neither holds a root: servers should not send one. CABundlePEM is every CA certificate
	// stored with the leaf (intermediates, then the root if there is one).
	ChainPEM     string
	FullChainPEM string
	CABundlePEM  string
	Roots        []*x509.Certificate
	// Trust and TrustPEM are the CA certificates a trust-store deployment installs.
	Trust    []*x509.Certificate
	TrustPEM string
}

// NewTrustMaterial picks the CA certificates to install into a trust store from a stored
// chain: the root(s) in it, or the certificate itself when it is a CA without its root.
func NewTrustMaterial(name, certPEM string) (*Material, error) {
	chain, err := pki.ParseChain(certPEM)
	if err != nil {
		return nil, err
	}
	m := &Material{Name: name, Leaf: chain[0], Chain: chain[1:]}
	for _, c := range chain {
		if c.IsCA && c.Subject.String() == c.Issuer.String() && c.CheckSignatureFrom(c) == nil {
			m.Trust = append(m.Trust, c)
		}
	}
	if len(m.Trust) == 0 && chain[0].IsCA {
		m.Trust = chain[:1]
	}
	if len(m.Trust) == 0 {
		return nil, errors.New(name + " is not a CA certificate and its chain holds no root, so there is nothing to trust. Pick the CA certificate (for NCC's own CA, the one named after the CA).")
	}
	m.Leaf = m.Trust[0]
	m.TrustPEM = encodeCerts(m.Trust)
	m.Roots = m.Trust
	return m, nil
}

// NewMaterial parses a stored chain and key.
func NewMaterial(name, certPEM, keyPEM string) (*Material, error) {
	if strings.TrimSpace(keyPEM) == "" {
		return nil, errors.New("this certificate has no private key in the vault; import it again with its key to deploy it")
	}
	chain, err := pki.ParseChain(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	m := &Material{Name: name, Leaf: chain[0], Chain: chain[1:], Key: key, KeyPEM: strings.TrimSpace(keyPEM) + "\n"}
	var inter []*x509.Certificate
	for _, c := range chain[1:] {
		if c.Subject.String() == c.Issuer.String() && c.CheckSignatureFrom(c) == nil {
			m.Roots = append(m.Roots, c)
		} else {
			inter = append(inter, c)
		}
	}
	m.LeafPEM = encodeCerts(chain[:1])
	m.ChainPEM = encodeCerts(inter)
	m.FullChainPEM = m.LeafPEM + m.ChainPEM
	m.CABundlePEM = encodeCerts(chain[1:])
	return m, nil
}

func encodeCerts(cs []*x509.Certificate) string {
	var b strings.Builder
	for _, c := range cs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return b.String()
}

func parseKey(keyPEM string) (crypto.Signer, error) {
	b, _ := pem.Decode([]byte(keyPEM))
	if b == nil {
		return nil, errors.New("private key is not PEM")
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
		return nil, fmt.Errorf("unsupported key type %q", b.Type)
	}
	if err != nil {
		return nil, err
	}
	s, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported private key")
	}
	return s, nil
}

// CombinedPEM is the leaf, the key and the intermediates in one file (Splunk splunkd, HAProxy).
func (m *Material) CombinedPEM() string { return m.LeafPEM + m.KeyPEM + m.ChainPEM }

// PFX builds a password-protected PKCS#12 file. Triple-DES is used because every
// Windows Server and Java version still in service can read it.
func (m *Material) PFX(password string) ([]byte, error) {
	return pkcs12.LegacyDES.Encode(m.Key, m.Leaf, m.Chain, password)
}

// Thumbprint is the Windows thumbprint (upper-case SHA-1) of a certificate.
func Thumbprint(c *x509.Certificate) string {
	h := sha1.Sum(c.Raw) //nolint:gosec
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

// Fingerprint is the SHA-256 fingerprint used by the certificate inventory.
func Fingerprint(c *x509.Certificate) string {
	return pki.Fingerprint(c)
}

// Covers reports whether the certificate is valid for a host name or IP address.
func (m *Material) Covers(host string) bool {
	if host == "" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, a := range m.Leaf.IPAddresses {
			if a.Equal(ip) {
				return true
			}
		}
		return false
	}
	return m.Leaf.VerifyHostname(host) == nil
}

// RandomPassword makes a password for keystores and PFX files.
func RandomPassword() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	out := make([]byte, 24)
	for i := range out {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		out[i] = alphabet[n.Int64()]
	}
	return string(out)
}
