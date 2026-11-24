// Package winps runs PowerShell on Windows servers over WinRM for the providers that read
// Windows services (Active Directory DNS, Hyper-V). It reuses the WinRM client of certificate
// deployment and gives those providers the same connection settings and catalog fields.
package winps

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/catalog"
	"github.com/dertown/network-control-centre/internal/certdeploy"
	"github.com/dertown/network-control-centre/internal/netutil"
)

// Options and secrets shared by WinRM connections.
const (
	OptPort        = "winrm_port"      // default 5986
	OptAuth        = "winrm_auth"      // ntlm (default) or basic
	OptTLS         = "tls"             // verify (default) or pin
	OptFingerprint = "tls_fingerprint" // SHA-256 of the WinRM listener's certificate, for pin
)

// Shell runs PowerShell scripts on one server.
type Shell interface {
	Run(ctx context.Context, script string) (string, error)
	Close() error
}

// Dial opens a shell; tests replace it.
var Dial = func(ctx context.Context, address string, options, creds map[string]string) (Shell, error) {
	host, port := strings.TrimSpace(address), 5986
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	if p, err := strconv.Atoi(options[OptPort]); err == nil && p > 0 {
		port = p
	}
	pin := netutil.NormFingerprint(options[OptFingerprint])
	pinMode := options[OptTLS] == "pin"
	if pinMode && pin == "" {
		// learn the fingerprint to show it; the connection is refused until it is pasted in
		_, seen, err := certdeploy.DialWinRM(ctx, certdeploy.WinRMOptions{Host: host, Port: port, HTTPS: true, Auth: options[OptAuth],
			User: creds["username"], Password: creds["password"], Timeout: 60 * time.Second})
		var pe *certdeploy.ErrTLSPinUnknown
		if errors.As(err, &pe) || seen != "" {
			return nil, fmt.Errorf("the WinRM certificate isn't pinned yet: check that the server's certificate has SHA-256 %s, then paste it into Certificate fingerprint (Settings → Edit)", seen)
		}
		return nil, err
	}
	if !pinMode {
		pin = ""
	}
	sh, _, err := certdeploy.DialWinRM(ctx, certdeploy.WinRMOptions{Host: host, Port: port, HTTPS: true, Auth: options[OptAuth],
		User: creds["username"], Password: creds["password"], TLSPin: pin, Verify: !pinMode, Timeout: 60 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("WinRM %s:%d: %w", host, port, err)
	}
	return sh, nil
}

// Quote quotes a string for PowerShell (single quotes, doubled inside).
func Quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// Fields are the catalog fields of a WinRM connection: the Windows login, the listener's
// port, authentication and certificate check.
func Fields(userPlaceholder string) []catalog.Field {
	return []catalog.Field{
		{Key: "username", Label: "Username", Type: catalog.Text, Store: catalog.StoreSecret, Required: true, Placeholder: userPlaceholder},
		{Key: "password", Label: "Password", Type: catalog.Password, Store: catalog.StoreSecret, Required: true},
		{Key: OptPort, Label: "WinRM HTTPS port", Type: catalog.Text, Store: catalog.StoreOption, Default: "5986"},
		{Key: OptAuth, Label: "Authentication", Type: catalog.Select, Store: catalog.StoreOption, Default: "ntlm", Choices: []catalog.Choice{
			{Value: "ntlm", Label: "Negotiate / NTLM (domain accounts)"}, {Value: "basic", Label: "Basic (local accounts)"}}},
		{Key: OptTLS, Label: "Certificate", Type: catalog.Select, Store: catalog.StoreOption, Default: "verify", Choices: []catalog.Choice{
			{Value: "verify", Label: "Verify with trusted CAs (AD CS)"}, {Value: "pin", Label: "Pin a self-signed certificate"}}},
		{Key: OptFingerprint, Label: "Certificate fingerprint (SHA-256)", Type: catalog.Text, Store: catalog.StoreOption,
			ShowIf: map[string]string{OptTLS: "pin"}, Placeholder: "shown by the first check"},
	}
}

// Help is the WinRM setup paragraph the providers share.
const Help = "NCC connects over WinRM on HTTPS (port 5986). On the server run Enable-PSRemoting, then add an HTTPS listener: " +
	"New-Item WSMan:\\localhost\\Listener -Transport HTTPS -Address * -CertificateThumbPrint <thumbprint> " +
	"(a certificate from your AD CS is verified as is; for a self-signed one pick Pin and paste the SHA-256 fingerprint the first check shows)."
