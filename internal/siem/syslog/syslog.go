// Package syslog forwards NCC events over syslog (UDP, TCP or TLS) in CEF, LEEF or JSON. It
// serves the products that collect syslog: IBM QRadar (LEEF), ArcSight and other CEF
// receivers, and any syslog server or log pipeline.
package syslog

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/catalog"
	"github.com/dertown/network-control-centre/internal/netutil"
	"github.com/dertown/network-control-centre/internal/siem"
)

// Options and secrets.
const (
	OptTransport = "transport" // udp | tcp | tls
	OptFormat    = "format"    // cef | leef | json
	OptFraming   = "framing"   // lf (newline) | octet (RFC 6587 octet counting), TCP and TLS only
	OptFacility  = "facility"  // 16..23 (local0..local7)
	OptAPIURL    = "api_url"   // QRadar only: console URL for the connection test
	SecretAPI    = "api_token" // QRadar only: authorised service token (SEC header)
)

func formatField(def string) catalog.Field {
	return catalog.Field{Key: OptFormat, Label: "Format", Type: catalog.Select, Store: catalog.StoreOption, Default: def, Choices: []catalog.Choice{
		{Value: "cef", Label: "CEF (ArcSight Common Event Format)"}, {Value: "leef", Label: "LEEF (QRadar)"}, {Value: "json", Label: "JSON"}}}
}

func transportFields(defTransport string) []catalog.Field {
	stream := map[string]string{OptTransport: "tcp"}
	secure := map[string]string{OptTransport: "tls"}
	return []catalog.Field{
		{Key: OptTransport, Label: "Transport", Type: catalog.Select, Store: catalog.StoreOption, Default: defTransport, Choices: []catalog.Choice{
			{Value: "tls", Label: "TLS (TCP, encrypted)"}, {Value: "tcp", Label: "TCP"}, {Value: "udp", Label: "UDP"}}},
		{Key: OptFraming, Label: "Framing", Type: catalog.Select, Store: catalog.StoreOption, Default: "lf", ShowIf: stream, Choices: []catalog.Choice{
			{Value: "lf", Label: "One event per line"}, {Value: "octet", Label: "Octet counting (RFC 6587)"}}},
		{Key: siem.OptTLS, Label: "Certificate", Type: catalog.Select, Store: catalog.StoreOption, Default: "pin", ShowIf: secure, Choices: []catalog.Choice{
			{Value: "pin", Label: "Pin on first use (self-signed)"}, {Value: "verify", Label: "Verify with trusted CAs"}}},
		{Key: OptFacility, Label: "Facility", Type: catalog.Select, Store: catalog.StoreOption, Default: "20", Choices: []catalog.Choice{
			{Value: "16", Label: "local0"}, {Value: "17", Label: "local1"}, {Value: "18", Label: "local2"}, {Value: "19", Label: "local3"},
			{Value: "20", Label: "local4"}, {Value: "21", Label: "local5"}, {Value: "22", Label: "local6"}, {Value: "23", Label: "local7"},
			{Value: "13", Label: "log audit"}, {Value: "10", Label: "authpriv"}}},
	}
}

func init() {
	siem.Register(Provider{},
		catalog.Vendor{
			ID: "qradar", Label: "IBM QRadar", Order: 40, NoLogin: true,
			Summary: "QRadar SIEM: LEEF events over syslog to the event collector, with an optional API check.",
			Help: "Point NCC at the QRadar console or event collector, port 514. QRadar usually detects a new log source on its own; you can also add one " +
				"(Admin → Log Sources) of type Universal LEEF with the NCC server as identifier. Optionally give the console URL and an authorised service token " +
				"(Admin → Authorized Services) so the connection check also reads the QRadar version.",
			NameDefault: "qradar", AddressKind: catalog.AddressHost, AddressLabel: "Event collector (host:port)", AddressPlaceholder: "qradar.example.com:514",
			Preset: map[string]string{OptFormat: "leef"},
			Fields: append(transportFields("tcp"),
				catalog.Field{Key: OptAPIURL, Label: "Console URL (optional)", Type: catalog.Text, Store: catalog.StoreOption, Placeholder: "https://qradar.example.com",
					Section: "QRadar API", Help: "Only used to check the connection and read the version."},
				catalog.Field{Key: SecretAPI, Label: "Authorized service token (optional)", Type: catalog.Token, Store: catalog.StoreSecret},
			),
		},
		catalog.Vendor{
			ID: "arcsight", Label: "OpenText ArcSight", Order: 60, NoLogin: true,
			Summary: "ArcSight ESM or Logger through a SmartConnector's syslog daemon, in CEF.",
			Help: "Send to an ArcSight SmartConnector of type Syslog Daemon (or a Logger syslog receiver), usually port 514. Events are CEF, so ArcSight parses " +
				"them without a custom parser.",
			NameDefault: "arcsight", AddressKind: catalog.AddressHost, AddressLabel: "SmartConnector (host:port)", AddressPlaceholder: "arcsight-connector.example.com:514",
			Preset: map[string]string{OptFormat: "cef"},
			Fields: transportFields("tcp"),
		},
		catalog.Vendor{
			ID: "syslog", Label: "Syslog / CEF (Other SIEM)", Order: 90, NoLogin: true,
			Summary: "Any syslog receiver: Wazuh, LogRhythm, Sumo Logic, Exabeam, rsyslog, syslog-ng, a Splunk or Sentinel forwarder.",
			Help: "Give the receiver's host and port (514 for UDP and TCP, often 6514 for TLS). CEF suits most SIEMs; JSON suits log pipelines. Lines are " +
				"RFC 5424 syslog with NCC's host name and the app name ncc.",
			NameDefault: "syslog", AddressKind: catalog.AddressHost, AddressLabel: "Receiver (host:port)", AddressPlaceholder: "siem.example.com:514",
			Fields: append([]catalog.Field{formatField("cef")}, transportFields("tls")...),
		},
	)
}

// Provider implements siem.Provider for syslog receivers.
type Provider struct{}

// Kind implements siem.Provider.
func (Provider) Kind() string { return "syslog" }

type dest struct {
	transport, addr, framing, format string
	facility                         int
}

func destOf(t siem.Target) (dest, error) {
	o := t.Options
	d := dest{transport: o[OptTransport], framing: o[OptFraming], format: o[OptFormat]}
	if d.transport == "" {
		d.transport = "tls"
	}
	if d.format == "" {
		d.format = "cef"
	}
	if d.transport == "tls" {
		d.framing = "lf"
	}
	d.facility, _ = strconv.Atoi(o[OptFacility])
	if d.facility <= 0 || d.facility > 23 {
		d.facility = 20
	}
	a := strings.TrimSpace(t.Address)
	for _, pre := range []string{"syslog://", "tcp://", "udp://", "tls://"} {
		a = strings.TrimPrefix(a, pre)
	}
	a = strings.TrimSuffix(a, "/")
	if a == "" {
		return d, errors.New("syslog: give the receiver's host and port")
	}
	if _, _, err := net.SplitHostPort(a); err != nil {
		port := "514"
		if d.transport == "tls" {
			port = "6514"
		}
		a = net.JoinHostPort(strings.Trim(a, "[]"), port)
	}
	d.addr = a
	return d, nil
}

// dial opens the connection and reports a certificate to pin on first use.
func dial(ctx context.Context, t siem.Target, d dest, res *siem.Result) (net.Conn, error) {
	dl := net.Dialer{Timeout: 10 * time.Second}
	switch d.transport {
	case "udp":
		return dl.DialContext(ctx, "udp", d.addr)
	case "tcp":
		return dl.DialContext(ctx, "tcp", d.addr)
	case "tls":
		mode := t.Options[siem.OptTLS]
		if mode == "" {
			mode = "pin"
		}
		pin := t.Options[siem.OptFingerprint]
		cfg, p := netutil.TLSConfig(mode, pin)
		host, _, _ := net.SplitHostPort(d.addr)
		cfg.ServerName = host
		c, err := (&tls.Dialer{NetDialer: &dl, Config: cfg}).DialContext(ctx, "tcp", d.addr)
		if err != nil {
			return nil, err
		}
		if mode == "pin" && netutil.NormFingerprint(pin) == "" && p.Seen() != "" {
			res.OptionUpdates = map[string]string{siem.OptFingerprint: p.Seen()}
		}
		return c, nil
	}
	return nil, fmt.Errorf("syslog: unknown transport %q", d.transport)
}

// Line formats one event for this destination (without framing).
func Line(e siem.Event, format string, facility int) string {
	var msg string
	switch format {
	case "leef":
		msg = siem.LEEF(e)
	case "json":
		b, _ := json.Marshal(siem.Doc(e))
		msg = string(b)
	default:
		msg = siem.CEF(e)
	}
	return siem.Syslog(e, facility, msg)
}

func frame(line, transport, framing string) []byte {
	line = strings.NewReplacer("\r", " ", "\n", " ").Replace(line)
	if transport == "udp" {
		if len(line) > 8000 {
			line = line[:8000]
		}
		return []byte(line)
	}
	if framing == "octet" {
		return []byte(strconv.Itoa(len(line)) + " " + line)
	}
	return []byte(line + "\n")
}

// Test opens the connection (TCP and TLS prove the receiver is listening; UDP can't), and on
// QRadar reads the version from the API when it is configured.
func (Provider) Test(ctx context.Context, t siem.Target, creds map[string]string) (*siem.Result, error) {
	d, err := destOf(t)
	if err != nil {
		return nil, err
	}
	res := &siem.Result{}
	c, err := dial(ctx, t, d, res)
	if err != nil {
		return res, fmt.Errorf("syslog: can't reach %s over %s: %w", d.addr, strings.ToUpper(d.transport), err)
	}
	_ = c.Close()
	info := []string{strings.ToUpper(d.transport) + " " + d.addr + " is listening"}
	if d.transport == "udp" {
		info = []string{"UDP can't confirm delivery; use Send Test Event and look for it in the SIEM"}
	}
	info[0] += " · " + strings.ToUpper(d.format)
	if api := strings.TrimSpace(t.Options[OptAPIURL]); api != "" {
		v, err := qradarVersion(ctx, t, api, creds[SecretAPI], res)
		if err != nil {
			return res, err
		}
		info = append(info, v)
	}
	res.Info = strings.Join(info, " · ")
	return res, nil
}

func qradarVersion(ctx context.Context, t siem.Target, raw, token string, res *siem.Result) (string, error) {
	base, err := siem.BaseURL("QRadar API", raw)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(token) == "" {
		return "", errors.New("qradar: the console URL is set but no authorized service token is saved")
	}
	// the QRadar API is a second HTTPS endpoint: its pin is kept apart from the syslog one
	h := siem.NewHTTP(t, base, "api_tls_fingerprint", 20*time.Second)
	code, body, err := h.Do(ctx, "GET", base+"/api/system/about", nil, map[string]string{"SEC": strings.TrimSpace(token), "Accept": "application/json", "Version": "12.0"})
	h.Pin(res)
	if err != nil {
		return "", fmt.Errorf("qradar API: %w", err)
	}
	if code != 200 {
		return "", siem.StatusErr("QRadar API", code, body)
	}
	var about struct {
		ExternalVersion string `json:"external_version"`
		ReleaseName     string `json:"release_name"`
	}
	_ = json.Unmarshal(body, &about)
	v := about.ExternalVersion
	if v == "" {
		v = about.ReleaseName
	}
	return strings.TrimSpace("QRadar " + v), nil
}

// Send writes the batch over one connection.
func (Provider) Send(ctx context.Context, t siem.Target, creds map[string]string, events []siem.Event) (*siem.Result, error) {
	d, err := destOf(t)
	if err != nil {
		return nil, err
	}
	res := &siem.Result{}
	c, err := dial(ctx, t, d, res)
	if err != nil {
		return res, fmt.Errorf("syslog: can't reach %s: %w", d.addr, err)
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetWriteDeadline(dl)
	} else {
		_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	}
	for i, e := range events {
		if _, err := c.Write(frame(Line(e, d.format, d.facility), d.transport, d.framing)); err != nil {
			return res, &siem.PartialError{Sent: i, Err: fmt.Errorf("syslog: write to %s: %w", d.addr, err)}
		}
	}
	return res, nil
}
