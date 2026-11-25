// Package graylog forwards NCC events to Graylog (and Graylog Security) through a GELF HTTP
// input, and optionally reads the Graylog API to show its version.
package graylog

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/catalog"
	"github.com/dertown/network-control-centre/internal/siem"
)

// Options and secrets.
const (
	OptAPIURL = "api_url"   // optional, e.g. https://graylog.example.com:9000
	SecretAPI = "api_token" // a Graylog access token
)

func init() {
	siem.Register(Provider{}, catalog.Vendor{
		Label: "Graylog", Order: 50, NoLogin: true,
		Summary: "Graylog and Graylog Security, through a GELF HTTP input.",
		Help: "In Graylog open System → Inputs, launch a GELF HTTP input (port 12201 is usual; turn on TLS if you can) and give its URL here; NCC posts to /gelf. " +
			"Optionally add the API URL and an access token (your profile → Edit tokens) so the connection check shows the Graylog version. The token is kept in the vault.",
		NameDefault: "graylog", AddressLabel: "GELF HTTP input URL", AddressPlaceholder: "https://graylog.example.com:12201",
		Fields: []catalog.Field{
			catalog.TLSField(""),
			{Key: OptAPIURL, Label: "API URL (optional)", Type: catalog.Text, Store: catalog.StoreOption, Placeholder: "https://graylog.example.com:9000",
				Section: "Graylog API", Help: "Only used to check the connection and read the version."},
			{Key: SecretAPI, Label: "Access token (optional)", Type: catalog.Token, Store: catalog.StoreSecret},
		},
	})
}

// Provider implements siem.Provider for Graylog.
type Provider struct{}

// Kind implements siem.Provider.
func (Provider) Kind() string { return "graylog" }

func gelfURL(addr string) (string, error) {
	base, err := siem.BaseURL("Graylog", addr)
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(base, "/gelf") {
		base += "/gelf"
	}
	return base, nil
}

// Test checks the input answers HTTP (a GELF input answers anything but a POST with an error
// status, which still proves it is there) and reads the API when configured.
func (Provider) Test(ctx context.Context, t siem.Target, creds map[string]string) (*siem.Result, error) {
	u, err := gelfURL(t.Address)
	if err != nil {
		return nil, err
	}
	res := &siem.Result{}
	h := siem.NewHTTP(t, u, siem.OptFingerprint, 15*time.Second)
	if _, _, err := h.Do(ctx, "GET", u, nil, nil); err != nil {
		h.Pin(res)
		return res, fmt.Errorf("graylog: can't reach the GELF input: %w", err)
	}
	h.Pin(res)
	info := []string{"GELF HTTP input reachable"}
	if api := strings.TrimSpace(t.Options[OptAPIURL]); api != "" {
		base, err := siem.BaseURL("Graylog API", api)
		if err != nil {
			return res, err
		}
		tok := strings.TrimSpace(creds[SecretAPI])
		if tok == "" {
			return res, fmt.Errorf("graylog: the API URL is set but no access token is saved")
		}
		a := siem.NewHTTP(t, base, "api_tls_fingerprint", 15*time.Second)
		code, body, err := a.Do(ctx, "GET", base+"/api/system", nil, map[string]string{
			"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(tok+":token")), "Accept": "application/json", "X-Requested-By": "ncc"})
		a.Pin(res)
		if err != nil {
			return res, fmt.Errorf("graylog API: %w", err)
		}
		if code != 200 {
			return res, siem.StatusErr("Graylog API", code, body)
		}
		var sys struct {
			Version string `json:"version"`
		}
		_ = json.Unmarshal(body, &sys)
		info = append(info, "Graylog "+sys.Version)
	}
	res.Info = strings.Join(info, " · ")
	return res, nil
}

// Send posts each event (a GELF HTTP input takes one message per request).
func (Provider) Send(ctx context.Context, t siem.Target, creds map[string]string, events []siem.Event) (*siem.Result, error) {
	u, err := gelfURL(t.Address)
	if err != nil {
		return nil, err
	}
	res := &siem.Result{}
	h := siem.NewHTTP(t, u, siem.OptFingerprint, 15*time.Second)
	defer h.Pin(res)
	for i, e := range events {
		b, err := json.Marshal(siem.GELF(e))
		if err != nil {
			return res, err
		}
		code, body, err := h.Do(ctx, "POST", u, b, map[string]string{"Content-Type": "application/json"})
		if err != nil {
			return res, &siem.PartialError{Sent: i, Err: fmt.Errorf("graylog: %w", err)}
		}
		if code >= 300 {
			return res, &siem.PartialError{Sent: i, Err: siem.StatusErr("Graylog GELF input", code, body)}
		}
	}
	return res, nil
}
