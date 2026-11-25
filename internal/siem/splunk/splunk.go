// Package splunk forwards NCC events to Splunk Enterprise Security (and plain Splunk
// Enterprise or Splunk Cloud) through the HTTP Event Collector, and reads the Splunk REST API
// to confirm the version and that the Enterprise Security app is installed.
//
// Events arrive as sourcetype ncc:audit or ncc:network (or the sourcetype set on the form)
// with CIM-style fields (action, user, src, dest, severity, signature, vendor_product), so
// they can be mapped to the Authentication and Change data models that Enterprise Security's
// correlation searches read.
package splunk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/catalog"
	"github.com/dertown/network-control-centre/internal/siem"
)

// Options and secrets.
const (
	OptIndex          = "index"                // optional; HEC token's default index otherwise
	OptSourcetype     = "sourcetype"           // optional; ncc:<source> otherwise
	OptRestURL        = "rest_url"             // optional management API, e.g. https://splunk:8089
	OptRestPin        = "rest_tls_fingerprint" // pinned certificate of the REST API ("host fp")
	SecretHEC         = "hec_token"
	SecretRestToken   = "rest_token" // a Splunk authentication token (Bearer)
	esApp             = "SplunkEnterpriseSecuritySuite"
	defaultSourceType = "ncc:"
)

func init() {
	siem.Register(Provider{}, catalog.Vendor{
		Label: "Splunk Enterprise Security", Order: 10,
		Summary: "Splunk ES, Splunk Enterprise or Splunk Cloud, through the HTTP Event Collector and the REST API.",
		Help: "In Splunk open Settings → Data inputs → HTTP Event Collector, turn on Global Settings and add a token (a dedicated index such as " +
			"ncc helps; give the token that index). The address is the collector, normally port 8088 (Splunk Cloud: https://http-inputs-<stack>.splunkcloud.com). " +
			"Optionally add the REST API (port 8089) and a Splunk authentication token (Settings → Tokens) with a role that can read apps, so NCC can show the " +
			"Splunk version and confirm Enterprise Security is installed. Tokens are kept in the vault.",
		NameDefault: "splunk", AddressLabel: "HTTP Event Collector URL", AddressPlaceholder: "https://splunk.example.com:8088",
		Fields: []catalog.Field{
			{Key: SecretHEC, Label: "HEC token", Type: catalog.Token, Store: catalog.StoreSecret, Required: true, Placeholder: "00000000-0000-0000-0000-000000000000"},
			{Key: OptIndex, Label: "Index (optional)", Type: catalog.Text, Store: catalog.StoreOption, Placeholder: "token's default"},
			{Key: OptSourcetype, Label: "Sourcetype (optional)", Type: catalog.Text, Store: catalog.StoreOption, Placeholder: "ncc:audit / ncc:network"},
			catalog.TLSField(""),
			{Key: OptRestURL, Label: "REST API URL (optional)", Type: catalog.Text, Store: catalog.StoreOption, Placeholder: "https://splunk.example.com:8089",
				Section: "Splunk REST API", Help: "Lets NCC report the Splunk version and whether Enterprise Security is installed. Leave empty to skip."},
			{Key: SecretRestToken, Label: "REST API token (optional)", Type: catalog.Token, Store: catalog.StoreSecret},
		},
	})
}

// Provider implements siem.Provider for Splunk.
type Provider struct{}

// Kind implements siem.Provider.
func (Provider) Kind() string { return "splunk" }

const product = "Splunk"

type hecReply struct {
	Text string `json:"text"`
	Code int    `json:"code"`
}

// Test checks the collector accepts the token (an empty post: Splunk answers "No data" for a
// good token and 401/403 for a bad one), then reads the REST API when it is configured.
func (p Provider) Test(ctx context.Context, t siem.Target, creds map[string]string) (*siem.Result, error) {
	base, err := siem.BaseURL(product, t.Address)
	if err != nil {
		return nil, err
	}
	tok := strings.TrimSpace(creds[SecretHEC])
	if tok == "" {
		return nil, errors.New("splunk: no HEC token saved in the vault")
	}
	res := &siem.Result{}
	h := siem.NewHTTP(t, base, siem.OptFingerprint, 20*time.Second)
	code, body, err := h.Do(ctx, "POST", base+"/services/collector/event", []byte{}, map[string]string{"Authorization": "Splunk " + tok})
	h.Pin(res)
	if err != nil {
		return res, fmt.Errorf("splunk: HTTP Event Collector: %w", err)
	}
	var r hecReply
	_ = json.Unmarshal(body, &r)
	switch {
	case code == 400 && (r.Code == 5 || r.Code == 6): // "No data" / "Invalid data format": the token was accepted
	case code < 300:
	case r.Code == 1 || r.Code == 2 || r.Code == 3 || r.Code == 4:
		return res, fmt.Errorf("splunk: the HEC token was refused: %s", r.Text)
	case r.Code == 9:
		return res, errors.New("splunk: the HTTP Event Collector is busy (server busy)")
	default:
		return res, siem.StatusErr("Splunk HTTP Event Collector", code, body)
	}
	info := []string{"HTTP Event Collector accepts the token"}
	if rest := strings.TrimSpace(t.Options[OptRestURL]); rest != "" {
		more, err := p.restInfo(ctx, t, rest, creds[SecretRestToken], res)
		if err != nil {
			return res, err
		}
		info = append(info, more...)
	}
	res.Info = strings.Join(info, " · ")
	return res, nil
}

// restInfo reads the version and looks for the Enterprise Security app.
func (Provider) restInfo(ctx context.Context, t siem.Target, raw, token string, res *siem.Result) ([]string, error) {
	base, err := siem.BaseURL("Splunk REST API", raw)
	if err != nil {
		return nil, err
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("splunk: the REST API URL is set but no REST API token is saved")
	}
	h := siem.NewHTTP(t, base, OptRestPin, 20*time.Second)
	h.Headers["Authorization"] = "Bearer " + token
	code, body, err := h.Do(ctx, "GET", base+"/services/server/info?output_mode=json", nil, nil)
	h.Pin(res)
	if err != nil {
		return nil, fmt.Errorf("splunk REST API: %w", err)
	}
	if code != 200 {
		return nil, siem.StatusErr("Splunk REST API", code, body)
	}
	var si struct {
		Entry []struct {
			Content struct {
				Version    string `json:"version"`
				ServerName string `json:"serverName"`
				Product    string `json:"product_type"`
			} `json:"content"`
		} `json:"entry"`
	}
	_ = json.Unmarshal(body, &si)
	var out []string
	if len(si.Entry) > 0 && si.Entry[0].Content.Version != "" {
		out = append(out, "Splunk "+si.Entry[0].Content.Version)
	}
	code, body, err = h.Do(ctx, "GET", base+"/services/apps/local/"+esApp+"?output_mode=json", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("splunk REST API: %w", err)
	}
	switch code {
	case 200:
		var app struct {
			Entry []struct {
				Content struct {
					Version  string `json:"version"`
					Disabled bool   `json:"disabled"`
				} `json:"content"`
			} `json:"entry"`
		}
		_ = json.Unmarshal(body, &app)
		s := "Enterprise Security installed"
		if len(app.Entry) > 0 {
			if v := app.Entry[0].Content.Version; v != "" {
				s = "Enterprise Security " + v + " installed"
			}
			if app.Entry[0].Content.Disabled {
				s += " (disabled)"
			}
		}
		out = append(out, s)
	case 404:
		out = append(out, "Enterprise Security not installed")
	case 403:
		out = append(out, "can't tell whether Enterprise Security is installed (the token may not list apps)")
	default:
		return nil, siem.StatusErr("Splunk REST API", code, body)
	}
	return out, nil
}

// Send posts the batch to the collector as one request of concatenated events.
func (Provider) Send(ctx context.Context, t siem.Target, creds map[string]string, events []siem.Event) (*siem.Result, error) {
	base, err := siem.BaseURL(product, t.Address)
	if err != nil {
		return nil, err
	}
	tok := strings.TrimSpace(creds[SecretHEC])
	if tok == "" {
		return nil, errors.New("splunk: no HEC token saved in the vault")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range events {
		st := strings.TrimSpace(t.Options[OptSourcetype])
		if st == "" {
			st = defaultSourceType + e.Source
		}
		ev := map[string]any{
			"time": float64(e.Time.UnixMilli()) / 1000, "host": siem.Host, "source": "ncc", "sourcetype": st, "event": siem.Doc(e),
		}
		if idx := strings.TrimSpace(t.Options[OptIndex]); idx != "" {
			ev["index"] = idx
		}
		if err := enc.Encode(ev); err != nil {
			return nil, err
		}
	}
	res := &siem.Result{}
	h := siem.NewHTTP(t, base, siem.OptFingerprint, 30*time.Second)
	code, body, err := h.Do(ctx, "POST", base+"/services/collector/event", buf.Bytes(),
		map[string]string{"Authorization": "Splunk " + tok, "Content-Type": "application/json"})
	h.Pin(res)
	if err != nil {
		return res, fmt.Errorf("splunk: %w", err)
	}
	var r hecReply
	_ = json.Unmarshal(body, &r)
	if code != 200 || r.Code != 0 {
		if r.Text != "" {
			return res, fmt.Errorf("splunk refused the events (%d, code %d): %s", code, r.Code, r.Text)
		}
		return res, siem.StatusErr("Splunk HTTP Event Collector", code, body)
	}
	return res, nil
}
