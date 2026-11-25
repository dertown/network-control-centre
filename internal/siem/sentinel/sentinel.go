// Package sentinel forwards NCC events to Microsoft Sentinel through the Azure Monitor Logs
// Ingestion API: a data collection endpoint (DCE) and a data collection rule (DCR) that writes
// a custom table (for example NCCEvents_CL) in the Log Analytics workspace Sentinel uses.
// NCC signs in with a Microsoft Entra ID app registration (client credentials).
package sentinel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dertown/network-control-centre/internal/catalog"
	"github.com/dertown/network-control-centre/internal/siem"
)

// Options and secrets.
const (
	OptTenant    = "tenant_id"
	OptClient    = "client_id"
	OptDCR       = "dcr_id"    // the rule's immutable id, dcr-...
	OptStream    = "stream"    // Custom-NCCEvents_CL
	OptAuthority = "authority" // https://login.microsoftonline.com
	SecretClient = "client_secret"

	apiVersion    = "2023-01-01"
	defaultStream = "Custom-NCCEvents_CL"
	scope         = "https://monitor.azure.com//.default"
)

func init() {
	siem.Register(Provider{}, catalog.Vendor{
		Label: "Microsoft Sentinel", Order: 20,
		Summary: "Sentinel and Log Analytics, through the Azure Monitor Logs Ingestion API.",
		Help: "In the Log Analytics workspace Sentinel uses, create a custom table (DCR-based) such as NCCEvents_CL with the columns TimeGenerated (datetime), " +
			"EventId, Source, Category, Action, Severity, SeverityId (int), Outcome, Actor, Target, SrcIp, Message, Computer and Detail (dynamic). That creates a data " +
			"collection rule; copy its immutable id (dcr-…) and the logs ingestion URL of its data collection endpoint. Register an app in Entra ID with a client secret " +
			"and give it the Monitoring Metrics Publisher role on the rule. The secret is kept in the vault.",
		NameDefault: "sentinel", AddressLabel: "Logs ingestion endpoint (DCE)", AddressPlaceholder: "https://my-dce-ab12.eastus-1.ingest.monitor.azure.com",
		Fields: []catalog.Field{
			{Key: OptTenant, Label: "Tenant (directory) id", Type: catalog.Text, Store: catalog.StoreOption, Required: true, Placeholder: "00000000-0000-0000-0000-000000000000"},
			{Key: OptClient, Label: "Client (application) id", Type: catalog.Text, Store: catalog.StoreOption, Required: true},
			{Key: SecretClient, Label: "Client secret", Type: catalog.Token, Store: catalog.StoreSecret, Required: true},
			{Key: OptDCR, Label: "Data collection rule immutable id", Type: catalog.Text, Store: catalog.StoreOption, Required: true, Placeholder: "dcr-0123456789abcdef0123456789abcdef"},
			{Key: OptStream, Label: "Stream", Type: catalog.Text, Store: catalog.StoreOption, Default: defaultStream},
			{Key: OptAuthority, Label: "Sign-in endpoint", Type: catalog.Text, Store: catalog.StoreOption, Default: "https://login.microsoftonline.com"},
		},
	})
}

// Provider implements siem.Provider for Microsoft Sentinel.
type Provider struct{}

// Kind implements siem.Provider.
func (Provider) Kind() string { return "sentinel" }

const product = "Microsoft Sentinel"

var httpClient = &http.Client{Timeout: 30 * time.Second}

type conn struct {
	dce, authority, tenant, clientID, secret, dcr, stream string
}

func newConn(t siem.Target, creds map[string]string) (*conn, error) {
	dce, err := siem.BaseURL(product, t.Address)
	if err != nil {
		return nil, err
	}
	o := t.Options
	c := &conn{
		dce: dce, authority: strings.TrimRight(strings.TrimSpace(o[OptAuthority]), "/"),
		tenant: strings.TrimSpace(o[OptTenant]), clientID: strings.TrimSpace(o[OptClient]), secret: creds[SecretClient],
		dcr: strings.TrimSpace(o[OptDCR]), stream: strings.TrimSpace(o[OptStream]),
	}
	if c.authority == "" {
		c.authority = "https://login.microsoftonline.com"
	}
	if c.stream == "" {
		c.stream = defaultStream
	}
	switch {
	case c.tenant == "" || c.clientID == "":
		return nil, errors.New("sentinel: the tenant id and client id are required")
	case c.secret == "":
		return nil, errors.New("sentinel: no client secret saved in the vault")
	case c.dcr == "":
		return nil, errors.New("sentinel: the data collection rule id is required")
	}
	return c, nil
}

type cachedToken struct {
	token string
	until time.Time
}

var (
	tokMu  sync.Mutex
	tokens = map[string]cachedToken{}
)

func (c *conn) token(ctx context.Context) (string, error) {
	h := sha256.Sum256([]byte(c.authority + "|" + c.tenant + "|" + c.clientID + "|" + c.secret))
	key := hex.EncodeToString(h[:])
	tokMu.Lock()
	if t, ok := tokens[key]; ok && time.Now().Before(t.until) {
		tokMu.Unlock()
		return t.token, nil
	}
	tokMu.Unlock()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.clientID}, "client_secret": {c.secret}, "scope": {scope}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.authority+"/"+url.PathEscape(c.tenant)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("sentinel: sign in to Entra ID: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &tr)
	if resp.StatusCode != 200 || tr.AccessToken == "" {
		msg := tr.Description
		if msg == "" {
			msg = siem.Snippet(body)
		}
		if i := strings.Index(msg, "\r\n"); i > 0 {
			msg = msg[:i]
		}
		return "", fmt.Errorf("sentinel: Entra ID sign-in failed (%d): %s", resp.StatusCode, msg)
	}
	life := time.Duration(tr.ExpiresIn) * time.Second
	if life <= 0 {
		life = time.Hour
	}
	tokMu.Lock()
	tokens[key] = cachedToken{tr.AccessToken, time.Now().Add(life - 2*time.Minute)}
	tokMu.Unlock()
	return tr.AccessToken, nil
}

func (c *conn) post(ctx context.Context, rows []map[string]any) (int, []byte, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return 0, nil, err
	}
	b, err := json.Marshal(rows)
	if err != nil {
		return 0, nil, err
	}
	u := c.dce + "/dataCollectionRules/" + url.PathEscape(c.dcr) + "/streams/" + url.PathEscape(c.stream) + "?api-version=" + apiVersion
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(b)))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("sentinel: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func explain(code int, body []byte) error {
	switch code {
	case 401, 403:
		return fmt.Errorf("sentinel: the app may not write to this data collection rule (%d); give it the Monitoring Metrics Publisher role on the rule (it can take 30 minutes to apply): %s",
			code, siem.Snippet(body))
	case 404:
		return fmt.Errorf("sentinel: the data collection rule or stream was not found at this endpoint (404); check the rule's immutable id and the stream name: %s", siem.Snippet(body))
	case 413:
		return errors.New("sentinel: the batch is too large (413)")
	}
	return siem.StatusErr(product, code, body)
}

// Test signs in and posts an empty batch. Azure checks the sign-in first (401/403) and the
// rule and stream next (404), and only then the body, so a 2xx or a 400 for the empty batch
// means everything NCC needs is in place, without writing a row.
func (Provider) Test(ctx context.Context, t siem.Target, creds map[string]string) (*siem.Result, error) {
	c, err := newConn(t, creds)
	if err != nil {
		return nil, err
	}
	code, body, err := c.post(ctx, []map[string]any{})
	if err != nil {
		return nil, err
	}
	if code >= 300 && code != 400 {
		return nil, explain(code, body)
	}
	return &siem.Result{Info: "Signed in to Entra ID · rule " + c.dcr + " stream " + c.stream}, nil
}

// Row is one event as a row of the custom table.
func Row(e siem.Event) map[string]any {
	r := map[string]any{
		"TimeGenerated": e.Time.UTC().Format(time.RFC3339Nano), "EventId": e.ExternalID(), "Source": e.Source, "Category": e.Category(),
		"Action": e.Type, "Severity": siem.SeverityWord(e.Severity), "SeverityId": e.Severity, "Outcome": e.Outcome(),
		"Actor": e.Actor, "Target": e.Target, "SrcIp": e.ClientIP(), "Message": e.Message, "Computer": siem.Host,
	}
	det := map[string]any{}
	if v := e.DetailValue(); v != nil {
		det["detail"] = v
	}
	for k, v := range e.Fields {
		det[k] = v
	}
	if len(det) > 0 {
		r["Detail"] = det
	}
	return r
}

// Send posts the batch, split so no request exceeds the API's 1 MB limit.
func (Provider) Send(ctx context.Context, t siem.Target, creds map[string]string, events []siem.Event) (*siem.Result, error) {
	c, err := newConn(t, creds)
	if err != nil {
		return nil, err
	}
	var batch []map[string]any
	size := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		code, body, err := c.post(ctx, batch)
		if err != nil {
			return err
		}
		if code >= 300 {
			return explain(code, body)
		}
		batch, size = nil, 0
		return nil
	}
	for _, e := range events {
		r := Row(e)
		b, _ := json.Marshal(r)
		if size+len(b) > 900_000 {
			if err := flush(); err != nil {
				return nil, err
			}
		}
		batch = append(batch, r)
		size += len(b) + 1
	}
	return &siem.Result{}, flush()
}
