// Package elastic forwards NCC events to Elastic Security (Elasticsearch, self-managed or
// Elastic Cloud) with the bulk API, as Elastic Common Schema documents in a logs-* data stream
// that Elastic Security's views and detection rules read.
package elastic

import (
	"bytes"
	"context"
	"encoding/base64"
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
	OptIndex     = "index" // data stream or index, default logs-ncc.events-default
	OptAuth      = "auth"  // apikey | basic (form only)
	SecretAPIKey = "api_key"

	defaultIndex = "logs-ncc.events-default"
)

func init() {
	siem.Register(Provider{}, catalog.Vendor{
		Label: "Elastic Security", Order: 30,
		Summary: "Elasticsearch and Elastic Cloud: ECS documents in a logs-* data stream.",
		Help: "In Kibana open Stack Management → API keys and create a key with the privileges create_doc and auto_configure on logs-ncc.* (or the index you " +
			"choose); use the Encoded value. The address is the Elasticsearch endpoint (Elastic Cloud: copy it from the deployment page). Documents follow the " +
			"Elastic Common Schema, so they show up in Elastic Security under the logs-* data view. The key is kept in the vault.",
		NameDefault: "elastic", AddressLabel: "Elasticsearch URL", AddressPlaceholder: "https://elastic.example.com:9200",
		Fields: []catalog.Field{
			{Key: OptAuth, Label: "Sign in with", Type: catalog.Select, Store: catalog.StoreForm, Default: "apikey", Choices: []catalog.Choice{
				{Value: "apikey", Label: "API key"}, {Value: "basic", Label: "Username and password"}}},
			{Key: SecretAPIKey, Label: "API key (encoded)", Type: catalog.Token, Store: catalog.StoreSecret, Required: true, ShowIf: map[string]string{OptAuth: "apikey"}},
			catalog.UserPassword("ncc_writer", map[string]string{OptAuth: "basic"})[0],
			catalog.UserPassword("ncc_writer", map[string]string{OptAuth: "basic"})[1],
			{Key: OptIndex, Label: "Data stream or index", Type: catalog.Text, Store: catalog.StoreOption, Default: defaultIndex},
			catalog.TLSField(""),
		},
	})
}

// Provider implements siem.Provider for Elastic.
type Provider struct{}

// Kind implements siem.Provider.
func (Provider) Kind() string { return "elastic" }

const product = "Elasticsearch"

func auth(creds map[string]string) (string, error) {
	if k := strings.TrimSpace(creds[SecretAPIKey]); k != "" {
		return "ApiKey " + k, nil
	}
	if creds["username"] != "" {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds["username"]+":"+creds["password"])), nil
	}
	return "", errors.New("elastic: no API key or password saved in the vault")
}

func client(t siem.Target, creds map[string]string, timeout time.Duration) (string, *siem.HTTP, error) {
	base, err := siem.BaseURL(product, t.Address)
	if err != nil {
		return "", nil, err
	}
	a, err := auth(creds)
	if err != nil {
		return "", nil, err
	}
	h := siem.NewHTTP(t, base, siem.OptFingerprint, timeout)
	h.Headers["Authorization"] = a
	return base, h, nil
}

// Test reads the cluster's name and version.
func (Provider) Test(ctx context.Context, t siem.Target, creds map[string]string) (*siem.Result, error) {
	base, h, err := client(t, creds, 20*time.Second)
	if err != nil {
		return nil, err
	}
	res := &siem.Result{}
	code, body, err := h.Do(ctx, "GET", base+"/", nil, nil)
	h.Pin(res)
	if err != nil {
		return res, fmt.Errorf("elastic: %w", err)
	}
	if code == 403 {
		// API keys limited to writing can't read the root endpoint; that is all NCC needs.
		res.Info = "Signed in (the key can't read cluster info, which is fine for writing)"
		return res, nil
	}
	if code != 200 {
		return res, siem.StatusErr(product, code, body)
	}
	var info struct {
		Cluster string `json:"cluster_name"`
		Version struct {
			Number string `json:"number"`
		} `json:"version"`
	}
	_ = json.Unmarshal(body, &info)
	res.Info = strings.TrimSpace(fmt.Sprintf("Elasticsearch %s · cluster %s", info.Version.Number, info.Cluster))
	return res, nil
}

// Send writes the batch with one bulk request. Data streams only take "create".
func (Provider) Send(ctx context.Context, t siem.Target, creds map[string]string, events []siem.Event) (*siem.Result, error) {
	base, h, err := client(t, creds, 30*time.Second)
	if err != nil {
		return nil, err
	}
	idx := strings.TrimSpace(t.Options[OptIndex])
	if idx == "" {
		idx = defaultIndex
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range events {
		// a stable _id makes a resent batch harmless: events already stored answer 409
		id := fmt.Sprintf("%s-%s-%d", siem.Host, e.ExternalID(), e.Time.UnixNano())
		_ = enc.Encode(map[string]any{"create": map[string]any{"_index": idx, "_id": id}})
		if err := enc.Encode(siem.ECS(e)); err != nil {
			return nil, err
		}
	}
	res := &siem.Result{}
	code, body, err := h.Do(ctx, "POST", base+"/_bulk", buf.Bytes(), map[string]string{"Content-Type": "application/x-ndjson"})
	h.Pin(res)
	if err != nil {
		return res, fmt.Errorf("elastic: %w", err)
	}
	if code != 200 {
		return res, siem.StatusErr(product, code, body)
	}
	var br struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Status int `json:"status"`
			Error  struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &br); err != nil {
		return res, fmt.Errorf("elastic: unreadable bulk reply: %s", siem.Snippet(body))
	}
	if br.Errors {
		failed, first := 0, ""
		for _, it := range br.Items {
			for _, r := range it {
				if r.Status >= 300 && r.Status != 409 { // 409: already there
					failed++
					if first == "" {
						first = r.Error.Type + ": " + r.Error.Reason
					}
				}
			}
		}
		if failed > 0 {
			return res, fmt.Errorf("elastic refused %d of %d events: %s", failed, len(events), first)
		}
	}
	return res, nil
}
