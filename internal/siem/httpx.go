package siem

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/netutil"
)

// OptTLS and OptFingerprint are the certificate settings HTTPS providers share with the rest
// of NCC (catalog.TLSField): pin the self-signed certificate on first use, or verify it.
const (
	OptTLS         = "tls"
	OptFingerprint = "tls_fingerprint"
)

// HTTP is a client for one HTTPS endpoint of a connection, with its certificate checks.
type HTTP struct {
	C       *http.Client
	mode    string
	pin     string
	pinKey  string
	scoped  string // host the pin belongs to, for endpoints other than the address
	pinner  *netutil.Pinner
	Headers map[string]string
}

// NewHTTP builds a client honouring the connection's certificate setting. pinKey is the
// option holding the pin: OptFingerprint for the connection's address, or another key for a
// second endpoint (Splunk's REST API), whose pin is stored with its host so a new URL starts
// over.
func NewHTTP(t Target, endpoint, pinKey string, timeout time.Duration) *HTTP {
	mode := t.Options[OptTLS]
	if mode == "" {
		mode = "pin"
	}
	pin, scoped := t.Options[pinKey], ""
	if pinKey != OptFingerprint {
		scoped = hostOf(endpoint)
		host, fp, _ := strings.Cut(pin, " ")
		if host != scoped {
			fp = ""
		}
		pin = fp
	}
	if !strings.HasPrefix(endpoint, "https://") {
		mode = "verify" // plain HTTP: nothing to pin
	}
	c, p := netutil.NewClient(mode, pin, timeout)
	return &HTTP{C: c, mode: mode, pin: pin, pinKey: pinKey, scoped: scoped, pinner: p, Headers: map[string]string{}}
}

// Pin adds the certificate seen on first use to res, to be saved with the connection.
func (h *HTTP) Pin(res *Result) {
	if h.mode != "pin" || h.pin != "" || h.pinner == nil {
		return
	}
	seen := h.pinner.Seen()
	if seen == "" {
		return
	}
	if res.OptionUpdates == nil {
		res.OptionUpdates = map[string]string{}
	}
	if h.scoped != "" {
		seen = h.scoped + " " + seen
	}
	res.OptionUpdates[h.pinKey] = seen
}

// Do sends a request and returns the status and body (at most 1 MiB).
func (h *HTTP) Do(ctx context.Context, method, u string, body []byte, headers map[string]string) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range h.Headers {
		req.Header.Set(k, v)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "ncc/"+Version)
	}
	resp, err := h.C.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, nil
}

// StatusErr turns an unexpected HTTP status into an error naming the product.
func StatusErr(product string, code int, body []byte) error {
	msg := Snippet(body)
	switch code {
	case 401:
		return fmt.Errorf("%s refused the credentials (401): %s", product, msg)
	case 403:
		return fmt.Errorf("%s says this login may not do that (403): %s", product, msg)
	case 404:
		return fmt.Errorf("%s: not found (404); check the address and names: %s", product, msg)
	}
	return fmt.Errorf("%s answered %d: %s", product, code, msg)
}

// BaseURL trims a configured URL and checks it is http(s).
func BaseURL(product, raw string) (string, error) {
	u := strings.TrimRight(strings.TrimSpace(raw), "/")
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		return "", fmt.Errorf("%s: the address must start with https:// (or http://)", product)
	}
	if _, err := url.Parse(u); err != nil {
		return "", fmt.Errorf("%s: %v", product, err)
	}
	return u, nil
}

func hostOf(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return u
	}
	return p.Host
}
