// Package recursorfix gets NCC reading the PowerDNS Recursor's API, which the router DNS
// check needs to see where the Recursor forwards internet queries.
//
// It works in two steps, each shown to a person before anything changes:
//
//  1. Discover looks for the API on the usual ports of the DNS server's addresses. Often the
//     API is on and only the URL saved in NCC is wrong; then saving the found URL is the fix.
//  2. When nothing answers, Inspect logs in over SSH, reads how the Recursor is installed and
//     configured, and returns a Plan: the exact file changes and commands that turn the web
//     server and API on (webserver, webserver-address, webserver-port, webserver-allow-from,
//     api-key), open the port in ufw when it is on, and restart the Recursor. Apply carries
//     the plan out, puts the old file back if the Recursor doesn't come back up, and checks
//     the API answers before NCC saves its URL and key.
package recursorfix

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---- step 1: find the API ----

// Probe is what one address and port answered.
type Probe struct {
	URL string `json:"url"`
	// Status is the HTTP status of the API call; 0 when nothing answered.
	Status     int    `json:"status,omitempty"`
	DaemonType string `json:"daemon_type,omitempty"` // "recursor" or "authoritative"
	Version    string `json:"version,omitempty"`
	// Recursor is set when this is a PowerDNS Recursor (from the API, or its web page).
	Recursor bool `json:"recursor"`
	// KeyOK is set when one of the keys NCC has was accepted.
	KeyOK bool   `json:"key_ok"`
	Error string `json:"error,omitempty"`
	key   string
}

// Key is the API key that worked for this probe, if any.
func (p Probe) Key() string { return p.key }

// Endpoint is a scheme and port the Recursor's web server is commonly on.
type Endpoint struct {
	Scheme string
	Port   int
}

// Endpoints are tried in this order: the Recursor's default port first, then ports people
// move it to, then the authoritative server's default (to tell the two apart).
var Endpoints = []Endpoint{{"http", 8082}, {"http", 8083}, {"http", 8084}, {"http", 8081}, {"http", 8080}, {"http", 80}, {"https", 443}, {"https", 8443}}

// Discovery is the result of looking for the API.
type Discovery struct {
	Hosts  []string `json:"hosts"`
	Probes []Probe  `json:"probes"`
	// Found is the Recursor API to use: one that accepted a key if there is one, otherwise a
	// Recursor that needs its key. Nil when no Recursor answered.
	Found *Probe `json:"found,omitempty"`
}

// Discover probes every host on every endpoint, trying keys (in order) on the API.
func Discover(ctx context.Context, hosts []string, keys []string, client *http.Client) Discovery {
	if client == nil {
		client = &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // only looking for which port answers
			Proxy:           nil,
		}}
	}
	d := Discovery{Hosts: hosts, Probes: []Probe{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range hosts {
		for _, e := range Endpoints {
			base := e.Scheme + "://" + net.JoinHostPort(h, strconv.Itoa(e.Port))
			if (e.Scheme == "http" && e.Port == 80) || (e.Scheme == "https" && e.Port == 443) {
				base = e.Scheme + "://" + hostForURL(h)
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				p := probe(ctx, client, base, keys)
				mu.Lock()
				d.Probes = append(d.Probes, p)
				mu.Unlock()
			}()
		}
	}
	wg.Wait()
	order := map[string]int{}
	for i, h := range hosts {
		for j, e := range Endpoints {
			b := e.Scheme + "://" + net.JoinHostPort(h, strconv.Itoa(e.Port))
			if (e.Scheme == "http" && e.Port == 80) || (e.Scheme == "https" && e.Port == 443) {
				b = e.Scheme + "://" + hostForURL(h)
			}
			order[b] = i*100 + j
		}
	}
	sort.Slice(d.Probes, func(i, j int) bool { return order[d.Probes[i].URL] < order[d.Probes[j].URL] })
	for i := range d.Probes {
		p := &d.Probes[i]
		if !p.Recursor {
			continue
		}
		if d.Found == nil || (p.KeyOK && !d.Found.KeyOK) {
			d.Found = p
		}
	}
	return d
}

func hostForURL(h string) string {
	if strings.Contains(h, ":") {
		return "[" + h + "]"
	}
	return h
}

func probe(ctx context.Context, c *http.Client, base string, keys []string) Probe {
	p := Probe{URL: base}
	try := func(key string) (int, []byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/servers/localhost", nil)
		if err != nil {
			return 0, nil, err
		}
		if key != "" {
			req.Header.Set("X-API-Key", key)
		}
		req.Header.Set("Accept", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return resp.StatusCode, b, nil
	}
	tried := false
	for _, k := range keys {
		if k == "" {
			continue
		}
		tried = true
		code, body, err := try(k)
		if err != nil {
			p.Error = shortErr(err)
			return p
		}
		p.Status = code
		if code == http.StatusOK {
			var info struct {
				DaemonType string `json:"daemon_type"`
				Version    string `json:"version"`
			}
			if json.Unmarshal(body, &info) == nil && info.DaemonType != "" {
				p.DaemonType, p.Version = info.DaemonType, info.Version
				p.Recursor = info.DaemonType == "recursor"
				p.KeyOK, p.key = true, k
				return p
			}
		}
		if code != http.StatusUnauthorized && code != http.StatusForbidden {
			break
		}
	}
	if !tried {
		code, _, err := try("")
		if err != nil {
			p.Error = shortErr(err)
			return p
		}
		p.Status = code
	}
	if p.Status == http.StatusUnauthorized || p.Status == http.StatusForbidden {
		// a PowerDNS web server that wants a key: the Recursor's start page says what it is
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
		if err == nil {
			if resp, err := c.Do(req); err == nil {
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
				resp.Body.Close()
				l := strings.ToLower(string(b))
				switch {
				case strings.Contains(l, "recursor"):
					p.Recursor, p.DaemonType = true, "recursor"
				case strings.Contains(l, "authoritative"):
					p.DaemonType = "authoritative"
				}
			}
		}
	}
	return p
}

func shortErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "connection refused"):
		return "connection refused"
	case strings.Contains(s, "Client.Timeout"), strings.Contains(s, "deadline exceeded"), strings.Contains(s, "i/o timeout"):
		return "no answer (timeout)"
	case strings.Contains(s, "no route to host"):
		return "no route to host"
	}
	if i := strings.LastIndex(s, ": "); i >= 0 && i+2 < len(s) {
		return s[i+2:]
	}
	return s
}

// CheckAPI returns nil when url answers as a PowerDNS Recursor and accepts key.
func CheckAPI(ctx context.Context, url, key string, client *http.Client) error {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	p := probe(ctx, client, strings.TrimRight(url, "/"), []string{key})
	switch {
	case p.Error != "":
		return errors.New(p.Error)
	case p.Status == http.StatusUnauthorized || p.Status == http.StatusForbidden:
		return fmt.Errorf("the API key was refused (HTTP %d)", p.Status)
	case !p.KeyOK:
		return fmt.Errorf("unexpected answer (HTTP %d)", p.Status)
	case !p.Recursor:
		return fmt.Errorf("this is the PowerDNS %s server, not the Recursor", p.DaemonType)
	}
	return nil
}
