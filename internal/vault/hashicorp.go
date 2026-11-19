package vault

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// HashiCorp stores secrets in a HashiCorp Vault KV v2 mount.
type HashiCorp struct {
	addr, mount, prefix, namespace string
	roleID, secretID               string
	client                         *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time // zero = static token, never re-login
}

// HashiCorpOptions configures the backend.
type HashiCorpOptions struct {
	Address, Mount, Prefix, Namespace string
	Token                             string
	RoleID, SecretID                  string
	CACertFile                        string
}

// NewHashiCorp builds a HashiCorp Vault backend.
func NewHashiCorp(o HashiCorpOptions) (*HashiCorp, error) {
	if o.Address == "" {
		return nil, errors.New("hashicorp vault: address is required")
	}
	if o.Token == "" && (o.RoleID == "" || o.SecretID == "") {
		return nil, errors.New("hashicorp vault: set a token or AppRole role_id + secret_id")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.CACertFile != "" {
		pem, err := os.ReadFile(o.CACertFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("hashicorp vault: no certificates in ca_cert")
		}
		tlsCfg.RootCAs = pool
	}
	if o.Mount == "" {
		o.Mount = "secret"
	}
	return &HashiCorp{
		addr: strings.TrimRight(o.Address, "/"), mount: strings.Trim(o.Mount, "/"),
		prefix: strings.Trim(o.Prefix, "/"), namespace: o.Namespace,
		token: o.Token, roleID: o.RoleID, secretID: o.SecretID,
		client: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}},
	}, nil
}

// Backend implements Store.
func (h *HashiCorp) Backend() string { return "hashicorp" }

func (h *HashiCorp) full(p string) string {
	if h.prefix == "" {
		return p
	}
	if p == "" {
		return h.prefix
	}
	return h.prefix + "/" + p
}

func (h *HashiCorp) login(ctx context.Context) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.token != "" && (h.tokenExp.IsZero() || time.Now().Before(h.tokenExp)) {
		return h.token, nil
	}
	body, _ := json.Marshal(map[string]string{"role_id": h.roleID, "secret_id": h.secretID})
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := h.do(ctx, http.MethodPost, "/v1/auth/approle/login", "", body, &out); err != nil {
		return "", fmt.Errorf("approle login: %w", err)
	}
	h.token = out.Auth.ClientToken
	ttl := time.Duration(out.Auth.LeaseDuration) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	h.tokenExp = time.Now().Add(ttl * 9 / 10)
	return h.token, nil
}

type statusErr struct{ code int }

func (e statusErr) Error() string { return fmt.Sprintf("vault returned HTTP %d", e.code) }

func (h *HashiCorp) do(ctx context.Context, method, path, token string, body []byte, out any) error {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.addr+path, rd)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if h.namespace != "" {
		req.Header.Set("X-Vault-Namespace", h.namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode >= 300 {
		return statusErr{resp.StatusCode}
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (h *HashiCorp) authed(ctx context.Context, method, path string, body []byte, out any) error {
	tok, err := h.login(ctx)
	if err != nil {
		return err
	}
	return h.do(ctx, method, path, tok, body, out)
}

// Put implements Store.
func (h *HashiCorp) Put(ctx context.Context, path string, s Secret) (int, error) {
	path, err := CleanPath(path)
	if err != nil {
		return 0, err
	}
	body, _ := json.Marshal(map[string]any{"data": s})
	var out struct {
		Data struct {
			Version int `json:"version"`
		} `json:"data"`
	}
	err = h.authed(ctx, http.MethodPost, "/v1/"+h.mount+"/data/"+h.full(path), body, &out)
	return out.Data.Version, err
}

// Get implements Store.
func (h *HashiCorp) Get(ctx context.Context, path string) (Secret, error) {
	path, err := CleanPath(path)
	if err != nil {
		return nil, err
	}
	var out struct {
		Data struct {
			Data Secret `json:"data"`
		} `json:"data"`
	}
	if err := h.authed(ctx, http.MethodGet, "/v1/"+h.mount+"/data/"+h.full(path), nil, &out); err != nil {
		return nil, err
	}
	if out.Data.Data == nil {
		return nil, ErrNotFound // deleted version
	}
	return out.Data.Data, nil
}

// List implements Store, walking folders recursively.
func (h *HashiCorp) List(ctx context.Context, prefix string) ([]string, error) {
	prefix = strings.Trim(prefix, "/")
	var out []string
	var walk func(dir string, depth int) error
	walk = func(dir string, depth int) error {
		if depth > 8 {
			return nil
		}
		var resp struct {
			Data struct {
				Keys []string `json:"keys"`
			} `json:"data"`
		}
		err := h.authed(ctx, "LIST", "/v1/"+h.mount+"/metadata/"+h.full(dir), nil, &resp)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, k := range resp.Data.Keys {
			child := strings.Trim(dir+"/"+k, "/")
			if strings.HasSuffix(k, "/") {
				if err := walk(child, depth+1); err != nil {
					return err
				}
				continue
			}
			out = append(out, child)
		}
		return nil
	}
	if err := walk(prefix, 0); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// Delete implements Store (removes all versions and metadata).
func (h *HashiCorp) Delete(ctx context.Context, path string) error {
	path, err := CleanPath(path)
	if err != nil {
		return err
	}
	return h.authed(ctx, http.MethodDelete, "/v1/"+h.mount+"/metadata/"+h.full(path), nil, nil)
}

// Status implements Store.
func (h *HashiCorp) Status(ctx context.Context) Status {
	st := Status{Backend: "hashicorp", Initialized: true}
	var health struct {
		Sealed bool `json:"sealed"`
	}
	if err := h.do(ctx, http.MethodGet, "/v1/sys/health?standbyok=true", "", nil, &health); err != nil {
		st.Sealed = true
		st.Detail = err.Error()
		return st
	}
	st.Sealed = health.Sealed
	if _, err := h.login(ctx); err != nil {
		st.Detail = err.Error()
	}
	return st
}
