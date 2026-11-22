package assistant

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/vault"
)

// Settings is how one provider is set up in NCC. Its sign-in lives in the vault at SecretPath.
type Settings struct {
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
	Model   string `json:"model"`
	// Binary overrides where the tool is (default: Kind.Binary on the PATH).
	Binary string `json:"binary"`
	// Address is the model server for HTTP providers (Ollama), e.g. http://localhost:11434.
	Address     string     `json:"address"`
	ConnectedAt *time.Time `json:"connected_at,omitempty"`
	LastUsed    *time.Time `json:"last_used,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
}

// SecretPath is where a provider's sign-in is kept in the vault.
func SecretPath(kind string) string { return "ai/" + kind }

// Service runs prompts through the configured providers.
type Service struct {
	DB    *sql.DB
	Vault vault.Store
	// TempDir is where private homes for the tools are made (default: the system temp dir).
	TempDir string
	// Timeout bounds one prompt (default 4 minutes).
	Timeout time.Duration
	// HTTP is used for Ollama (default http.DefaultClient with the timeout).
	HTTP *http.Client
}

// Migrate creates the assistant's tables. It is safe to call more than once.
func Migrate(db *sql.DB) error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS ai_providers (
			kind TEXT PRIMARY KEY,
			data TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ai_plans (
			id TEXT PRIMARY KEY,
			created_at TIMESTAMP NOT NULL,
			status TEXT NOT NULL,
			data TEXT NOT NULL
		)`,
	} {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// Settings returns every provider's settings, defaults for ones never set up.
func (s *Service) Settings(ctx context.Context) ([]Settings, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT kind, data FROM ai_providers`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	saved := map[string]Settings{}
	for rows.Next() {
		var k, d string
		if err := rows.Scan(&k, &d); err != nil {
			return nil, err
		}
		var st Settings
		if json.Unmarshal([]byte(d), &st) == nil {
			saved[k] = st
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Settings, 0, len(Kinds))
	for _, k := range Kinds {
		st, ok := saved[k.ID]
		if !ok {
			st = Settings{Kind: k.ID}
			if k.HTTP {
				st.Address = "http://localhost:11434"
			}
		}
		st.Kind = k.ID
		out = append(out, st)
	}
	return out, nil
}

// Get returns one provider's settings.
func (s *Service) Get(ctx context.Context, kind string) (Settings, error) {
	all, err := s.Settings(ctx)
	if err != nil {
		return Settings{}, err
	}
	for _, st := range all {
		if st.Kind == kind {
			return st, nil
		}
	}
	return Settings{}, fmt.Errorf("no AI provider %q", kind)
}

// Save stores one provider's settings.
func (s *Service) Save(ctx context.Context, st Settings) error {
	if _, err := KindByID(st.Kind); err != nil {
		return err
	}
	b, _ := json.Marshal(st)
	_, err := s.DB.ExecContext(ctx, `INSERT INTO ai_providers(kind, data) VALUES(?, ?)
		ON CONFLICT(kind) DO UPDATE SET data = excluded.data`, st.Kind, string(b))
	return err
}

func (s *Service) update(ctx context.Context, kind string, fn func(*Settings)) error {
	st, err := s.Get(ctx, kind)
	if err != nil {
		return err
	}
	fn(&st)
	return s.Save(ctx, st)
}

// BinaryPath finds a provider's tool, or returns an error saying how to install it.
func BinaryPath(k *Kind, st Settings) (string, error) {
	name := k.Binary
	if st.Binary != "" {
		name = st.Binary
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s is not installed on the NCC server (%s)", name, k.Install)
	}
	return p, nil
}

// Connected reports whether a provider has a sign-in in the vault (or needs none).
func (s *Service) Connected(ctx context.Context, k *Kind) (bool, error) {
	if k.HTTP {
		return true, nil
	}
	sec, err := s.Vault.Get(ctx, SecretPath(k.ID))
	if errors.Is(err, vault.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return len(sec) > 0, nil
}

// SavePasted stores a sign-in pasted by the person (see Kind.Paste).
func (s *Service) SavePasted(ctx context.Context, k *Kind, value string) error {
	value = strings.TrimSpace(value)
	if k.pasteAs == "" {
		return errors.New(k.Label + " cannot be connected by pasting; sign in instead")
	}
	if value == "" {
		return errors.New("paste the sign-in first")
	}
	sec := vault.Secret{}
	switch {
	case strings.HasPrefix(k.pasteAs, "env:"):
		if k.tokenRe != nil {
			m := k.tokenRe.FindString(value)
			if m == "" {
				return errors.New("that does not look like a " + k.Label + " sign-in token")
			}
			value = m
		}
		if strings.ContainsAny(value, " \n\t") {
			return errors.New("paste only the token, without spaces")
		}
		if strings.HasPrefix(value, "sk-ant-api") {
			return errors.New("that is an Anthropic API key; NCC uses your subscription sign-in instead (run claude setup-token)")
		}
		sec[k.pasteAs] = value
	case strings.HasPrefix(k.pasteAs, "file:"):
		if !json.Valid([]byte(value)) {
			return errors.New("paste the whole file; it is JSON")
		}
		sec[k.pasteAs] = base64.StdEncoding.EncodeToString([]byte(value))
	}
	if _, err := s.Vault.Put(ctx, SecretPath(k.ID), sec); err != nil {
		return err
	}
	now := time.Now().UTC()
	return s.update(ctx, k.ID, func(st *Settings) { st.ConnectedAt, st.LastError = &now, "" })
}

// SignOut removes a provider's sign-in from the vault.
func (s *Service) SignOut(ctx context.Context, k *Kind) error {
	if err := s.Vault.Delete(ctx, SecretPath(k.ID)); err != nil && !errors.Is(err, vault.ErrNotFound) {
		return err
	}
	return s.update(ctx, k.ID, func(st *Settings) { st.ConnectedAt = nil })
}

// Ask sends one prompt to a provider and returns the model's answer.
func (s *Service) Ask(ctx context.Context, kind, prompt string) (string, error) {
	k, err := KindByID(kind)
	if err != nil {
		return "", err
	}
	st, err := s.Get(ctx, kind)
	if err != nil {
		return "", err
	}
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 4 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var answer string
	if k.HTTP {
		answer, err = s.askOllama(ctx, st, prompt)
	} else {
		answer, err = s.askCLI(ctx, k, st, prompt)
	}
	now := time.Now().UTC()
	_ = s.update(context.WithoutCancel(ctx), kind, func(st *Settings) {
		st.LastUsed = &now
		st.LastError = ""
		if err != nil {
			st.LastError = err.Error()
		}
	})
	return answer, err
}

func (s *Service) askCLI(ctx context.Context, k *Kind, st Settings, prompt string) (string, error) {
	bin, err := BinaryPath(k, st)
	if err != nil {
		return "", err
	}
	sec, err := s.Vault.Get(ctx, SecretPath(k.ID))
	if errors.Is(err, vault.ErrNotFound) {
		return "", errors.New(k.Label + " is not signed in yet")
	}
	if err != nil {
		return "", err
	}
	home, err := s.newHome(k, sec)
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(home)
	model := st.Model
	if model == "" {
		model = k.DefaultModel
	}
	args := k.args(model)
	if !k.stdin {
		args = append(args, prompt)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = filepath.Join(home, "work")
	cmd.Env = toolEnv(home, sec)
	if k.stdin {
		cmd.Stdin = strings.NewReader(prompt)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &limitWriter{w: &errb, n: 16 << 10}
	cmd.WaitDelay = 5 * time.Second
	runErr := cmd.Run()
	// tools refresh their sign-in as they go: keep the newest one
	if upd, changed := harvest(k, home, sec); changed {
		_, _ = s.Vault.Put(context.WithoutCancel(ctx), SecretPath(k.ID), upd)
	}
	if runErr != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("%s took too long to answer", k.Label)
		}
		msg := strings.TrimSpace(stripANSI(errb.String()))
		if msg == "" {
			msg = strings.TrimSpace(stripANSI(out.String()))
		}
		if len(msg) > 600 {
			msg = msg[len(msg)-600:]
		}
		return "", fmt.Errorf("%s failed: %v: %s", k.Label, runErr, msg)
	}
	return k.parse(out.Bytes())
}

// newHome makes a private home folder for one run of a tool, with its settings and sign-in.
func (s *Service) newHome(k *Kind, sec vault.Secret) (string, error) {
	home, err := os.MkdirTemp(s.TempDir, "ncc-ai-")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(home, 0o700); err != nil {
		os.RemoveAll(home)
		return "", err
	}
	for _, d := range []string{"work", ".config", ".cache", ".local/share"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			os.RemoveAll(home)
			return "", err
		}
	}
	files := map[string][]byte{}
	for p, c := range k.setupFiles {
		files[p] = []byte(c)
	}
	for key, v := range sec {
		if p, ok := strings.CutPrefix(key, "file:"); ok {
			b, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				continue
			}
			files[p] = b
		}
	}
	for p, b := range files {
		if !safeRel(p) {
			continue
		}
		full := filepath.Join(home, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			os.RemoveAll(home)
			return "", err
		}
		if err := os.WriteFile(full, b, 0o600); err != nil {
			os.RemoveAll(home)
			return "", err
		}
	}
	return home, nil
}

func safeRel(p string) bool {
	c := filepath.Clean(p)
	return c != "." && !filepath.IsAbs(c) && !strings.HasPrefix(c, "..")
}

// toolEnv is the environment a tool runs with: its private home, its sign-in token, and
// nothing else from NCC's own environment but the PATH.
func toolEnv(home string, sec vault.Secret) []string {
	env := []string{
		"HOME=" + home,
		"USERPROFILE=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"XDG_CACHE_HOME=" + filepath.Join(home, ".cache"),
		"XDG_DATA_HOME=" + filepath.Join(home, ".local/share"),
		"CODEX_HOME=" + filepath.Join(home, ".codex"),
		"TERM=xterm-256color",
		"NO_COLOR=1",
		"LANG=C.UTF-8",
	}
	for _, k := range []string{"PATH", "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy", "SYSTEMROOT", "TZ"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	for key, v := range sec {
		if name, ok := strings.CutPrefix(key, "env:"); ok && validEnvName(name) {
			env = append(env, name+"="+v)
		}
	}
	return env
}

func validEnvName(n string) bool {
	if n == "" {
		return false
	}
	for _, r := range n {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// harvest reads a tool's sign-in files back from its home. changed is set when they differ
// from sec (a refreshed token).
func harvest(k *Kind, home string, sec vault.Secret) (vault.Secret, bool) {
	out := vault.Secret{}
	for key, v := range sec {
		out[key] = v
	}
	changed := false
	for _, p := range k.credFiles {
		b, err := os.ReadFile(filepath.Join(home, p))
		if err != nil || len(b) == 0 {
			continue
		}
		enc := base64.StdEncoding.EncodeToString(b)
		if out["file:"+p] != enc {
			out["file:"+p] = enc
			changed = true
		}
	}
	return out, changed
}

type limitWriter struct {
	w io.Writer
	n int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	q := p
	if len(q) > l.n {
		q = q[:l.n]
	}
	l.n -= len(q)
	_, _ = l.w.Write(q)
	return len(p), nil
}

func (s *Service) askOllama(ctx context.Context, st Settings, prompt string) (string, error) {
	addr := strings.TrimRight(strings.TrimSpace(st.Address), "/")
	if addr == "" {
		addr = "http://localhost:11434"
	}
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		return "", errors.New("the Ollama address must start with http:// or https://")
	}
	model := st.Model
	if model == "" {
		model = "qwen2.5:14b"
	}
	body, _ := json.Marshal(map[string]any{"model": model, "prompt": prompt, "stream": false, "format": "json",
		"options": map[string]any{"temperature": 0.2, "num_ctx": 32768}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := s.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot reach Ollama at %s: %w", addr, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	var r struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}
	_ = json.Unmarshal(raw, &r)
	if resp.StatusCode != 200 {
		if r.Error == "" {
			r.Error = resp.Status
		}
		return "", fmt.Errorf("Ollama: %s", r.Error)
	}
	return plainText([]byte(r.Response))
}
