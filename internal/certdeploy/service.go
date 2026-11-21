// Package certdeploy installs certificates from NCC's inventory (keys from the vault) on
// servers: nginx, Apache, Tomcat, Splunk Enterprise, Splunk SOAR, Foundry VTT, other Linux
// services over SSH, and IIS over WinRM. Every deployment is previewed first, runs as a list
// of steps, is checked by connecting to the server afterwards, and is kept in a history.
package certdeploy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dertown/network-control-centre/internal/pki"
	"github.com/dertown/network-control-centre/internal/vault"
)

// Target is a server NCC deploys certificates to.
type Target struct {
	ID         int64             `json:"id"`
	Name       string            `json:"name"`
	Kind       string            `json:"kind"`
	Host       string            `json:"host"`
	Port       int               `json:"port"`
	Options    map[string]string `json:"options"`
	SecretPath string            `json:"secret_path"`
	// CertID is the certificate normally deployed here (0 = none chosen yet).
	CertID int64 `json:"cert_id"`
	// Credentials says which login values are saved in the vault (never the values).
	Credentials map[string]bool `json:"credentials"`
	Last        *Deployment     `json:"last_deploy,omitempty"`
}

func (t *Target) kind() *Kind {
	if k := kindByID(t.Kind); k != nil {
		return k
	}
	return &Kind{ID: t.Kind}
}

// Deployment is one run, kept in the history.
type Deployment struct {
	ID          int64        `json:"id"`
	TargetID    int64        `json:"target_id"`
	TargetName  string       `json:"target_name"`
	CertID      int64        `json:"cert_id"`
	CertName    string       `json:"cert_name"`
	Fingerprint string       `json:"fingerprint"`
	Actor       string       `json:"actor"`
	Started     time.Time    `json:"started"`
	Finished    *time.Time   `json:"finished,omitempty"`
	Status      string       `json:"status"` // running | ok | failed
	Verified    string       `json:"verified"`
	Steps       []StepResult `json:"steps"`
	Error       string       `json:"error,omitempty"`
}

// StepResult is the outcome of one step.
type StepResult struct {
	Title  string `json:"title"`
	Op     string `json:"op"`
	Path   string `json:"path,omitempty"`
	Status string `json:"status"` // pending | running | ok | unchanged | failed | skipped
	Output string `json:"output,omitempty"`
}

// Plan is the preview of a deployment.
type Plan struct {
	Target     Target     `json:"target"`
	Cert       *pki.Cert  `json:"cert"`
	Steps      []Step     `json:"steps"`
	Notes      []string   `json:"notes"`
	Warnings   []string   `json:"warnings"`
	Blocked    string     `json:"blocked,omitempty"` // why it cannot be deployed
	Connection *ConnCheck `json:"connection,omitempty"`
}

// ConnCheck reports a test login made for the preview.
type ConnCheck struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Fingerprint is the SSH host key or WinRM certificate seen; Trust asks the person to confirm it.
	Fingerprint string `json:"fingerprint,omitempty"`
	Trust       bool   `json:"trust,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

// Auditor records audit log entries.
type Auditor interface {
	Record(ctx context.Context, actor, action, target string, detail any) error
}

// Service manages deploy targets and runs deployments.
type Service struct {
	DB    *sql.DB
	Vault vault.Store
	Certs *pki.Inventory
	Audit Auditor

	// Dial functions can be replaced in tests.
	DialSSH   func(context.Context, SSHOptions) (Conn, string, error)
	DialWinRM func(context.Context, WinRMOptions) (Conn, string, error)
	// VerifyEvery is the pause between checks of the served certificate.
	VerifyEvery time.Duration
	// VerifyWait overrides each server type's wait for the new certificate to be served.
	VerifyWait time.Duration

	running sync.Map // target id -> struct{}
	wg      sync.WaitGroup
}

var (
	nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`)
	hostRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.:_-]{0,252}$`)
	// ErrNotFound is returned for unknown targets or deployments.
	ErrNotFound = errors.New("deploy target not found")
	// ErrBusy is returned when a deployment to the same target is already running.
	ErrBusy = errors.New("a deployment to this server is already running")
)

// credentialKeys are the login values a target may keep in the vault.
var credentialKeys = []string{"username", "password", "ssh_private_key", "ssh_passphrase", "sudo_password", "keystore_password"}

// ---- targets ----

const targetCols = `id, name, kind, host, port, options, secret_path, cert_id`

func scanTarget(sc interface{ Scan(...any) error }) (*Target, error) {
	var t Target
	var opts string
	if err := sc.Scan(&t.ID, &t.Name, &t.Kind, &t.Host, &t.Port, &opts, &t.SecretPath, &t.CertID); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(opts), &t.Options)
	if t.Options == nil {
		t.Options = map[string]string{}
	}
	return &t, nil
}

func (s *Service) validate(t *Target) error {
	if !nameRe.MatchString(t.Name) {
		return errors.New("name may use letters, digits, dot, dash and underscore (max 63)")
	}
	k := kindByID(t.Kind)
	if k == nil {
		return fmt.Errorf("unknown server type %q", t.Kind)
	}
	t.Host = strings.TrimSpace(t.Host)
	if !hostRe.MatchString(t.Host) {
		return errors.New("enter the server's host name or IP address")
	}
	if t.Port == 0 {
		t.Port = k.DefaultPort
	}
	if t.Port < 1 || t.Port > 65535 {
		return errors.New("port must be 1-65535")
	}
	clean := map[string]string{}
	for _, f := range k.Fields {
		if v, ok := t.Options[f.Key]; ok {
			if strings.ContainsAny(v, "\x00") {
				return fmt.Errorf("%s contains a NUL character", f.Label)
			}
			clean[f.Key] = strings.TrimSpace(v)
		}
	}
	t.Options = clean
	return nil
}

// Create adds a deploy target.
func (s *Service) Create(ctx context.Context, t *Target) error {
	if err := s.validate(t); err != nil {
		return err
	}
	t.SecretPath = "deploy/" + t.Name
	opts, _ := json.Marshal(t.Options)
	res, err := s.DB.ExecContext(ctx, `INSERT INTO cert_deploy_targets (name, kind, host, port, options, secret_path, cert_id)
		VALUES (?,?,?,?,?,?,?)`, t.Name, t.Kind, t.Host, t.Port, string(opts), t.SecretPath, t.CertID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return fmt.Errorf("a server called %q already exists", t.Name)
		}
		return err
	}
	t.ID, _ = res.LastInsertId()
	return nil
}

// Update saves a target's address, settings and chosen certificate (the name and type stay).
func (s *Service) Update(ctx context.Context, t *Target) error {
	old, err := s.Get(ctx, t.ID)
	if err != nil {
		return err
	}
	t.Name, t.Kind, t.SecretPath = old.Name, old.Kind, old.SecretPath
	if err := s.validate(t); err != nil {
		return err
	}
	// a new address invalidates the pinned host key / WinRM certificate
	if t.Host != old.Host || t.Port != old.Port {
		if t.Options["host_key"] == old.Options["host_key"] {
			delete(t.Options, "host_key")
		}
		if t.Options["tls_pin"] == old.Options["tls_pin"] {
			delete(t.Options, "tls_pin")
		}
	}
	opts, _ := json.Marshal(t.Options)
	_, err = s.DB.ExecContext(ctx, `UPDATE cert_deploy_targets SET host = ?, port = ?, options = ?, cert_id = ? WHERE id = ?`,
		t.Host, t.Port, string(opts), t.CertID, t.ID)
	return err
}

// Get loads one target.
func (s *Service) Get(ctx context.Context, id int64) (*Target, error) {
	t, err := scanTarget(s.DB.QueryRowContext(ctx, `SELECT `+targetCols+` FROM cert_deploy_targets WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

// List returns every target with its saved-credential flags and last deployment.
func (s *Service) List(ctx context.Context) ([]Target, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+targetCols+` FROM cert_deploy_targets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var out []Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, *t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	last, err := s.lastByTarget(ctx)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Credentials = s.credentialFlags(ctx, out[i].SecretPath)
		out[i].Last = last[out[i].ID]
	}
	return out, nil
}

func (s *Service) credentialFlags(ctx context.Context, path string) map[string]bool {
	flags := map[string]bool{}
	sec, err := s.Vault.Get(ctx, path)
	if err != nil {
		return flags
	}
	for _, k := range credentialKeys {
		if sec[k] != "" {
			flags[k] = true
		}
	}
	return flags
}

// Delete removes a target, its history and its saved login.
func (s *Service) Delete(ctx context.Context, id int64) error {
	t, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if err := s.Vault.Delete(ctx, t.SecretPath); err != nil && !errors.Is(err, vault.ErrNotFound) {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `DELETE FROM cert_deploy_targets WHERE id = ?`, id)
	return err
}

// SetCredentials merges login values into the target's vault secret. Empty values are left
// alone; keys listed in clear are removed.
func (s *Service) SetCredentials(ctx context.Context, id int64, values map[string]string, clear []string) error {
	t, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	cur, err := s.Vault.Get(ctx, t.SecretPath)
	if errors.Is(err, vault.ErrNotFound) {
		cur, err = vault.Secret{}, nil
	}
	if err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, k := range credentialKeys {
		allowed[k] = true
	}
	for k, v := range values {
		if !allowed[k] {
			return fmt.Errorf("unknown credential %q", k)
		}
		if v != "" {
			cur[k] = v
		}
	}
	for _, k := range clear {
		delete(cur, k)
	}
	_, err = s.Vault.Put(ctx, t.SecretPath, cur)
	return err
}

// ---- plan ----

func (s *Service) secrets(ctx context.Context, t *Target) (map[string]string, error) {
	sec, err := s.Vault.Get(ctx, t.SecretPath)
	if errors.Is(err, vault.ErrNotFound) {
		return map[string]string{}, nil
	}
	return sec, err
}

func effectiveOptions(t *Target) map[string]string {
	opts := map[string]string{}
	for _, f := range t.kind().Fields {
		opts[f.Key] = f.Default
	}
	// a setting that is present wins, even when empty (an empty check port skips the check)
	for k, v := range t.Options {
		opts[k] = v
	}
	return opts
}

// build makes the steps for a target and certificate without touching the server.
func (s *Service) build(ctx context.Context, t *Target, certID int64) (*Plan, *planner, error) {
	k := kindByID(t.Kind)
	if k == nil {
		return nil, nil, fmt.Errorf("unknown server type %q", t.Kind)
	}
	cert, err := s.Certs.Get(ctx, certID)
	if err != nil {
		return nil, nil, errors.New("certificate not found")
	}
	plan := &Plan{Target: *t, Cert: cert, Steps: []Step{}, Notes: []string{}, Warnings: []string{}}
	if !cert.HasKey {
		plan.Blocked = "This certificate was imported without its private key, so it cannot be installed. Import it again with the key."
		return plan, nil, nil
	}
	certPEM, keyPEM, err := s.Certs.Material(ctx, certID)
	if err != nil {
		return nil, nil, err
	}
	m, err := NewMaterial(cert.Name, certPEM, keyPEM)
	if err != nil {
		plan.Blocked = err.Error()
		return plan, nil, nil
	}
	sec, err := s.secrets(ctx, t)
	if err != nil {
		return nil, nil, err
	}
	p := &planner{t: t, transport: k.Transport, m: m, opts: effectiveOptions(t), secrets: sec}
	if err := k.build(p); err != nil {
		plan.Blocked = "Settings problem: " + err.Error()
		return plan, nil, nil
	}
	plan.Steps = p.steps
	plan.Notes = append(plan.Notes, p.notes...)
	plan.Warnings = append(plan.Warnings, p.warnings...)

	now := time.Now()
	switch {
	case cert.NotAfter.Before(now):
		plan.Warnings = append(plan.Warnings, "This certificate has expired.")
	case cert.NotBefore.After(now):
		plan.Warnings = append(plan.Warnings, "This certificate is not valid yet (from "+cert.NotBefore.Format("2 Jan 2006")+").")
	case cert.DaysLeft <= pki.WarnDays:
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("This certificate expires in %d days.", cert.DaysLeft))
	}
	if name := checkName(p, m); name != "" && !m.Covers(name) {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("The certificate does not cover %s (it covers %s), so browsers will warn.", name, strings.Join(cert.SANs, ", ")))
	}
	if m.ChainPEM == "" && m.Leaf.Subject.String() != m.Leaf.Issuer.String() {
		plan.Warnings = append(plan.Warnings, "No intermediate certificates are stored with this certificate, so some clients may not trust it. If your CA gave you a CA bundle, add it under Vault & certificates (Add CA bundle).")
	}
	if t.CertID != 0 && t.CertID != certID {
		if prev, err := s.Certs.Get(ctx, t.CertID); err == nil {
			plan.Warnings = append(plan.Warnings, "This server normally gets "+prev.Name+"; deploying "+cert.Name+" replaces it.")
		}
	}
	return plan, p, nil
}

// checkName is the host name the served certificate is checked against.
func checkName(p *planner, m *Material) string {
	if v := p.opt("check_name"); v != "" {
		return v
	}
	if v := p.opt("host_header"); v != "" {
		return v
	}
	if net.ParseIP(p.t.Host) == nil {
		return p.t.Host
	}
	return "" // an IP address: browsers usually reach it by a name we do not know
}

// Plan previews deploying certID to target id. With connect it also tests the login.
func (s *Service) Plan(ctx context.Context, id, certID int64, connect bool) (*Plan, error) {
	t, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	t.Credentials = s.credentialFlags(ctx, t.SecretPath)
	plan, _, err := s.build(ctx, t, certID)
	if err != nil {
		return nil, err
	}
	if connect && plan.Blocked == "" {
		plan.Connection = s.Test(ctx, t, "")
	}
	return plan, nil
}

// Test logs in to the server and checks that NCC can act as root (Linux) or run PowerShell (Windows).
func (s *Service) Test(ctx context.Context, t *Target, accept string) *ConnCheck {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, seen, err := s.connect(ctx, t, accept)
	cc := &ConnCheck{Fingerprint: seen}
	if err != nil {
		var hk *ErrHostKeyUnknown
		var tp *ErrTLSPinUnknown
		if errors.As(err, &hk) || errors.As(err, &tp) {
			cc.Trust = true
		}
		cc.Error = err.Error()
		return cc
	}
	defer conn.Close()
	if t.kind().Transport == "winrm" {
		out, err := conn.Run(ctx, "$env:COMPUTERNAME+' '+[Environment]::OSVersion.VersionString")
		if err != nil {
			cc.Error = "logged in, but PowerShell failed: " + err.Error()
			return cc
		}
		cc.OK, cc.Detail = true, "Logged in to "+strings.TrimSpace(out)
		return cc
	}
	sudo := strings.EqualFold(effectiveOptions(t)["use_sudo"], "true")
	out, err := conn.Run(ctx, "id -un; hostname")
	if err != nil {
		if sudo {
			cc.Error = "logged in, but sudo failed: " + err.Error()
		} else {
			cc.Error = "logged in, but could not run commands: " + err.Error()
		}
		return cc
	}
	f := strings.Fields(out)
	as := "root"
	if len(f) >= 1 {
		as = f[0]
	}
	if sudo && as != "root" {
		cc.Error = "sudo did not give root (commands run as " + as + ")"
		return cc
	}
	// without sudo NCC works as the login user, which is right when that user owns the
	// service (e.g. Splunk installed in the splunk user's home)
	cc.OK = true
	cc.Detail = "Logged in; commands run as " + as
	if len(f) >= 2 {
		cc.Detail += " on " + f[1]
	}
	return cc
}

func (s *Service) connect(ctx context.Context, t *Target, accept string) (Conn, string, error) {
	sec, err := s.secrets(ctx, t)
	if err != nil {
		return nil, "", err
	}
	opts := effectiveOptions(t)
	b := func(k string) bool { v := strings.ToLower(opts[k]); return v == "true" || v == "1" || v == "yes" }
	if t.kind().Transport == "winrm" {
		dial := s.DialWinRM
		if dial == nil {
			dial = DialWinRM
		}
		return dial(ctx, WinRMOptions{Host: t.Host, Port: t.Port, HTTPS: true, Auth: opts["auth"], User: sec["username"],
			Password: sec["password"], TLSPin: opts["tls_pin"], AcceptPin: accept, Verify: b("verify_tls")})
	}
	dial := s.DialSSH
	if dial == nil {
		dial = DialSSH
	}
	return dial(ctx, SSHOptions{Host: t.Host, Port: t.Port, User: sec["username"], Password: sec["password"],
		PrivateKey: sec["ssh_private_key"], Passphrase: sec["ssh_passphrase"], HostKey: opts["host_key"], AcceptHostKey: accept,
		Sudo: b("use_sudo"), SudoPassword: sec["sudo_password"]})
}

// ---- deploy ----

// Deploy starts a deployment in the background and returns its id. accept confirms a host key
// or WinRM certificate fingerprint shown in the preview; it is pinned once the login works.
func (s *Service) Deploy(ctx context.Context, id, certID int64, accept, actor string) (*Deployment, error) {
	t, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	plan, p, err := s.build(ctx, t, certID)
	if err != nil {
		return nil, err
	}
	if plan.Blocked != "" {
		return nil, errors.New(plan.Blocked)
	}
	if _, busy := s.running.LoadOrStore(id, struct{}{}); busy {
		return nil, ErrBusy
	}
	d := &Deployment{TargetID: t.ID, TargetName: t.Name, CertID: certID, CertName: plan.Cert.Name, Fingerprint: plan.Cert.Fingerprint,
		Actor: actor, Started: time.Now().UTC(), Status: "running"}
	for _, st := range plan.Steps {
		d.Steps = append(d.Steps, StepResult{Title: st.Title, Op: st.Op, Path: st.Path, Status: "pending"})
	}
	if err := s.insert(ctx, d); err != nil {
		s.running.Delete(id)
		return nil, err
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.running.Delete(id)
		// the browser may go away; the deployment carries on
		rctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		s.execute(rctx, t, plan, p, d, accept)
	}()
	return d, nil
}

// Wait blocks until background deployments finish (tests, shutdown).
func (s *Service) Wait() { s.wg.Wait() }

func (s *Service) execute(ctx context.Context, t *Target, plan *Plan, p *planner, d *Deployment, accept string) {
	fail := func(msg string) {
		d.Status, d.Error = "failed", msg
		s.finish(ctx, t, d)
	}
	conn, seen, err := s.connect(ctx, t, accept)
	if err != nil {
		fail("Could not connect: " + err.Error())
		return
	}
	defer conn.Close()
	if accept != "" && seen == accept {
		key := "host_key"
		if t.kind().Transport == "winrm" {
			key = "tls_pin"
		}
		if t.Options[key] == "" {
			t.Options[key] = seen
			opts, _ := json.Marshal(t.Options)
			_, _ = s.DB.ExecContext(ctx, `UPDATE cert_deploy_targets SET options = ? WHERE id = ?`, string(opts), t.ID)
		}
	}
	if len(p.saveSecrets) > 0 {
		if err := s.SetCredentials(ctx, t.ID, p.saveSecrets, nil); err != nil {
			fail("Could not save the generated keystore password in the vault: " + err.Error())
			return
		}
	}
	for i, st := range plan.Steps {
		d.Steps[i].Status = "running"
		s.save(ctx, d)
		out, status, err := runStep(ctx, conn, st)
		d.Steps[i].Output = trimOutput(out)
		if err != nil {
			d.Steps[i].Status = "failed"
			d.Steps[i].Output = trimOutput(err.Error())
			for j := i + 1; j < len(d.Steps); j++ {
				d.Steps[j].Status = "skipped"
			}
			fail(st.Title + " failed: " + err.Error())
			return
		}
		d.Steps[i].Status = status
	}
	if t.CertID != d.CertID {
		_, _ = s.DB.ExecContext(ctx, `UPDATE cert_deploy_targets SET cert_id = ? WHERE id = ?`, d.CertID, t.ID)
	}
	d.Status = "ok"
	d.Verified = s.verify(ctx, t, p, plan.Cert.Fingerprint)
	s.finish(ctx, t, d)
}

func runStep(ctx context.Context, conn Conn, st Step) (string, string, error) {
	switch st.Op {
	case "write":
		return "", "ok", conn.WriteFile(ctx, st.Path, st.data, st.mode, st.owner)
	case "edit":
		old, err := conn.ReadFile(ctx, st.Path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", "", err
		}
		created := errors.Is(err, fs.ErrNotExist)
		upd, err := st.edit(old)
		if err != nil {
			return "", "", fmt.Errorf("could not update %s: %w", st.Path, err)
		}
		if string(upd) == string(old) {
			return "already set", "unchanged", nil
		}
		if err := conn.WriteFile(ctx, st.Path, upd, "", ""); err != nil {
			return "", "", err
		}
		if created {
			return "created the file", "ok", nil
		}
		return "updated; the old file is kept as " + st.Path + ".ncc-bak", "ok", nil
	case "run":
		out, err := conn.Run(ctx, st.cmd)
		return out, "ok", err
	}
	return "", "", fmt.Errorf("unknown step %q", st.Op)
}

func trimOutput(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 2000 {
		s = s[:2000] + " …"
	}
	return s
}

// verify connects to the service until it serves the new certificate or the kind's wait runs out.
func (s *Service) verify(ctx context.Context, t *Target, p *planner, want string) string {
	port := p.opt("https_port")
	if port == "" {
		return "skipped: no port to check"
	}
	name := checkName(p, p.m)
	if name == "" && len(p.m.Leaf.DNSNames) > 0 {
		name = strings.Replace(p.m.Leaf.DNSNames[0], "*.", "www.", 1)
	}
	wait := time.Duration(t.kind().VerifyWait) * time.Second
	if s.VerifyWait != 0 {
		wait = s.VerifyWait
	}
	every := s.VerifyEvery
	if every == 0 {
		every = 3 * time.Second
	}
	deadline := time.Now().Add(wait)
	var last string
	for {
		info, err := Probe(ctx, t.Host, port, name)
		switch {
		case err != nil:
			last = "could not connect to port " + port + ": " + err.Error()
		case info.Fingerprint == want:
			return "ok: port " + port + " now serves the new certificate"
		default:
			last = "port " + port + " still serves " + info.Subject + " (expires " + info.NotAfter.Format("2 Jan 2006") + ")"
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return "not confirmed: " + last
		}
		select {
		case <-ctx.Done():
			return "not confirmed: " + last
		case <-time.After(every):
		}
	}
}

// Served is the certificate a server presents.
type Served struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"`
	SANs        []string  `json:"sans"`
	// CertName is the inventory certificate with the same fingerprint, if any.
	CertName string `json:"cert_name,omitempty"`
	Port     string `json:"port"`
	Error    string `json:"error,omitempty"`
}

// Probe reads the certificate served on host:port, without trusting or checking it.
func Probe(ctx context.Context, host, port, serverName string) (*Served, error) {
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // only reading which certificate is served
		MinVersion:         tls.VersionTLS10,
	}}
	pctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	c, err := d.DialContext(pctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	certs := c.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("no certificate")
	}
	return servedFrom(certs[0], port), nil
}

func servedFrom(c *x509.Certificate, port string) *Served {
	sans := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}
	return &Served{Subject: c.Subject.String(), Issuer: c.Issuer.String(), NotAfter: c.NotAfter, Fingerprint: pki.Fingerprint(c), SANs: sans, Port: port}
}

// ServedBy probes a target's service port and names the matching inventory certificate.
func (s *Service) ServedBy(ctx context.Context, id int64) (*Served, error) {
	t, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	opts := effectiveOptions(t)
	port := opts["https_port"]
	if port == "" {
		return &Served{Error: "no port to check"}, nil
	}
	if _, err := strconv.Atoi(port); err != nil {
		return &Served{Port: port, Error: "bad port"}, nil
	}
	name := opts["check_name"]
	if name == "" {
		name = opts["host_header"]
	}
	if name == "" && net.ParseIP(t.Host) == nil {
		name = t.Host
	}
	info, err := Probe(ctx, t.Host, port, name)
	if err != nil {
		return &Served{Port: port, Error: err.Error()}, nil
	}
	var fp string
	if err := s.DB.QueryRowContext(ctx, `SELECT name FROM certificates WHERE fingerprint = ?`, info.Fingerprint).Scan(&fp); err == nil {
		info.CertName = fp
	}
	return info, nil
}

// ---- history ----

func (s *Service) insert(ctx context.Context, d *Deployment) error {
	steps, _ := json.Marshal(d.Steps)
	res, err := s.DB.ExecContext(ctx, `INSERT INTO cert_deployments (target_id, target_name, cert_id, cert_name, fingerprint, actor, started, status, steps)
		VALUES (?,?,?,?,?,?,?,?,?)`, d.TargetID, d.TargetName, d.CertID, d.CertName, d.Fingerprint, d.Actor, d.Started.Format(time.RFC3339), d.Status, string(steps))
	if err != nil {
		return err
	}
	d.ID, _ = res.LastInsertId()
	return nil
}

func (s *Service) save(ctx context.Context, d *Deployment) {
	steps, _ := json.Marshal(d.Steps)
	var fin any
	if d.Finished != nil {
		fin = d.Finished.Format(time.RFC3339)
	}
	_, _ = s.DB.ExecContext(context.WithoutCancel(ctx), `UPDATE cert_deployments SET status = ?, verified = ?, steps = ?, error = ?, finished = ? WHERE id = ?`,
		d.Status, d.Verified, string(steps), d.Error, fin, d.ID)
}

func (s *Service) finish(ctx context.Context, t *Target, d *Deployment) {
	now := time.Now().UTC()
	d.Finished = &now
	s.save(ctx, d)
	if s.Audit != nil {
		var done []string
		for _, st := range d.Steps {
			done = append(done, st.Title+": "+st.Status)
		}
		action := "cert.deploy"
		if d.Status != "ok" {
			action = "cert.deploy.failed"
		}
		_ = s.Audit.Record(context.WithoutCancel(ctx), d.Actor, action, "deploy/"+t.Name, map[string]any{
			"cert": d.CertName, "fingerprint": d.Fingerprint, "kind": t.Kind, "host": t.Host,
			"steps": done, "verified": d.Verified, "error": d.Error,
		})
	}
}

const deployCols = `id, target_id, target_name, cert_id, cert_name, fingerprint, actor, started, finished, status, verified, steps, error`

func scanDeployment(sc interface{ Scan(...any) error }) (*Deployment, error) {
	var d Deployment
	var started string
	var fin sql.NullString
	var steps string
	if err := sc.Scan(&d.ID, &d.TargetID, &d.TargetName, &d.CertID, &d.CertName, &d.Fingerprint, &d.Actor, &started, &fin, &d.Status, &d.Verified, &steps, &d.Error); err != nil {
		return nil, err
	}
	d.Started, _ = time.Parse(time.RFC3339, started)
	if fin.Valid {
		f, _ := time.Parse(time.RFC3339, fin.String)
		d.Finished = &f
	}
	_ = json.Unmarshal([]byte(steps), &d.Steps)
	return &d, nil
}

// Deployment returns one deployment (for following its progress).
func (s *Service) Deployment(ctx context.Context, id int64) (*Deployment, error) {
	d, err := scanDeployment(s.DB.QueryRowContext(ctx, `SELECT `+deployCols+` FROM cert_deployments WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

// History lists recent deployments, newest first; targetID 0 means all servers.
func (s *Service) History(ctx context.Context, targetID int64, limit int) ([]Deployment, error) {
	q := `SELECT ` + deployCols + ` FROM cert_deployments`
	var args []any
	if targetID != 0 {
		q += ` WHERE target_id = ?`
		args = append(args, targetID)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Deployment{}
	for rows.Next() {
		d, err := scanDeployment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

func (s *Service) lastByTarget(ctx context.Context) (map[int64]*Deployment, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+deployCols+` FROM cert_deployments WHERE id IN (SELECT MAX(id) FROM cert_deployments GROUP BY target_id)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]*Deployment{}
	for rows.Next() {
		d, err := scanDeployment(rows)
		if err != nil {
			return nil, err
		}
		out[d.TargetID] = d
	}
	return out, rows.Err()
}

// MarkInterrupted fails deployments left running by a restart of NCC.
func (s *Service) MarkInterrupted(ctx context.Context) {
	_, _ = s.DB.ExecContext(ctx, `UPDATE cert_deployments SET status = 'failed', error = 'NCC restarted while this deployment was running; check the server and deploy again'
		WHERE status = 'running'`)
}
