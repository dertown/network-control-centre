package certdeploy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Conn is an open connection to a server that NCC installs certificates on.
type Conn interface {
	// WriteFile replaces a file. owner "" keeps the existing file's owner (or takes the folder's for a
	// new file); mode "" keeps the existing mode (0644 for a new file).
	WriteFile(ctx context.Context, path string, data []byte, mode, owner string) error
	// ReadFile returns fs.ErrNotExist when the file is missing.
	ReadFile(ctx context.Context, path string) ([]byte, error)
	// Run runs a command (a shell command on Linux, PowerShell on Windows) and returns its output.
	Run(ctx context.Context, cmd string) (string, error)
	Close() error
}

// SSHOptions configures an SSH connection.
type SSHOptions struct {
	Host, User string
	Port       int
	Password   string
	PrivateKey string // PEM (OpenSSH or PKCS#8); optional
	Passphrase string // for an encrypted private key
	// HostKey is the pinned SHA256 host key fingerprint ("SHA256:..."). Empty refuses to connect
	// unless AcceptHostKey matches what the server presents (trust on first use, confirmed in the preview).
	HostKey       string
	AcceptHostKey string
	Sudo          bool
	SudoPassword  string // defaults to Password
	Timeout       time.Duration
}

// ErrHostKeyUnknown means the server's host key has not been pinned yet.
type ErrHostKeyUnknown struct{ Seen string }

func (e *ErrHostKeyUnknown) Error() string {
	return "this server's SSH host key is not trusted yet (" + e.Seen + "); confirm it in the preview"
}

type sshConn struct {
	c    *ssh.Client
	opts SSHOptions
}

// DialSSH opens an SSH connection. The returned string is the host key fingerprint the server presented.
func DialSSH(ctx context.Context, o SSHOptions) (Conn, string, error) {
	if o.Port == 0 {
		o.Port = 22
	}
	if o.Timeout == 0 {
		o.Timeout = 15 * time.Second
	}
	if o.SudoPassword == "" {
		o.SudoPassword = o.Password
	}
	var auths []ssh.AuthMethod
	if strings.TrimSpace(o.PrivateKey) != "" {
		var signer ssh.Signer
		var err error
		if o.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(o.PrivateKey), []byte(o.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(o.PrivateKey))
		}
		if err != nil {
			return nil, "", fmt.Errorf("SSH private key: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if o.Password != "" {
		pw := o.Password
		auths = append(auths, ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			ans := make([]string, len(qs))
			for i := range qs {
				ans[i] = pw
			}
			return ans, nil
		}))
	}
	if len(auths) == 0 {
		return nil, "", errors.New("no SSH password or private key saved for this server")
	}
	var seen string
	cfg := &ssh.ClientConfig{
		User: o.User,
		Auth: auths,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = ssh.FingerprintSHA256(key)
			want := o.HostKey
			if want == "" {
				want = o.AcceptHostKey
			}
			if want == "" {
				return &ErrHostKeyUnknown{Seen: seen}
			}
			if seen != want {
				return fmt.Errorf("SSH host key changed: pinned %s, server sent %s", want, seen)
			}
			return nil
		},
		Timeout: o.Timeout,
	}
	addr := net.JoinHostPort(o.Host, strconv.Itoa(o.Port))
	d := net.Dialer{Timeout: o.Timeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "", err
	}
	cc, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		_ = raw.Close()
		var hk *ErrHostKeyUnknown
		if errors.As(err, &hk) {
			return nil, seen, hk
		}
		return nil, seen, err
	}
	return &sshConn{c: ssh.NewClient(cc, chans, reqs), opts: o}, seen, nil
}

func (s *sshConn) Close() error { return s.c.Close() }

// exec runs one command with optional stdin and returns stdout; stderr goes into the error.
func (s *sshConn) exec(ctx context.Context, cmd string, stdin []byte) (string, int, error) {
	sess, err := s.c.NewSession()
	if err != nil {
		return "", -1, err
	}
	defer sess.Close()
	var out, errb bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &errb
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		return out.String(), -1, ctx.Err()
	case err = <-done:
	}
	if err != nil {
		code := -1
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitStatus()
		}
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = strings.TrimSpace(out.String())
		}
		if msg == "" {
			msg = err.Error()
		}
		return out.String(), code, errors.New(msg)
	}
	return out.String(), 0, nil
}

// privileged runs a shell script as root through sudo when the target is set up for it.
// The sudo password, if any, goes in on stdin so it never shows in a process list.
func (s *sshConn) privileged(ctx context.Context, script string) (string, int, error) {
	if !s.opts.Sudo || s.opts.User == "root" {
		return s.exec(ctx, "sh -c "+shQuote(script), nil)
	}
	if s.opts.SudoPassword == "" {
		return s.exec(ctx, "sudo -n sh -c "+shQuote(script), nil)
	}
	return s.exec(ctx, "sudo -S -p '' sh -c "+shQuote(script), []byte(s.opts.SudoPassword+"\n"))
}

func (s *sshConn) Run(ctx context.Context, cmd string) (string, error) {
	out, _, err := s.privileged(ctx, cmd)
	return out, err
}

func (s *sshConn) ReadFile(ctx context.Context, path string) ([]byte, error) {
	p := shQuote(path)
	out, code, err := s.privileged(ctx, "if [ -e "+p+" ]; then cat "+p+"; else exit 44; fi")
	if code == 44 {
		return nil, fs.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

var modeRe = func(m string) bool {
	if len(m) < 3 || len(m) > 4 {
		return false
	}
	for _, c := range m {
		if c < '0' || c > '7' {
			return false
		}
	}
	return true
}

// WriteFile uploads to a private temporary file as the login user, then (as root when sudo is on)
// keeps a .ncc-bak copy of the old file and moves the new one into place atomically.
func (s *sshConn) WriteFile(ctx context.Context, path string, data []byte, mode, owner string) error {
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("path %q must be absolute", path)
	}
	if mode != "" && !modeRe(mode) {
		return fmt.Errorf("bad file mode %q", mode)
	}
	tmp, _, err := s.exec(ctx, `umask 077; t=$(mktemp /tmp/ncc-cert.XXXXXXXX) && cat > "$t" && echo "$t"`, data)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	tmp = strings.TrimSpace(tmp)
	script := strings.Join([]string{
		"set -e",
		"t=" + shQuote(tmp) + "; p=" + shQuote(path) + "; own=" + shQuote(owner),
		`trap 'rm -f "$t"' EXIT`,
		`mkdir -p "$(dirname "$p")"`,
		// new files take the owner of their folder; replaced files keep their owner and mode
		`o=$(stat -c %u:%g "$(dirname "$p")" 2>/dev/null || true); m=` + shQuote(mode),
		`if [ -e "$p" ]; then cp -p "$p" "$p.ncc-bak"; o=$(stat -c %u:%g "$p" 2>/dev/null || true); [ -n "$m" ] || m=$(stat -c %a "$p"); fi`,
		`[ -n "$m" ] || m=0644`,
		`(umask 077; cat "$t" > "$p.ncc-new")`,
		`chmod "$m" "$p.ncc-new"`,
		`if [ -n "$own" ]; then chown "$own" "$p.ncc-new"; elif [ -n "$o" ]; then chown "$o" "$p.ncc-new" 2>/dev/null || true; fi`,
		`mv -f "$p.ncc-new" "$p"`,
	}, "\n")
	if _, _, err := s.privileged(ctx, script); err != nil {
		_, _, _ = s.exec(ctx, "rm -f "+shQuote(tmp), nil)
		return err
	}
	return nil
}

// shQuote quotes a string for a POSIX shell.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
