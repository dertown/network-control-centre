package assistant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"

	"github.com/dertown/network-control-centre/internal/vault"
)

// Sign-in: NCC runs the tool's own sign-in command in a terminal on the NCC server and shows
// its output in the browser (the link to open and the device code), and passes back what the
// person types (an authorization code, or "y" to a question). When the command finishes, the
// sign-in it saved (a file in its private home, or a token it printed) goes into the vault and
// the private home is deleted.

// SignIn states.
const (
	SignInRunning   = "running"
	SignInConnected = "connected"
	SignInFailed    = "failed"
)

// SignInView is what the browser sees of a sign-in.
type SignInView struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	State  string `json:"state"`
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

type signIn struct {
	mu      sync.Mutex
	view    SignInView
	raw     strings.Builder
	tty     *os.File
	cancel  context.CancelFunc
	started time.Time
}

// SignIns keeps the sign-ins in progress.
type SignIns struct {
	Service *Service
	mu      sync.Mutex
	byID    map[string]*signIn
}

const signInTimeout = 10 * time.Minute

// Start runs a provider's sign-in command.
func (m *SignIns) Start(kind string) (SignInView, error) {
	k, err := KindByID(kind)
	if err != nil {
		return SignInView{}, err
	}
	if len(k.SignIn) == 0 {
		return SignInView{}, errors.New(k.Label + " needs no sign-in")
	}
	s := m.Service
	st, err := s.Get(context.Background(), kind)
	if err != nil {
		return SignInView{}, err
	}
	bin, err := s.BinaryPath(k, st)
	if err != nil {
		return SignInView{}, err
	}
	if vs := s.Vault.Status(context.Background()); vs.Sealed {
		return SignInView{}, vault.ErrSealed
	}
	home, err := s.newHome(k, nil)
	if err != nil {
		return SignInView{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), signInTimeout)
	cmd := exec.CommandContext(ctx, bin, k.SignIn...)
	cmd.Dir = home
	cmd.Env = append(toolEnv(home, nil, s.toolPath()), k.signInEnv...)
	cmd.WaitDelay = 5 * time.Second
	tty, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 40, Cols: 200})
	if err != nil {
		cancel()
		os.RemoveAll(home)
		return SignInView{}, errors.New("cannot start " + k.Binary + ": " + err.Error())
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	si := &signIn{view: SignInView{ID: hex.EncodeToString(b), Kind: kind, State: SignInRunning}, tty: tty, cancel: cancel, started: time.Now()}
	m.mu.Lock()
	if m.byID == nil {
		m.byID = map[string]*signIn{}
	}
	m.gc()
	// one sign-in per provider at a time
	for id, o := range m.byID {
		if o.view.Kind == kind {
			o.cancel()
			delete(m.byID, id)
		}
	}
	m.byID[si.view.ID] = si
	m.mu.Unlock()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := tty.Read(buf)
			if n > 0 {
				si.mu.Lock()
				if si.raw.Len() < 256<<10 {
					si.raw.Write(buf[:n])
				}
				si.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		werr := cmd.Wait()
		time.Sleep(200 * time.Millisecond) // let the reader drain the terminal
		tty.Close()
		cancel()
		defer os.RemoveAll(home)
		si.mu.Lock()
		out := stripANSI(si.raw.String())
		si.mu.Unlock()
		sec, _ := harvest(k, home, vault.Secret{})
		if k.tokenRe != nil && k.tokenEnv != "" {
			if tok := k.tokenRe.FindString(out); tok != "" {
				sec["env:"+k.tokenEnv] = tok
			}
		}
		state, msg := SignInConnected, ""
		switch {
		case len(sec) == 0 && werr != nil:
			state, msg = SignInFailed, "the sign-in did not finish: "+werr.Error()
		case len(sec) == 0:
			state, msg = SignInFailed, "the tool finished without saving a sign-in"
		default:
			bg := context.Background()
			if _, err := s.Vault.Put(bg, SecretPath(k.ID), sec); err != nil {
				state, msg = SignInFailed, "could not save the sign-in in the vault: "+err.Error()
			} else {
				now := time.Now().UTC()
				_ = s.update(bg, k.ID, func(st *Settings) { st.ConnectedAt, st.LastError, st.Enabled = &now, "", true })
			}
		}
		si.mu.Lock()
		si.view.State, si.view.Error = state, msg
		si.mu.Unlock()
	}()
	return si.snapshot(), nil
}

// gc forgets sign-ins that ended a while ago. Callers hold m.mu.
func (m *SignIns) gc() {
	for id, o := range m.byID {
		if time.Since(o.started) > signInTimeout+5*time.Minute {
			o.cancel()
			delete(m.byID, id)
		}
	}
}

func (si *signIn) snapshot() SignInView {
	si.mu.Lock()
	defer si.mu.Unlock()
	v := si.view
	v.Output = redactTokens(stripANSI(si.raw.String()))
	if len(v.Output) > 16<<10 {
		v.Output = v.Output[len(v.Output)-16<<10:]
	}
	return v
}

// redactTokens hides sign-in tokens a tool prints, so they don't reach the browser.
func redactTokens(s string) string {
	for _, k := range Kinds {
		if k.tokenRe != nil {
			s = k.tokenRe.ReplaceAllStringFunc(s, func(t string) string { return t[:12] + "… (saved in the vault)" })
		}
	}
	return s
}

func (m *SignIns) get(id string) (*signIn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	si, ok := m.byID[id]
	if !ok {
		return nil, errors.New("that sign-in has ended; start again")
	}
	return si, nil
}

// View returns a sign-in's state and output so far.
func (m *SignIns) View(id string) (SignInView, error) {
	si, err := m.get(id)
	if err != nil {
		return SignInView{}, err
	}
	return si.snapshot(), nil
}

// Input types a line into the sign-in (an authorization code, or an answer).
func (m *SignIns) Input(id, text string) (SignInView, error) {
	si, err := m.get(id)
	if err != nil {
		return SignInView{}, err
	}
	if strings.ContainsAny(text, "\r\n") || len(text) > 4096 {
		return SignInView{}, errors.New("type one line")
	}
	si.mu.Lock()
	running := si.view.State == SignInRunning
	si.mu.Unlock()
	if !running {
		return si.snapshot(), nil
	}
	if _, err := si.tty.Write([]byte(text + "\r")); err != nil {
		return SignInView{}, err
	}
	time.Sleep(300 * time.Millisecond)
	return si.snapshot(), nil
}

// Cancel stops a sign-in.
func (m *SignIns) Cancel(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if si, ok := m.byID[id]; ok {
		si.cancel()
		delete(m.byID, id)
	}
}
