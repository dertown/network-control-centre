package assistant

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Installing the tools: NCC installs a provider's command-line tool itself, into its own
// folder (Service.ToolsDir, normally <data_dir>/ai-tools), so nothing needs root and nothing
// outside NCC's data folder changes. The tools are npm packages, installed from the official
// npm registry with the Node.js already on the server, or, when there is none, with an
// official Node.js LTS downloaded from nodejs.org and checked against its published SHA-256.

// Official sources. Variables so tests can point them at a local server.
var (
	NodeDist    = "https://nodejs.org/dist"
	NPMRegistry = "https://registry.npmjs.org/"
	// systemNodeDirs are looked at after the PATH (the Proxmox installer puts Node here, and
	// the NCC service's PATH may not include it).
	systemNodeDirs = []string{"/usr/local/node/bin", "/usr/local/bin", "/usr/bin"}
)

const minNodeMajor = 20

// Install job states.
const (
	InstallRunning = "running"
	InstallDone    = "done"
	InstallFailed  = "failed"
)

// InstallPlan says exactly what installing a tool will do, for the person to confirm.
type InstallPlan struct {
	Kind         string `json:"kind"`
	Package      string `json:"package,omitempty"`
	Location     string `json:"location,omitempty"`
	Node         string `json:"node,omitempty"`
	DownloadNode bool   `json:"download_node,omitempty"`
	// Commands are the exact steps, in order, as they would be typed.
	Commands []string `json:"commands"`
	// Installed is the version NCC installed before, if any (installing again updates it).
	Installed  string `json:"installed,omitempty"`
	CanInstall bool   `json:"can_install"`
	Problem    string `json:"problem,omitempty"`
}

// InstallView is what the browser sees of an install.
type InstallView struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	State   string `json:"state"`
	Output  string `json:"output"`
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (s *Service) npmDir() string  { return filepath.Join(s.ToolsDir, "npm") }
func (s *Service) nodeDir() string { return filepath.Join(s.ToolsDir, "node") }

// ncBin is where NCC's own install of a tool puts its command.
func (s *Service) ncBin(k *Kind) string {
	if s.ToolsDir == "" || k.Binary == "" {
		return ""
	}
	return filepath.Join(s.npmDir(), "node_modules", ".bin", k.Binary)
}

// BinaryPath finds a provider's tool: the path set in its settings, NCC's own install, or the
// PATH, in that order. The error says how to install it.
func (s *Service) BinaryPath(k *Kind, st Settings) (string, error) {
	if st.Binary != "" {
		p, err := exec.LookPath(st.Binary)
		if err != nil {
			return "", fmt.Errorf("%s was not found on the NCC server", st.Binary)
		}
		return p, nil
	}
	if b := s.ncBin(k); b != "" {
		if fi, err := os.Stat(b); err == nil && !fi.IsDir() {
			return b, nil
		}
	}
	p, err := exec.LookPath(k.Binary)
	if err != nil {
		if s.ToolsDir != "" && k.npmPackage != "" {
			return "", fmt.Errorf("%s is not installed on the NCC server; use Install", k.Binary)
		}
		return "", fmt.Errorf("%s is not installed on the NCC server (%s)", k.Binary, k.Install)
	}
	return p, nil
}

// InstalledVersion is the version of NCC's own install of a tool, or "".
func (s *Service) InstalledVersion(k *Kind) string {
	if s.ToolsDir == "" || k.npmPackage == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(s.npmDir(), "node_modules", filepath.FromSlash(k.npmPackage), "package.json"))
	if err != nil {
		return ""
	}
	var p struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(b, &p) != nil {
		return ""
	}
	return p.Version
}

var nodeVerRe = regexp.MustCompile(`^v(\d+)\.\d+\.\d+`)

// nodeVersion runs node --version and returns it with its major number.
func nodeVersion(bin string) (string, int) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--version").Output()
	if err != nil {
		return "", 0
	}
	v := strings.TrimSpace(string(out))
	m := nodeVerRe.FindStringSubmatch(v)
	if m == nil {
		return "", 0
	}
	n, _ := strconv.Atoi(m[1])
	return v, n
}

// findNode returns a usable Node.js (version 20 or newer) and its version: NCC's own copy
// first, then the PATH, then the usual install folders. "" when there is none.
func (s *Service) findNode() (string, string) {
	cands := []string{}
	if s.ToolsDir != "" {
		cands = append(cands, filepath.Join(s.nodeDir(), "bin", "node"))
	}
	if p, err := exec.LookPath("node"); err == nil {
		cands = append(cands, p)
	}
	for _, d := range systemNodeDirs {
		cands = append(cands, filepath.Join(d, "node"))
	}
	seen := map[string]bool{}
	for _, c := range cands {
		if seen[c] {
			continue
		}
		seen[c] = true
		if fi, err := os.Stat(c); err != nil || fi.IsDir() {
			continue
		}
		if v, major := nodeVersion(c); major >= minNodeMajor {
			// npm sits next to the real node, not next to a link to it
			if r, err := filepath.EvalSymlinks(c); err == nil {
				c = r
			}
			return c, v
		}
	}
	return "", ""
}

// toolPath is the PATH tools run with: NCC's installed tools and the Node.js they need,
// before NCC's own PATH (the npm tools start with "#!/usr/bin/env node").
func (s *Service) toolPath() string {
	parts := []string{}
	if s.ToolsDir != "" {
		parts = append(parts, filepath.Join(s.npmDir(), "node_modules", ".bin"))
	}
	if n, _ := s.findNode(); n != "" {
		parts = append(parts, filepath.Dir(n))
	}
	if p := os.Getenv("PATH"); p != "" {
		parts = append(parts, p)
	} else {
		parts = append(parts, "/usr/local/bin:/usr/bin:/bin")
	}
	return strings.Join(parts, string(os.PathListSeparator))
}

// nodePlatform is the nodejs.org file name part for this machine, or "" when NCC can't
// download Node.js for it.
func nodePlatform() string {
	arch := map[string]string{"amd64": "x64", "arm64": "arm64"}[runtime.GOARCH]
	if arch == "" || (runtime.GOOS != "linux" && runtime.GOOS != "darwin") {
		return ""
	}
	return runtime.GOOS + "-" + arch
}

// CanInstall reports whether NCC can install a provider's tool itself.
func (s *Service) CanInstall(k *Kind) bool {
	return s.ToolsDir != "" && k.npmPackage != "" && !k.HTTP && runtime.GOOS != "windows"
}

// PlanInstall says what installing a provider's tool would do.
func (s *Service) PlanInstall(kind string) (InstallPlan, error) {
	k, err := KindByID(kind)
	if err != nil {
		return InstallPlan{}, err
	}
	p := InstallPlan{Kind: k.ID, Package: k.npmPackage, Commands: []string{}}
	switch {
	case k.HTTP:
		p.Problem = k.Label + " runs as its own service, not inside NCC. Install it from " + k.Install + " and set its address."
		return p, nil
	case k.npmPackage == "":
		p.Problem = "NCC can't install " + k.Label + " itself: " + k.Install
		return p, nil
	case s.ToolsDir == "":
		p.Problem = "installing from NCC is off because NCC has no data folder for tools; run " + k.Install + " on the server"
		return p, nil
	case runtime.GOOS == "windows":
		p.Problem = "installing from NCC is not supported on Windows; run " + k.Install + " on the server"
		return p, nil
	}
	p.Location = s.npmDir()
	p.Installed = s.InstalledVersion(k)
	node, ver := s.findNode()
	npm := ""
	if node != "" {
		p.Node = "Node.js " + ver + " at " + node
		npm = filepath.Join(filepath.Dir(node), "npm")
	} else {
		plat := nodePlatform()
		if plat == "" {
			p.Problem = "there is no Node.js " + strconv.Itoa(minNodeMajor) + "+ on the server and NCC can't download one for " + runtime.GOOS + "/" + runtime.GOARCH
			return p, nil
		}
		p.DownloadNode = true
		p.Node = "Node.js LTS for " + plat + ", downloaded from " + NodeDist + " into " + s.nodeDir()
		p.Commands = append(p.Commands,
			fmt.Sprintf("download %s/<latest LTS>/node-<version>-%s.tar.gz", NodeDist, plat),
			fmt.Sprintf("check its SHA-256 against %s/<latest LTS>/SHASUMS256.txt", NodeDist),
			"unpack it into "+s.nodeDir())
		npm = filepath.Join(s.nodeDir(), "bin", "npm")
	}
	p.Commands = append(p.Commands, strings.Join(npmArgs(npm, s.npmDir(), k.npmPackage), " "),
		filepath.Join(s.npmDir(), "node_modules", ".bin", k.Binary)+" --version")
	p.CanInstall = true
	return p, nil
}

func npmArgs(npm, prefix, pkg string) []string {
	return []string{npm, "install", "--prefix", prefix, "--registry=" + NPMRegistry,
		"--no-fund", "--no-audit", "--omit=dev", pkg + "@latest"}
}

// Installs keeps the installs in progress. One install runs at a time.
type Installs struct {
	Service *Service
	mu      sync.Mutex
	byID    map[string]*installJob
	running bool
}

type installJob struct {
	mu      sync.Mutex
	view    InstallView
	out     bytes.Buffer
	started time.Time
}

func (j *installJob) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.out.Len() < 512<<10 {
		j.out.Write(p)
	}
	return len(p), nil
}

func (j *installJob) logf(format string, a ...any) {
	fmt.Fprintf(j, "$ "+format+"\n", a...)
}

func (j *installJob) snapshot() InstallView {
	j.mu.Lock()
	defer j.mu.Unlock()
	v := j.view
	v.Output = stripANSI(j.out.String())
	if len(v.Output) > 32<<10 {
		v.Output = v.Output[len(v.Output)-32<<10:]
	}
	return v
}

const installTimeout = 15 * time.Minute

// ErrInstallBusy is returned while another install runs.
var ErrInstallBusy = errors.New("another install is running; wait for it to finish")

// Start installs (or updates) a provider's tool in the background.
func (m *Installs) Start(kind string) (InstallView, error) {
	s := m.Service
	plan, err := s.PlanInstall(kind)
	if err != nil {
		return InstallView{}, err
	}
	if !plan.CanInstall {
		return InstallView{}, errors.New(plan.Problem)
	}
	k, _ := KindByID(kind)
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return InstallView{}, ErrInstallBusy
	}
	if m.byID == nil {
		m.byID = map[string]*installJob{}
	}
	for id, o := range m.byID {
		if time.Since(o.started) > installTimeout+time.Hour {
			delete(m.byID, id)
		}
	}
	j := &installJob{view: InstallView{ID: newID(), Kind: kind, State: InstallRunning}, started: time.Now()}
	m.byID[j.view.ID] = j
	m.running = true
	m.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), installTimeout)
		defer cancel()
		ver, err := s.install(ctx, k, j)
		j.mu.Lock()
		if err != nil {
			j.view.State, j.view.Error = InstallFailed, err.Error()
			fmt.Fprintf(&j.out, "\nFailed: %s\n", err)
		} else {
			j.view.State, j.view.Version = InstallDone, ver
			fmt.Fprintf(&j.out, "\nInstalled %s %s\n", k.Binary, ver)
		}
		j.mu.Unlock()
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()
	return j.snapshot(), nil
}

// View returns an install's state and output so far.
func (m *Installs) View(id string) (InstallView, error) {
	m.mu.Lock()
	j, ok := m.byID[id]
	m.mu.Unlock()
	if !ok {
		return InstallView{}, errors.New("no such install")
	}
	return j.snapshot(), nil
}

func (s *Service) install(ctx context.Context, k *Kind, j *installJob) (string, error) {
	if err := os.MkdirAll(s.ToolsDir, 0o750); err != nil {
		return "", err
	}
	node, ver := s.findNode()
	if node == "" {
		var err error
		if node, err = s.downloadNode(ctx, j); err != nil {
			return "", err
		}
		if ver, _ = nodeVersion(node); ver == "" {
			return "", errors.New("the downloaded Node.js does not run on this server (a minimal container image has no system libraries for it); install the tool on a server or VM instead")
		}
	}
	fmt.Fprintf(j, "Using Node.js %s at %s\n", ver, node)
	npm := filepath.Join(filepath.Dir(node), "npm")
	if _, err := os.Stat(npm); err != nil {
		return "", fmt.Errorf("npm was not found next to %s", node)
	}
	if err := os.MkdirAll(s.npmDir(), 0o750); err != nil {
		return "", err
	}
	// a package.json keeps npm from looking for one in a parent folder
	pj := filepath.Join(s.npmDir(), "package.json")
	if _, err := os.Stat(pj); err != nil {
		if err := os.WriteFile(pj, []byte(`{"name":"ncc-ai-tools","private":true}`+"\n"), 0o640); err != nil {
			return "", err
		}
	}
	args := npmArgs(npm, s.npmDir(), k.npmPackage)
	j.logf("%s", strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = s.npmDir()
	cmd.Env = s.installEnv(filepath.Dir(node))
	cmd.Stdout, cmd.Stderr = j, j
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", errors.New("the install took too long")
		}
		return "", fmt.Errorf("npm install failed: %v", err)
	}
	bin := s.ncBin(k)
	if _, err := os.Stat(bin); err != nil {
		return "", fmt.Errorf("npm finished but %s is missing", bin)
	}
	j.logf("%s --version", bin)
	vctx, vcancel := context.WithTimeout(ctx, time.Minute)
	defer vcancel()
	vc := exec.CommandContext(vctx, bin, "--version")
	vc.Dir = s.ToolsDir
	vc.Env = s.installEnv(filepath.Dir(node))
	out, err := vc.CombinedOutput()
	_, _ = j.Write(out)
	if err != nil {
		return "", fmt.Errorf("%s was installed but does not run: %v", k.Binary, err)
	}
	v := strings.TrimSpace(stripANSI(string(out)))
	if i := strings.IndexByte(v, '\n'); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		v = s.InstalledVersion(k)
	}
	return v, nil
}

// installEnv is npm's environment: a home, cache and config inside the tools folder, and
// only the proxy and certificate settings from NCC's own environment.
func (s *Service) installEnv(nodeBin string) []string {
	home := filepath.Join(s.ToolsDir, "home")
	_ = os.MkdirAll(home, 0o750)
	env := []string{
		"HOME=" + home,
		"PATH=" + nodeBin + string(os.PathListSeparator) + firstOf(os.Getenv("PATH"), "/usr/local/bin:/usr/bin:/bin"),
		"npm_config_cache=" + filepath.Join(s.ToolsDir, "npm-cache"),
		"npm_config_userconfig=" + filepath.Join(home, ".npmrc"),
		"npm_config_update_notifier=false",
		"npm_config_loglevel=notice",
		"NO_COLOR=1",
		"LANG=C.UTF-8",
	}
	for _, k := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy", "TZ", "TMPDIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func (s *Service) httpClient() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return http.DefaultClient
}

func (s *Service) fetch(ctx context.Context, url string, w io.Writer, max int64) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, max+1))
	if err == nil && n > max {
		err = fmt.Errorf("%s is larger than expected", url)
	}
	return err
}

// downloadNode puts the latest Node.js LTS from nodejs.org into the tools folder, after
// checking it against the SHA-256 nodejs.org publishes for it.
func (s *Service) downloadNode(ctx context.Context, j *installJob) (string, error) {
	plat := nodePlatform()
	if plat == "" {
		return "", fmt.Errorf("NCC can't download Node.js for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	j.logf("download %s/index.json", NodeDist)
	var idx bytes.Buffer
	if err := s.fetch(ctx, NodeDist+"/index.json", &idx, 8<<20); err != nil {
		return "", err
	}
	var rels []struct {
		Version string          `json:"version"`
		LTS     json.RawMessage `json:"lts"`
		Files   []string        `json:"files"`
	}
	if err := json.Unmarshal(idx.Bytes(), &rels); err != nil {
		return "", fmt.Errorf("could not read the Node.js release list: %v", err)
	}
	version := ""
	for _, r := range rels {
		lts := strings.TrimSpace(string(r.LTS))
		if lts == "" || lts == "false" || lts == "null" || !nodeVerRe.MatchString(r.Version) {
			continue
		}
		version = r.Version
		break
	}
	if version == "" {
		return "", errors.New("no Node.js LTS release found")
	}
	file := "node-" + version + "-" + plat + ".tar.gz"
	base := NodeDist + "/" + version + "/"
	j.logf("download %sSHASUMS256.txt", base)
	var sums bytes.Buffer
	if err := s.fetch(ctx, base+"SHASUMS256.txt", &sums, 1<<20); err != nil {
		return "", err
	}
	want := ""
	sc := bufio.NewScanner(&sums)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && f[1] == file {
			want = strings.ToLower(f[0])
		}
	}
	if len(want) != 64 {
		return "", fmt.Errorf("SHASUMS256.txt has no checksum for %s", file)
	}
	tmp, err := os.CreateTemp(s.ToolsDir, "node-*.tar.gz")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	j.logf("download %s%s", base, file)
	h := sha256.New()
	if err := s.fetch(ctx, base+file, io.MultiWriter(tmp, h), 512<<20); err != nil {
		return "", err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return "", fmt.Errorf("the Node.js download does not match its published SHA-256 (got %s, want %s); nothing was installed", got, want)
	}
	fmt.Fprintf(j, "SHA-256 %s matches SHASUMS256.txt\n", got)
	if _, err := tmp.Seek(0, 0); err != nil {
		return "", err
	}
	stage := s.nodeDir() + ".new"
	os.RemoveAll(stage)
	j.logf("unpack %s into %s", file, s.nodeDir())
	if err := untarStrip(tmp, stage); err != nil {
		os.RemoveAll(stage)
		return "", fmt.Errorf("could not unpack Node.js: %v", err)
	}
	old := s.nodeDir() + ".old"
	os.RemoveAll(old)
	_ = os.Rename(s.nodeDir(), old)
	if err := os.Rename(stage, s.nodeDir()); err != nil {
		_ = os.Rename(old, s.nodeDir())
		return "", err
	}
	os.RemoveAll(old)
	return filepath.Join(s.nodeDir(), "bin", "node"), nil
}

// untarStrip unpacks a .tar.gz into dest, dropping the first path element (the
// node-vX-platform folder). Entries and links that would land outside dest are refused.
func untarStrip(r io.Reader, dest string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	realDest, err := filepath.EvalSymlinks(dest)
	if err != nil {
		return err
	}
	within := func(root, p string) bool {
		rel, err := filepath.Rel(root, p)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	inside := func(p string) bool { return within(dest, p) }
	// the folder an entry is written into must really be inside dest (not reached through a
	// link the archive made earlier)
	parentInside := func(p string) error {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		rp, err := filepath.EvalSymlinks(filepath.Dir(p))
		if err != nil {
			return err
		}
		if !within(realDest, rp) {
			return fmt.Errorf("%s points outside the folder", p)
		}
		return nil
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.FromSlash(h.Name)
		if i := strings.IndexRune(name, filepath.Separator); i >= 0 {
			name = name[i+1:]
		} else {
			continue // the top folder itself
		}
		if name == "" {
			continue
		}
		target := filepath.Join(dest, name)
		if !inside(target) {
			return fmt.Errorf("%s points outside the folder", h.Name)
		}
		if err := parentInside(target); err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			_ = os.Remove(target)
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(h.Mode)&0o755)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, io.LimitReader(tr, h.Size)); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if filepath.IsAbs(h.Linkname) || !inside(filepath.Join(filepath.Dir(target), h.Linkname)) {
				return fmt.Errorf("link %s points outside the folder", h.Name)
			}
			_ = os.Remove(target)
			if err := os.Symlink(h.Linkname, target); err != nil {
				return err
			}
		default:
			// hard links, devices and the like are not in Node.js releases
		}
	}
}
