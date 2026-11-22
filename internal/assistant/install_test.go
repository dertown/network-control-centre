package assistant

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeNode makes a folder with a pretend node (printing version) and npm. The npm installs a
// pretend package: its package.json and a command in node_modules/.bin that prints its
// version and checks it was given node on the PATH.
func fakeNode(t *testing.T, version string) string {
	d := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(d, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("node", "echo "+version+"\n")
	write("npm", `echo "npm $*" >&2
prefix=""; pkg=""
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) prefix="$2"; shift ;;
    --registry=https://registry.npmjs.org/) reg=ok ;;
    -*) ;;
    install) ;;
    *) pkg="$1" ;;
  esac
  shift
done
[ "$reg" = ok ] || { echo "not the official registry" >&2; exit 3; }
case "$HOME" in "$prefix"*|*/ai-tools/home) ;; *) echo "HOME is $HOME" >&2; exit 4 ;; esac
name="${pkg%@latest}"
mkdir -p "$prefix/node_modules/$name" "$prefix/node_modules/.bin"
echo '{"name":"'"$name"'","version":"2.0.1"}' > "$prefix/node_modules/$name/package.json"
printf '#!/bin/sh\ncommand -v node >/dev/null || { echo no node; exit 5; }\necho "2.0.1 (pretend)"\n' > "$prefix/node_modules/.bin/claude"
chmod +x "$prefix/node_modules/.bin/claude"
echo "added 1 package"
`)
	return d
}

func waitInstall(t *testing.T, m *Installs, id string) InstallView {
	for i := 0; i < 200; i++ {
		v, err := m.View(id)
		if err != nil {
			t.Fatal(err)
		}
		if v.State != InstallRunning {
			return v
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("install did not finish")
	return InstallView{}
}

func TestInstallWithServerNode(t *testing.T) {
	s := newService(t)
	s.ToolsDir = filepath.Join(t.TempDir(), "ai-tools")
	nd := fakeNode(t, "v22.4.0")
	t.Setenv("PATH", nd+":/usr/bin:/bin")
	old := systemNodeDirs
	systemNodeDirs = nil
	defer func() { systemNodeDirs = old }()
	k, _ := KindByID(KindClaude)

	if _, err := s.BinaryPath(k, Settings{}); err == nil || !strings.Contains(err.Error(), "use Install") {
		t.Fatalf("before install: %v", err)
	}
	p, err := s.PlanInstall(KindClaude)
	if err != nil || !p.CanInstall || p.DownloadNode || len(p.Commands) != 2 {
		t.Fatalf("plan: %v %+v", err, p)
	}
	want := filepath.Join(nd, "npm") + " install --prefix " + s.npmDir() + " --registry=https://registry.npmjs.org/ --no-fund --no-audit --omit=dev @anthropic-ai/claude-code@latest"
	if p.Commands[0] != want || !strings.Contains(p.Node, "v22.4.0") {
		t.Fatalf("commands: %q, node %q", p.Commands, p.Node)
	}

	m := &Installs{Service: s}
	v, err := m.Start(KindClaude)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(KindClaude); err != ErrInstallBusy {
		t.Fatalf("second install at once: %v", err)
	}
	v = waitInstall(t, m, v.ID)
	if v.State != InstallDone || v.Version != "2.0.1 (pretend)" || !strings.Contains(v.Output, "added 1 package") {
		t.Fatalf("install: %+v", v)
	}
	bin, err := s.BinaryPath(k, Settings{})
	if err != nil || bin != s.ncBin(k) {
		t.Fatalf("binary: %s %v", bin, err)
	}
	if got := s.InstalledVersion(k); got != "2.0.1" {
		t.Fatalf("version: %q", got)
	}
	// the tool runs with node and NCC's tools on its PATH
	if path := s.toolPath(); !strings.HasPrefix(path, filepath.Join(s.npmDir(), "node_modules", ".bin")+":"+nd+":") {
		t.Fatalf("PATH: %s", path)
	}
	// a path set by hand still wins
	other := tool(t, "echo hi\n")
	if b, _ := s.BinaryPath(k, Settings{Binary: other}); b != other {
		t.Fatalf("binary setting ignored: %s", b)
	}

	// Ollama and a service without a tools folder can't install
	if p, _ := s.PlanInstall(KindOllama); p.CanInstall || p.Problem == "" {
		t.Fatalf("ollama: %+v", p)
	}
	s2 := &Service{}
	if p, _ := s2.PlanInstall(KindClaude); p.CanInstall {
		t.Fatalf("no tools folder: %+v", p)
	}
}

// nodeRelease builds a pretend Node.js release archive.
func nodeRelease(t *testing.T, top string, extra func(tw *tar.Writer)) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(h *tar.Header, body string) {
		h.Size = int64(len(body))
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(body))
	}
	add(&tar.Header{Name: top + "/", Typeflag: tar.TypeDir, Mode: 0o755}, "")
	add(&tar.Header{Name: top + "/bin/", Typeflag: tar.TypeDir, Mode: 0o755}, "")
	add(&tar.Header{Name: top + "/bin/node", Typeflag: tar.TypeReg, Mode: 0o755}, "#!/bin/sh\necho v22.11.0\n")
	add(&tar.Header{Name: top + "/lib/npm/npm-cli.js", Typeflag: tar.TypeReg, Mode: 0o755}, "#!/bin/sh\necho npm\n")
	add(&tar.Header{Name: top + "/bin/npm", Typeflag: tar.TypeSymlink, Linkname: "../lib/npm/npm-cli.js"}, "")
	if extra != nil {
		extra(tw)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func nodeDist(t *testing.T, archive []byte, sum string) *httptest.Server {
	plat := nodePlatform()
	file := "node-v22.11.0-" + plat + ".tar.gz"
	if sum == "" {
		h := sha256.Sum256(archive)
		sum = hex.EncodeToString(h[:])
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.json":
			fmt.Fprint(w, `[{"version":"v23.1.0","lts":false},{"version":"v22.11.0","lts":"Jod"},{"version":"v20.18.0","lts":"Iron"}]`)
		case "/v22.11.0/SHASUMS256.txt":
			fmt.Fprintf(w, "%s  node-v22.11.0-other.tar.gz\n%s  %s\n", strings.Repeat("0", 64), sum, file)
		case "/v22.11.0/" + file:
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDownloadNode(t *testing.T) {
	if nodePlatform() == "" {
		t.Skip("no Node.js download for this platform")
	}
	archive := nodeRelease(t, "node-v22.11.0-x", nil)
	old := NodeDist
	defer func() { NodeDist = old }()

	// a download that doesn't match its checksum is refused, and nothing is unpacked
	s := newService(t)
	s.ToolsDir = t.TempDir()
	NodeDist = nodeDist(t, archive, strings.Repeat("ab", 32)).URL
	j := &installJob{}
	if _, err := s.downloadNode(t.Context(), j); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("bad checksum: %v", err)
	}
	if _, err := os.Stat(s.nodeDir()); !os.IsNotExist(err) {
		t.Fatalf("node folder made after a bad download: %v", err)
	}

	NodeDist = nodeDist(t, archive, "").URL
	j = &installJob{}
	node, err := s.downloadNode(t.Context(), j)
	if err != nil {
		t.Fatalf("%v\n%s", err, j.out.String())
	}
	if node != filepath.Join(s.nodeDir(), "bin", "node") {
		t.Fatalf("node: %s", node)
	}
	if v, major := nodeVersion(node); v != "v22.11.0" || major != 22 {
		t.Fatalf("version: %s", v)
	}
	if target, err := os.Readlink(filepath.Join(s.nodeDir(), "bin", "npm")); err != nil || target != "../lib/npm/npm-cli.js" {
		t.Fatalf("npm link: %s %v", target, err)
	}
	if !strings.Contains(j.out.String(), "matches SHASUMS256.txt") {
		t.Fatalf("log: %s", j.out.String())
	}

	// the plan says it will download Node.js when there is none
	t.Setenv("PATH", "/nonexistent")
	oldDirs := systemNodeDirs
	systemNodeDirs = nil
	defer func() { systemNodeDirs = oldDirs }()
	s2 := newService(t)
	s2.ToolsDir = t.TempDir()
	p, _ := s2.PlanInstall(KindCodex)
	if !p.CanInstall || !p.DownloadNode || len(p.Commands) != 5 || !strings.Contains(p.Commands[1], "SHASUMS256.txt") {
		t.Fatalf("plan: %+v", p)
	}
}

func TestUntarRefusesEscapes(t *testing.T) {
	for name, extra := range map[string]func(tw *tar.Writer){
		"dot-dot": func(tw *tar.Writer) {
			_ = tw.WriteHeader(&tar.Header{Name: "top/../../evil", Typeflag: tar.TypeReg, Mode: 0o644})
		},
		"absolute link": func(tw *tar.Writer) {
			_ = tw.WriteHeader(&tar.Header{Name: "top/etc", Typeflag: tar.TypeSymlink, Linkname: "/etc"})
		},
		"link out": func(tw *tar.Writer) {
			_ = tw.WriteHeader(&tar.Header{Name: "top/up", Typeflag: tar.TypeSymlink, Linkname: "../../.."})
		},
	} {
		dest := filepath.Join(t.TempDir(), "out")
		err := untarStrip(bytes.NewReader(nodeRelease(t, "top", extra)), dest)
		if err == nil || !strings.Contains(err.Error(), "outside") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
