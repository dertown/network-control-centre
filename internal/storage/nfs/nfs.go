// Package nfs is the NCC storage provider for NFS servers. It asks the server's portmapper
// which NFS versions it offers and asks mountd for the export list (what "showmount -e"
// prints), with the hosts or networks each export allows. It needs no login, only reads,
// and does not mount anything. NFSv4-only servers with no mountd show as reachable with no
// export list.
package nfs

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/dertown/network-control-centre/internal/catalog"
	"io"
	"math/rand/v2"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/storage"
)

func init() {
	storage.Register(Provider{}, catalog.Vendor{
		Label: "NFS server", Groups: []string{catalog.GroupStorage}, Order: 40,
		Summary:     "Any NFS server: versions and export list.",
		Help:        "NCC asks the server's portmapper and mountd for its NFS versions and export list (like showmount -e). No login is needed and nothing is mounted.",
		NameDefault: "nfs", AddressKind: catalog.AddressHost, AddressDefault: "192.168.1.80", NoLogin: true,
		Fields: []catalog.Field{},
	})
}

// Provider implements storage.Provider for NFS servers.
type Provider struct{}

// Kind implements storage.Provider.
func (Provider) Kind() string { return "nfs" }

const (
	progPortmap = 100000
	progNFS     = 100003
	progMount   = 100005
)

// Host returns the server host from "nfs://server", "server" or "server:/export".
func Host(address string) string {
	a := strings.TrimSpace(address)
	if strings.Contains(a, "://") {
		if u, err := url.Parse(a); err == nil {
			return u.Hostname()
		}
		return ""
	}
	a, _, _ = strings.Cut(a, ":/")
	if h, _, err := net.SplitHostPort(a); err == nil {
		return h
	}
	return a
}

// rpc is a tiny ONC RPC (RFC 5531) client over TCP with AUTH_NONE.
type rpc struct {
	c net.Conn
	r *bufio.Reader
}

func dialRPC(ctx context.Context, host string, port int) (*rpc, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(15 * time.Second)
	}
	_ = c.SetDeadline(dl)
	return &rpc{c: c, r: bufio.NewReader(c)}, nil
}

func (r *rpc) close() { _ = r.c.Close() }

func (r *rpc) call(prog, vers, proc uint32, args []byte) ([]byte, error) {
	xid := rand.Uint32()
	var b []byte
	b = be(b, xid, 0, 2, prog, vers, proc, 0, 0, 0, 0)
	b = append(b, args...)
	frame := be(nil, 0x80000000|uint32(len(b)))
	if _, err := r.c.Write(append(frame, b...)); err != nil {
		return nil, err
	}
	var reply []byte
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(r.r, hdr[:]); err != nil {
			return nil, err
		}
		h := binary.BigEndian.Uint32(hdr[:])
		n := h & 0x7fffffff
		if n > 4<<20 {
			return nil, errors.New("rpc: reply too large")
		}
		part := make([]byte, n)
		if _, err := io.ReadFull(r.r, part); err != nil {
			return nil, err
		}
		reply = append(reply, part...)
		if h&0x80000000 != 0 {
			break
		}
	}
	d := &xdr{b: reply}
	if d.u32() != xid || d.u32() != 1 {
		return nil, errors.New("rpc: unexpected reply")
	}
	if d.u32() != 0 { // MSG_DENIED
		return nil, errors.New("rpc: call denied")
	}
	d.u32()    // verifier flavour
	d.opaque() // verifier body
	switch d.u32() {
	case 0:
	case 1:
		return nil, errors.New("rpc: program unavailable")
	case 2:
		return nil, errors.New("rpc: program version unavailable")
	case 3:
		return nil, errors.New("rpc: procedure unavailable")
	default:
		return nil, errors.New("rpc: call failed")
	}
	if d.err != nil {
		return nil, d.err
	}
	return d.b[d.p:], nil
}

func be(b []byte, vs ...uint32) []byte {
	for _, v := range vs {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	return b
}

type xdr struct {
	b   []byte
	p   int
	err error
}

func (x *xdr) u32() uint32 {
	if x.err != nil || x.p+4 > len(x.b) {
		x.err = io.ErrUnexpectedEOF
		return 0
	}
	v := binary.BigEndian.Uint32(x.b[x.p:])
	x.p += 4
	return v
}

func (x *xdr) opaque() []byte {
	n := int(x.u32())
	if x.err != nil || n < 0 || x.p+n > len(x.b) {
		x.err = io.ErrUnexpectedEOF
		return nil
	}
	v := x.b[x.p : x.p+n]
	x.p += (n + 3) &^ 3
	if x.p > len(x.b) {
		x.p = len(x.b)
	}
	return v
}

// Mapping is one program registered with the portmapper.
type Mapping struct{ Prog, Vers, Prot, Port uint32 }

// ParseDump decodes a PMAPPROC_DUMP reply.
func ParseDump(b []byte) ([]Mapping, error) {
	x := &xdr{b: b}
	var out []Mapping
	for x.u32() == 1 && x.err == nil {
		m := Mapping{Prog: x.u32(), Vers: x.u32(), Prot: x.u32(), Port: x.u32()}
		out = append(out, m)
	}
	return out, x.err
}

// Export is one entry of mountd's export list.
type Export struct {
	Dir    string
	Groups []string
}

// ParseExports decodes a MOUNTPROC3_EXPORT reply.
func ParseExports(b []byte) ([]Export, error) {
	x := &xdr{b: b}
	var out []Export
	for x.u32() == 1 && x.err == nil {
		e := Export{Dir: string(x.opaque())}
		for x.u32() == 1 && x.err == nil {
			e.Groups = append(e.Groups, string(x.opaque()))
		}
		out = append(out, e)
	}
	return out, x.err
}

// Collect implements storage.Provider.
func (Provider) Collect(ctx context.Context, t storage.Target, _ map[string]string) (*storage.Result, error) {
	host := Host(t.Address)
	if host == "" {
		return nil, fmt.Errorf("nfs: address must look like nfs://192.168.1.20, got %q", t.Address)
	}
	pm, err := dialRPC(ctx, host, 111)
	if err != nil {
		return nil, fmt.Errorf("nfs: the portmapper (port 111) did not answer: %w", err)
	}
	raw, err := pm.call(progPortmap, 2, 4, nil)
	pm.close()
	if err != nil {
		return nil, fmt.Errorf("nfs: portmapper: %w", err)
	}
	maps, err := ParseDump(raw)
	if err != nil {
		return nil, fmt.Errorf("nfs: portmapper: %w", err)
	}
	inv := &storage.Inventory{Target: t.Name, Kind: "nfs", TakenAt: time.Now().UTC(), Capabilities: []string{}}
	inv.System = storage.System{Name: t.Name, Vendor: "NFS server", CPUUsage: -1, Health: storage.HealthGood,
		NICs: []storage.NIC{{Name: "NFS", Up: true, IP: host}}}
	vers := map[uint32]bool{}
	mountPort := 0
	for _, m := range maps {
		if m.Prog == progNFS {
			vers[m.Vers] = true
		}
		if m.Prog == progMount && m.Vers == 3 && m.Prot == 6 {
			mountPort = int(m.Port)
		}
	}
	if len(vers) == 0 {
		inv.System.Health = storage.HealthCritical
		inv.Alerts = append(inv.Alerts, storage.Alert{Level: storage.HealthCritical, Subject: "NFS", Message: "The server runs a portmapper but no NFS service is registered."})
	}
	vs := make([]int, 0, len(vers))
	for v := range vers {
		vs = append(vs, int(v))
	}
	sort.Ints(vs)
	names := make([]string, len(vs))
	for i, v := range vs {
		names[i] = "v" + strconv.Itoa(v)
	}
	inv.System.OS = "NFS " + strings.Join(names, ", ")
	if mountPort == 0 {
		inv.Warnings = append(inv.Warnings, "mountd is not registered over TCP, so the export list can't be read (NFSv4-only servers have no export list).")
		inv.Finish()
		return &storage.Result{Inventory: inv}, nil
	}
	md, err := dialRPC(ctx, host, mountPort)
	if err != nil {
		return nil, fmt.Errorf("nfs: mountd (port %d): %w", mountPort, err)
	}
	defer md.close()
	raw, err = md.call(progMount, 3, 5, nil)
	if err != nil {
		return nil, fmt.Errorf("nfs: export list: %w", err)
	}
	exports, err := ParseExports(raw)
	if err != nil {
		return nil, fmt.Errorf("nfs: export list: %w", err)
	}
	for _, e := range exports {
		name := e.Dir
		if i := strings.LastIndex(strings.TrimRight(name, "/"), "/"); i >= 0 && len(name) > 1 {
			name = strings.TrimRight(name, "/")[i+1:]
		}
		clients := e.Groups
		if len(clients) == 0 {
			clients = []string{"everyone"}
		}
		inv.Shares = append(inv.Shares, storage.Share{Name: name, Path: e.Dir, Protocols: []string{"NFS"}, Clients: clients})
		for _, c := range clients {
			if c == "everyone" || c == "*" || c == "0.0.0.0/0" {
				inv.Alerts = append(inv.Alerts, storage.Alert{Level: storage.HealthWarning, Subject: e.Dir,
					Message: "Exported to every host. Limit it to your LAN or the machines that need it."})
				break
			}
		}
	}
	inv.Finish()
	return &storage.Result{Inventory: inv}, nil
}
