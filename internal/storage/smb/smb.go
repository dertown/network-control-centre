// Package smb is the NCC storage provider for any SMB file server: Windows, Samba, a NAS
// NCC has no API driver for, or a router's USB share. It signs in over SMB 2/3 (NTLM),
// lists the shares, and reads the size and free space of each one. It can also create a
// folder in a share.
package smb

import (
	"context"
	"errors"
	"fmt"
	"github.com/dertown/network-control-centre/internal/catalog"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"

	"github.com/dertown/network-control-centre/internal/storage"
)

func init() {
	storage.Register(Provider{}, catalog.Vendor{
		Label: "SMB file server", Groups: []string{catalog.GroupStorage}, Order: 30,
		Summary: "Windows, Samba, or any SMB 2/3 share: size and free space.",
		Help: "Any SMB 2/3 server: Windows, Samba, a NAS without an API driver or a router's USB share. NCC signs in, lists the shares " +
			"and reads each one's size and free space. A read-only account is enough to monitor; creating folders needs write access.",
		NameDefault: "fileserver", AddressKind: catalog.AddressHost, AddressDefault: "192.168.1.70",
		Fields: append(catalog.UserPassword("", nil),
			catalog.Field{Key: "domain", Label: "Domain (optional)", Type: catalog.Text, Store: catalog.StoreSecret, Placeholder: "WORKGROUP"}),
	})
}

// Provider implements storage.Provider and storage.Controller for SMB servers.
type Provider struct{}

// Kind implements storage.Provider.
func (Provider) Kind() string { return "smb" }

// HostPort turns "smb://server", "\\server", "server" or "server:4445" into host:port.
func HostPort(address string) (string, error) {
	a := strings.TrimSpace(address)
	a = strings.TrimPrefix(strings.ReplaceAll(a, `\`, "/"), "//")
	if strings.Contains(a, "://") {
		u, err := url.Parse(a)
		if err != nil || u.Hostname() == "" {
			return "", fmt.Errorf("smb: address must look like smb://192.168.1.20 or 192.168.1.20, got %q", address)
		}
		port := u.Port()
		if port == "" {
			port = "445"
		}
		return net.JoinHostPort(u.Hostname(), port), nil
	}
	a, _, _ = strings.Cut(a, "/")
	if a == "" {
		return "", fmt.Errorf("smb: address must look like smb://192.168.1.20 or 192.168.1.20, got %q", address)
	}
	if _, _, err := net.SplitHostPort(a); err == nil {
		return a, nil
	}
	return net.JoinHostPort(a, "445"), nil
}

type conn struct {
	tcp  net.Conn
	sess *smb2.Session
}

func (c *conn) close() {
	if c.sess != nil {
		_ = c.sess.Logoff()
	}
	_ = c.tcp.Close()
}

func dial(ctx context.Context, address string, creds map[string]string) (*conn, error) {
	hp, err := HostPort(address)
	if err != nil {
		return nil, err
	}
	user := strings.TrimSpace(creds["username"])
	domain := strings.TrimSpace(creds["domain"])
	if d, u, ok := strings.Cut(user, `\`); ok && domain == "" {
		domain, user = d, u
	}
	if user == "" {
		return nil, errors.New("smb: give a username and password (a read-only account is enough for monitoring)")
	}
	var d net.Dialer
	tcp, err := d.DialContext(ctx, "tcp", hp)
	if err != nil {
		return nil, fmt.Errorf("smb: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = tcp.SetDeadline(dl)
	} else {
		_ = tcp.SetDeadline(time.Now().Add(60 * time.Second))
	}
	sd := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: user, Password: creds["password"], Domain: domain}}
	sess, err := sd.DialContext(ctx, tcp)
	if err != nil {
		_ = tcp.Close()
		if strings.Contains(strings.ToLower(err.Error()), "logon failure") {
			return nil, errors.New("smb: the server refused the username or password")
		}
		return nil, fmt.Errorf("smb: %w", err)
	}
	return &conn{tcp: tcp, sess: sess}, nil
}

// Collect implements storage.Provider.
func (Provider) Collect(ctx context.Context, t storage.Target, creds map[string]string) (*storage.Result, error) {
	c, err := dial(ctx, t.Address, creds)
	if err != nil {
		return nil, err
	}
	defer c.close()
	host, _, _ := net.SplitHostPort(c.tcp.RemoteAddr().String())
	inv := &storage.Inventory{Target: t.Name, Kind: "smb", TakenAt: time.Now().UTC(), Capabilities: []string{storage.CapFolderCreate}}
	inv.System = storage.System{Name: t.Name, Vendor: "SMB file server", CPUUsage: -1, Health: storage.HealthGood}
	inv.System.NICs = []storage.NIC{{Name: "SMB", Up: true, IP: host}}

	names, err := c.sess.WithContext(ctx).ListSharenames()
	if err != nil {
		return nil, fmt.Errorf("smb: list shares: %w", err)
	}
	type key struct{ total, free int64 }
	vols := map[key]int{}
	var extra []int
	for _, n := range names {
		sh := storage.Share{Name: n, Path: `\\` + host + `\` + n, Protocols: []string{"SMB"}, Hidden: strings.HasSuffix(n, "$")}
		if strings.EqualFold(n, "IPC$") || strings.EqualFold(n, "print$") {
			continue
		}
		if !sh.Hidden {
			if m, err := c.sess.WithContext(ctx).Mount(n); err == nil {
				if fi, err := m.Statfs("."); err == nil {
					unit := int64(fi.BlockSize() * fi.FragmentSize())
					sh.Total = unit * int64(fi.TotalBlockCount())
					sh.Free = unit * int64(fi.AvailableBlockCount())
					sh.Used = sh.Total - unit*int64(fi.FreeBlockCount())
				}
				_ = m.Umount()
			} else {
				sh.Comment = "Can't open: " + shortErr(err)
			}
		}
		inv.Shares = append(inv.Shares, sh)
		if sh.Total > 0 {
			k := key{sh.Total, sh.Free}
			i, ok := vols[k]
			if !ok {
				i = len(inv.Volumes)
				vols[k] = i
				inv.Volumes = append(inv.Volumes, storage.Volume{ID: n, Name: n, Status: "online", Health: storage.HealthGood, Total: sh.Total, Used: sh.Total - sh.Free})
				extra = append(extra, 0)
			} else {
				extra[i]++
			}
			inv.Shares[len(inv.Shares)-1].Volume = inv.Volumes[i].ID
		}
	}
	// shares on the same disk report the same size and free space: show that disk once
	for i, n := range extra {
		if n > 0 {
			inv.Volumes[i].Name = fmt.Sprintf("%s (+%d share%s)", inv.Volumes[i].ID, n, plural(n))
		}
	}
	inv.Finish()
	return &storage.Result{Inventory: inv}, nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	return s
}

// CreateFolder implements storage.Controller.
func (Provider) CreateFolder(ctx context.Context, t storage.Target, creds map[string]string, share, path string) error {
	if err := storage.ValidFolder(path); err != nil {
		return err
	}
	c, err := dial(ctx, t.Address, creds)
	if err != nil {
		return err
	}
	defer c.close()
	m, err := c.sess.WithContext(ctx).Mount(share)
	if err != nil {
		return fmt.Errorf("smb: open %s: %w", share, err)
	}
	defer m.Umount()
	p := strings.ReplaceAll(strings.Trim(path, "/"), "/", `\`)
	if _, err := m.Stat(p); err == nil {
		return fmt.Errorf("smb: %s already exists in %s", path, share)
	}
	if err := m.MkdirAll(p, 0o755); err != nil {
		return fmt.Errorf("smb: %w", err)
	}
	return nil
}

// Power implements storage.Controller; SMB has no power control.
func (Provider) Power(context.Context, storage.Target, map[string]string, string) error {
	return storage.ErrUnsupported
}

// CreateShare implements storage.Controller; SMB clients can't create shares.
func (Provider) CreateShare(context.Context, storage.Target, map[string]string, storage.ShareSpec) error {
	return storage.ErrUnsupported
}

// CreateSnapshot implements storage.Controller.
func (Provider) CreateSnapshot(context.Context, storage.Target, map[string]string, string, string) error {
	return storage.ErrUnsupported
}

// DeleteSnapshot implements storage.Controller.
func (Provider) DeleteSnapshot(context.Context, storage.Target, map[string]string, string, string) error {
	return storage.ErrUnsupported
}
