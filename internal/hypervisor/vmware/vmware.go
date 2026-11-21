// Package vmware is the NCC hypervisor provider for VMware vSphere: a vCenter Server
// or a standalone ESXi host. It reads hosts and virtual machines over the vSphere web
// services API (the same API the vSphere Client uses), so it works on free ESXi hosts
// that have no REST API as well as on vCenter.
//
// It only reads. A vCenter user with the Read-only role, or an ESXi local user with
// the Read-only role, is enough.
package vmware

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/vmware/govmomi/session"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"

	hv "github.com/dertown/network-control-centre/internal/hypervisor"
	"github.com/dertown/network-control-centre/internal/netutil"
)

func init() { hv.Register(Provider{}) }

// Provider implements hypervisor.Provider for vCenter and ESXi.
type Provider struct{}

// Kind implements hypervisor.Provider.
func (Provider) Kind() string { return "vmware" }

// Option keys.
const (
	OptTLS         = "tls"             // "pin" (default) or "verify"
	OptFingerprint = "tls_fingerprint" // pinned SHA-256 of the server's certificate
)

// ErrUnauthorized means the credentials were refused.
var ErrUnauthorized = errors.New("vmware: credentials refused")

func sdkURL(addr string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(addr), "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("vmware: address must be a URL like https://vcenter.lan or https://192.168.1.20, got %q", addr)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/sdk"
	}
	return u, nil
}

// conn is a logged-in connection. Close logs out.
type conn struct {
	vc     *vim25.Client
	sm     *session.Manager
	pin    *netutil.Pinner
	pinned bool // a fingerprint was already pinned or verification is on
}

func (c *conn) Close() {
	lctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.sm.Logout(lctx)
}

// newPin returns the fingerprint to save after a trust-on-first-use connection.
func (c *conn) newPin() map[string]string {
	if c == nil || c.pinned || c.pin.Seen() == "" {
		return nil
	}
	return map[string]string{OptFingerprint: c.pin.Seen()}
}

func connect(ctx context.Context, t hv.Target, creds map[string]string) (*conn, error) {
	u, err := sdkURL(t.Address)
	if err != nil {
		return nil, err
	}
	if creds["username"] == "" || creds["password"] == "" {
		return nil, errors.New("vmware: a username and password are required")
	}
	mode := t.Options[OptTLS]
	if mode == "" {
		mode = "pin"
	}
	cfg, pin := netutil.TLSConfig(mode, t.Options[OptFingerprint])
	sc := soap.NewClient(u, false)
	sc.DefaultTransport().TLSClientConfig = cfg
	sc.Timeout = 60 * time.Second
	c := &conn{pin: pin, pinned: mode != "pin" || t.Options[OptFingerprint] != ""}

	vc, err := vim25.NewClient(ctx, sc)
	if err != nil {
		return c, fmt.Errorf("vmware: %w", err)
	}
	c.vc = vc
	c.sm = session.NewManager(vc)
	if err := c.sm.Login(ctx, url.UserPassword(creds["username"], creds["password"])); err != nil {
		if invalidLogin(err) {
			return c, fmt.Errorf("%w: the username or password was refused (vCenter users look like ncc@vsphere.local)", ErrUnauthorized)
		}
		return c, fmt.Errorf("vmware: login: %w", err)
	}
	return c, nil
}

// Collect implements hypervisor.Provider.
func (Provider) Collect(ctx context.Context, t hv.Target, creds map[string]string) (*hv.Result, error) {
	c, err := connect(ctx, t, creds)
	res := &hv.Result{OptionUpdates: c.newPin()}
	if err != nil {
		return res, err
	}
	defer c.Close()
	vc := c.vc

	about := vc.ServiceContent.About
	inv := &hv.Inventory{Target: t.Name, Platform: "vmware", TakenAt: time.Now().UTC(), Version: about.FullName}
	res.Inventory = inv

	vm := view.NewManager(vc)
	hostView, err := vm.CreateContainerView(ctx, vc.ServiceContent.RootFolder, []string{"HostSystem"}, true)
	if err != nil {
		return res, fmt.Errorf("vmware: %w", err)
	}
	defer func() { _ = hostView.Destroy(context.Background()) }()
	var hosts []mo.HostSystem
	if err := hostView.Retrieve(ctx, []string{"HostSystem"}, []string{"summary"}, &hosts); err != nil {
		return res, fmt.Errorf("vmware: read hosts: %w", err)
	}
	hostName := map[string]string{}
	hostMHz := map[string]int32{}
	for _, h := range hosts {
		s := h.Summary
		name := s.Config.Name
		hostName[h.Reference().Value] = name
		out := hv.Host{
			Name: name, Online: s.Runtime != nil && s.Runtime.ConnectionState == types.HostSystemConnectionStateConnected &&
				s.Runtime.PowerState == types.HostSystemPowerStatePoweredOn,
			UptimeS: int64(s.QuickStats.Uptime), MemUsed: int64(s.QuickStats.OverallMemoryUsage) << 20,
			Version: s.Config.Product.FullName, Target: t.Name, Platform: "vmware",
		}
		if hw := s.Hardware; hw != nil {
			out.CPUs = int(hw.NumCpuThreads)
			out.MemBytes = hw.MemorySize
			out.Model = strings.TrimSpace(hw.Vendor + " " + hw.Model)
			hostMHz[h.Reference().Value] = hw.CpuMhz
			if total := float64(hw.CpuMhz) * float64(hw.NumCpuCores); total > 0 {
				out.CPUUsage = float64(s.QuickStats.OverallCpuUsage) / total
			}
		}
		inv.Hosts = append(inv.Hosts, out)
	}

	vmView, err := vm.CreateContainerView(ctx, vc.ServiceContent.RootFolder, []string{"VirtualMachine"}, true)
	if err != nil {
		return res, fmt.Errorf("vmware: %w", err)
	}
	defer func() { _ = vmView.Destroy(context.Background()) }()
	var vms []mo.VirtualMachine
	if err := vmView.Retrieve(ctx, []string{"VirtualMachine"}, []string{"summary", "guest.net", "config.annotation"}, &vms); err != nil {
		return res, fmt.Errorf("vmware: read virtual machines: %w", err)
	}
	for _, v := range vms {
		inv.VMs = append(inv.VMs, convert(t.Name, v, hostName, hostMHz))
	}
	inv.Sort()
	return res, nil
}

func convert(target string, v mo.VirtualMachine, hostName map[string]string, hostMHz map[string]int32) hv.VM {
	s := v.Summary
	out := hv.VM{
		ID: target + "/" + v.Reference().Value, Name: s.Config.Name, Type: "vm", Template: s.Config.Template,
		CPUs: int(s.Config.NumCpu), MemBytes: int64(s.Config.MemorySizeMB) << 20,
		MemUsed: int64(s.QuickStats.HostMemoryUsage) << 20, UptimeS: int64(s.QuickStats.UptimeSeconds),
		OS: s.Config.GuestFullName, Notes: strings.TrimSpace(s.Config.Annotation), Target: target, Platform: "vmware",
	}
	switch s.Runtime.PowerState {
	case types.VirtualMachinePowerStatePoweredOn:
		out.State = hv.StateRunning
	case types.VirtualMachinePowerStatePoweredOff:
		out.State = hv.StateStopped
	case types.VirtualMachinePowerStateSuspended:
		out.State = hv.StateSuspended
	default:
		out.State = hv.StateUnknown
	}
	if h := s.Runtime.Host; h != nil {
		out.Host = hostName[h.Value]
		if mhz := hostMHz[h.Value]; mhz > 0 && out.CPUs > 0 {
			out.CPUUsage = float64(s.QuickStats.OverallCpuUsage) / (float64(mhz) * float64(out.CPUs))
			if out.CPUUsage > 1 {
				out.CPUUsage = 1
			}
		}
	}
	if st := s.Storage; st != nil {
		out.DiskUsed = st.Committed
		out.DiskBytes = st.Committed + st.Uncommitted
	}
	if g := s.Guest; g != nil {
		if g.GuestFullName != "" {
			out.OS = g.GuestFullName
		}
		switch g.ToolsRunningStatus {
		case string(types.VirtualMachineToolsRunningStatusGuestToolsRunning):
			out.GuestTools = "VMware Tools running"
		case string(types.VirtualMachineToolsRunningStatusGuestToolsNotRunning):
			out.GuestTools = "VMware Tools not running"
		}
	}
	if v.Guest != nil {
		for _, n := range v.Guest.Net {
			for _, a := range n.IpAddress {
				out.IPs = appendIP(out.IPs, a)
			}
		}
	}
	if len(out.IPs) == 0 && s.Guest != nil && s.Guest.IpAddress != "" {
		out.IPs = appendIP(out.IPs, s.Guest.IpAddress)
	}
	if v.Config != nil {
		out.Notes = strings.TrimSpace(v.Config.Annotation)
	}
	if len(out.Notes) > 8192 {
		out.Notes = out.Notes[:8192]
	}
	return out
}

func appendIP(ips []string, s string) []string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return ips
	}
	for _, have := range ips {
		if have == ip.String() {
			return ips
		}
	}
	if ip.To4() != nil {
		n := 0
		for n < len(ips) && net.ParseIP(ips[n]).To4() != nil {
			n++
		}
		return append(ips[:n], append([]string{ip.String()}, ips[n:]...)...)
	}
	return append(ips, ip.String())
}

func invalidLogin(err error) bool {
	if soap.IsSoapFault(err) {
		switch soap.ToSoapFault(err).VimFault().(type) {
		case types.InvalidLogin, *types.InvalidLogin:
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "login failure") || strings.Contains(msg, "incorrect user name or password")
}
