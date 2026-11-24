// Package hypervisor defines the virtualisation platform interface (Proxmox VE,
// VMware vCenter/ESXi) and the virtual machine inventory NCC collects from them.
package hypervisor

import (
	"context"
	"fmt"
	"github.com/dertown/network-control-centre/internal/catalog"
	"sort"
	"sync"
	"time"
)

// VM states, normalised across platforms.
const (
	StateRunning   = "running"
	StateStopped   = "stopped"
	StateSuspended = "suspended"
	StateUnknown   = "unknown"
)

// VM is one virtual machine or container.
type VM struct {
	ID         string   `json:"id"`    // platform id, e.g. "pve/qemu/101" or "vm-42"
	Name       string   `json:"name"`  // display name
	Type       string   `json:"type"`  // "qemu", "lxc" or "vm"
	State      string   `json:"state"` // running, stopped, suspended, unknown
	Host       string   `json:"host"`  // Proxmox node or ESXi host
	Template   bool     `json:"template,omitempty"`
	CPUs       int      `json:"cpus"`           // vCPUs
	CPUUsage   float64  `json:"cpu_usage"`      // 0..1 of the allocated vCPUs, when known
	MemBytes   int64    `json:"mem_bytes"`      // configured memory
	MemUsed    int64    `json:"mem_used"`       // used memory, when known
	DiskBytes  int64    `json:"disk_bytes"`     // provisioned disk
	DiskUsed   int64    `json:"disk_used"`      // used disk, when known
	IPs        []string `json:"ips,omitempty"`  // guest addresses, from the guest agent or VMware Tools
	OS         string   `json:"os,omitempty"`   // guest OS as the platform names it
	UptimeS    int64    `json:"uptime_s"`       // seconds since power on
	Tags       []string `json:"tags,omitempty"` // Proxmox tags
	Notes      string   `json:"notes,omitempty"`
	GuestTools string   `json:"guest_tools,omitempty"` // agent / VMware Tools state
	Target     string   `json:"target"`                // NCC connection name
	Platform   string   `json:"platform"`              // proxmox | vmware
}

// Host is one hypervisor host (Proxmox node or ESXi host).
type Host struct {
	Name     string  `json:"name"`
	Online   bool    `json:"online"`
	CPUs     int     `json:"cpus"`
	CPUUsage float64 `json:"cpu_usage"` // 0..1
	MemBytes int64   `json:"mem_bytes"`
	MemUsed  int64   `json:"mem_used"`
	UptimeS  int64   `json:"uptime_s"`
	Version  string  `json:"version,omitempty"`
	Model    string  `json:"model,omitempty"`
	Target   string  `json:"target"`
	Platform string  `json:"platform"`
}

// Inventory is what one collection from one platform returns.
type Inventory struct {
	Target   string    `json:"target"`
	Platform string    `json:"platform"`
	TakenAt  time.Time `json:"taken_at"`
	Version  string    `json:"version,omitempty"` // platform version, e.g. "pve-manager/8.2.4"
	Hosts    []Host    `json:"hosts"`
	VMs      []VM      `json:"vms"`
	Warnings []string  `json:"warnings,omitempty"`
}

// Target is a configured hypervisor connection.
type Target struct {
	ID      int64
	Name    string
	Kind    string
	Address string
	Options map[string]string
}

// Result is a collection plus option values to save back, e.g. a pinned certificate.
type Result struct {
	Inventory     *Inventory
	OptionUpdates map[string]string
}

// Provider talks to one kind of virtualisation platform. Read-only.
type Provider interface {
	Kind() string
	Collect(ctx context.Context, t Target, creds map[string]string) (*Result, error)
}

var (
	mu        sync.RWMutex
	providers = map[string]Provider{}
)

// Register adds a provider and its entries for the Settings wizard (see package catalog).
// Providers call it from init.
func Register(p Provider, entries ...catalog.Vendor) {
	mu.Lock()
	providers[p.Kind()] = p
	mu.Unlock()
	catalog.Register(p.Kind(), "hypervisor", entries...)
}

// Get returns a registered provider.
func Get(kind string) (Provider, error) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := providers[kind]
	if !ok {
		return nil, fmt.Errorf("no hypervisor provider %q", kind)
	}
	return p, nil
}

// Kinds lists registered providers.
func Kinds() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(providers))
	for k := range providers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Sort orders VMs by host then name, and hosts by name.
func (inv *Inventory) Sort() {
	sort.SliceStable(inv.VMs, func(i, j int) bool {
		if inv.VMs[i].Host != inv.VMs[j].Host {
			return inv.VMs[i].Host < inv.VMs[j].Host
		}
		return inv.VMs[i].Name < inv.VMs[j].Name
	})
	sort.SliceStable(inv.Hosts, func(i, j int) bool { return inv.Hosts[i].Name < inv.Hosts[j].Name })
}

// Power actions.
const (
	ActionStart    = "start"    // power on
	ActionShutdown = "shutdown" // ask the guest OS to shut down
	ActionStop     = "stop"     // power off at once, like pulling the plug
	ActionReboot   = "reboot"   // ask the guest OS to restart
)

// ValidAction reports whether a is a known power action.
func ValidAction(a string) bool {
	switch a {
	case ActionStart, ActionShutdown, ActionStop, ActionReboot:
		return true
	}
	return false
}

// Settings is a change to a VM's settings. Nil fields are left as they are.
type Settings struct {
	Name     *string `json:"name,omitempty"`
	CPUs     *int    `json:"cpus,omitempty"`
	MemoryMB *int    `json:"memory_mb,omitempty"`
	Notes    *string `json:"notes,omitempty"`
}

// Validate checks the values are sensible.
func (s Settings) Validate() error {
	if s.Name != nil && (len(*s.Name) == 0 || len(*s.Name) > 80) {
		return fmt.Errorf("name must be 1 to 80 characters")
	}
	if s.CPUs != nil && (*s.CPUs < 1 || *s.CPUs > 512) {
		return fmt.Errorf("vCPUs must be between 1 and 512")
	}
	if s.MemoryMB != nil && (*s.MemoryMB < 16 || *s.MemoryMB > 16<<20) {
		return fmt.Errorf("memory must be at least 16 MB")
	}
	if s.Notes != nil && len(*s.Notes) > 8192 {
		return fmt.Errorf("notes are limited to 8 KB")
	}
	if s.Name == nil && s.CPUs == nil && s.MemoryMB == nil && s.Notes == nil {
		return fmt.Errorf("nothing to change")
	}
	return nil
}

// Controller is implemented by providers that can change virtual machines. vmID is a
// VM's ID as Collect reports it.
type Controller interface {
	Power(ctx context.Context, t Target, creds map[string]string, vmID, action string) error
	Configure(ctx context.Context, t Target, creds map[string]string, vmID string, s Settings) error
	// Delete removes a stopped VM and its disks.
	Delete(ctx context.Context, t Target, creds map[string]string, vmID string) error
}
