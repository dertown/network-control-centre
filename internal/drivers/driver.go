// Package drivers defines the device driver interface and registry.
package drivers

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/vault"
)

// Target is a configured controller or device NCC talks to.
type Target struct {
	ID      int64             `json:"id"`
	Name    string            `json:"name"`
	Kind    string            `json:"kind"`
	Address string            `json:"address"`
	Options map[string]string `json:"options"`
}

// Result is what a collection returns besides the snapshot.
type Result struct {
	Snapshot *inventory.Snapshot
	// OptionUpdates are persisted back into the target, e.g. a TLS fingerprint pinned on first use.
	OptionUpdates map[string]string
	// Traffic is per-client traffic, when the driver can report it.
	Traffic *inventory.TrafficReport
}

// Driver collects inventory from one kind of target. Read-only in the MVP.
type Driver interface {
	Kind() string
	Collect(ctx context.Context, t Target, creds vault.Secret) (*Result, error)
	// Test checks connectivity and credentials without collecting everything.
	Test(ctx context.Context, t Target, creds vault.Secret) (*Result, error)
}

var (
	mu       sync.RWMutex
	registry = map[string]Driver{}
)

// Register adds a driver. Drivers call it from init.
func Register(d Driver) {
	mu.Lock()
	defer mu.Unlock()
	registry[d.Kind()] = d
}

// Get returns a registered driver.
func Get(kind string) (Driver, error) {
	mu.RLock()
	defer mu.RUnlock()
	d, ok := registry[kind]
	if !ok {
		return nil, fmt.Errorf("no device driver %q", kind)
	}
	return d, nil
}

// Kinds lists registered drivers.
func Kinds() []string {
	mu.RLock()
	defer mu.RUnlock()
	var out []string
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// NetworkSpec describes a new VLAN network.
type NetworkSpec struct {
	Name string `json:"name"`
	VLAN int    `json:"vlan"`
	// Mode is "gateway" (the router routes the network and can hand out addresses) or
	// "vlan-only" (a VLAN with no gateway or DHCP on the router, for a third-party router).
	Mode string `json:"mode"`
	// Gateway is the router's address with the prefix length, e.g. 192.168.30.1/24 (gateway mode).
	Gateway   string `json:"gateway,omitempty"`
	DHCP      bool   `json:"dhcp"`
	DHCPStart string `json:"dhcp_start,omitempty"`
	DHCPStop  string `json:"dhcp_stop,omitempty"`
	// Isolated blocks traffic from this network to the router's other networks.
	Isolated       bool `json:"isolated"`
	InternetAccess bool `json:"internet_access"`
}

// Ways a client is moved to another network.
const (
	// MovePort sets the untagged (native) network of the switch port the client is cabled to.
	// Everything on that port moves together.
	MovePort = "port"
	// MoveClient overrides the network of one wireless client, keeping it on the same Wi-Fi.
	MoveClient = "client"
)

// ClientMove is one change that puts a client in another network.
type ClientMove struct {
	MAC    string `json:"mac"`
	Name   string `json:"name"`
	Method string `json:"method"`
	// SwitchMAC and SwitchPort name the port for MovePort.
	SwitchMAC  string `json:"switch_mac,omitempty"`
	SwitchPort int    `json:"switch_port,omitempty"`
}

// MoveResult is what happened to one ClientMove.
type MoveResult struct {
	MAC   string   `json:"mac"`
	Name  string   `json:"name"`
	OK    bool     `json:"ok"`
	Error string   `json:"error,omitempty"`
	Notes []string `json:"notes,omitempty"`
}

// NetworkWriter is a driver that can create networks and move clients between them.
type NetworkWriter interface {
	// CreateNetwork adds a VLAN network and returns its id.
	CreateNetwork(ctx context.Context, t Target, creds vault.Secret, spec NetworkSpec) (string, error)
	// MoveClients puts clients in the network with id networkID. With reconnect, clients are
	// made to ask for a new address straight away (see Reconnect).
	MoveClients(ctx context.Context, t Target, creds vault.Secret, networkID string, moves []ClientMove, reconnect bool) ([]MoveResult, error)
	// Reconnect makes clients ask for a new address: Wi-Fi clients rejoin, a wired client's
	// switch port is power-cycled (PoE) or switched off briefly.
	Reconnect(ctx context.Context, t Target, creds vault.Secret, moves []ClientMove) ([]MoveResult, error)
}
