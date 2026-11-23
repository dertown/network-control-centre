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

// NetworkDomainSetter is a driver that can set the DNS domain name a network's DHCP server
// hands out (the clients' search domain), so a VLAN's clients resolve short names in its zone.
type NetworkDomainSetter interface {
	// SetNetworkDomain sets the domain of the network with id networkID; "" clears it.
	// domain has no trailing dot.
	SetNetworkDomain(ctx context.Context, t Target, creds vault.Secret, networkID, domain string) error
}

// WLANChange is an edit to one Wi-Fi network (SSID). Nil fields are left as they are.
type WLANChange struct {
	Name    *string `json:"name,omitempty"`
	Enabled *bool   `json:"enabled,omitempty"`
	Hidden  *bool   `json:"hidden,omitempty"`
	// NetworkID is the network (VLAN) the SSID puts its clients in.
	NetworkID *string `json:"network_id,omitempty"`
	// Security is inventory.SecWPA2, SecWPA2WPA3 or SecWPA3. NCC never makes a network
	// open or weaker than WPA2.
	Security *string `json:"security,omitempty"`
	// Passphrase is the new Wi-Fi password. It is never marshalled, so a WLANChange can be
	// written to the audit log or a log line without leaking it.
	Passphrase *string `json:"-"`
	// Bands are the bands the network is broadcast on: "2.4", "5" and "6" (GHz).
	Bands []string `json:"bands,omitempty"`
}

// RadioSetting is a change to one radio of an access point. Nil fields are left as they are.
type RadioSetting struct {
	// Band is "2.4", "5" or "6" (GHz); it picks the radio.
	Band string `json:"band"`
	// Channel is the channel number, or 0 for auto (the access point picks).
	Channel *int `json:"channel,omitempty"`
	// WidthMHz is the channel width: 20, 40, 80, 160 or 320.
	WidthMHz *int `json:"width_mhz,omitempty"`
	// TxPowerMode is auto | high | medium | low | custom; TxPower is the power in dBm for custom.
	TxPowerMode *string `json:"tx_power_mode,omitempty"`
	TxPower     *int    `json:"tx_power,omitempty"`
}

// APChange is a change to one access point's radios and the Wi-Fi networks it broadcasts.
type APChange struct {
	Radios []RadioSetting `json:"radios,omitempty"`
	// SSIDsOff, when set, is the complete list per band ("2.4", "5", "6") of the Wi-Fi
	// networks (by SSID id) this access point stops broadcasting; networks not listed for a
	// band are broadcast there as the network itself says. Bands not in the map are left alone.
	SSIDsOff map[string][]string `json:"ssids_off,omitempty"`
}

// APRadioWriter is a driver that can change access point radios.
type APRadioWriter interface {
	// UpdateAPRadios changes the access point with device id deviceID (its normalised MAC).
	UpdateAPRadios(ctx context.Context, t Target, creds vault.Secret, deviceID string, ch APChange) error
}

// WiFiWriter is a driver that can change Wi-Fi networks.
type WiFiWriter interface {
	// UpdateWLAN changes the SSID with id ssidID.
	UpdateWLAN(ctx context.Context, t Target, creds vault.Secret, ssidID string, ch WLANChange) error
	// WLANPassphrase reads the current passphrase of the SSID with id ssidID.
	WLANPassphrase(ctx context.Context, t Target, creds vault.Secret, ssidID string) (string, error)
}
