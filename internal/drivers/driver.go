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
