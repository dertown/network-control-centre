// Package siem defines the SIEM interface (Splunk Enterprise Security, Microsoft Sentinel,
// Elastic Security, IBM QRadar, Graylog, ArcSight and any syslog receiver) and the events NCC
// forwards to them: every audit log entry (sign-ins, configuration changes, DNS edits,
// certificate deployments...) and the network events NCC notices while polling (a connection
// going down or coming back, a switching loop, a storage device turning unhealthy).
//
// Providers only test a connection and deliver batches of events. Which events go where, the
// per-connection cursors and retries live in core (core.SIEMForwarder), so a provider never
// needs to know about the database.
package siem

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dertown/network-control-centre/internal/catalog"
)

// Event sources.
const (
	SourceAudit   = "audit"   // NCC's audit log
	SourceNetwork = "network" // events NCC noticed on the network while polling
	SourceTest    = "test"    // "Send test event"
)

// Severities on the CEF scale (0 lowest to 10 highest), used by every format.
const (
	SevInfo     = 1
	SevLow      = 3
	SevMedium   = 5
	SevHigh     = 7
	SevCritical = 9
)

// Event is one thing NCC tells a SIEM about.
type Event struct {
	ID       int64             `json:"id"`     // id within its source (audit log id, network event id)
	Source   string            `json:"source"` // audit | network | test
	Time     time.Time         `json:"time"`
	Type     string            `json:"type"`     // e.g. login.failed, target.create, connection.down
	Severity int               `json:"severity"` // 0..10
	Actor    string            `json:"actor,omitempty"`
	Target   string            `json:"target,omitempty"` // what it is about, e.g. target/udm or dns/example.com
	Message  string            `json:"message"`
	Detail   string            `json:"detail,omitempty"` // JSON text from the audit log, never secrets
	Fields   map[string]string `json:"fields,omitempty"` // extra flat fields (network events)
}

// ExternalID is a stable id across sources, e.g. "audit-42", for de-duplicating in the SIEM.
func (e Event) ExternalID() string { return fmt.Sprintf("%s-%d", e.Source, e.ID) }

// Outcome is "failure" for failed actions (login.failed, *.error, connection.down) and
// "success" otherwise, the way CIM and ECS want it.
func (e Event) Outcome() string {
	t := strings.ToLower(e.Type)
	if strings.Contains(t, "fail") || strings.Contains(t, "error") || strings.HasSuffix(t, ".down") || strings.Contains(t, "denied") {
		return "failure"
	}
	return "success"
}

// Category is a coarse kind for the SIEM's dashboards: authentication, configuration, network
// or test.
func (e Event) Category() string {
	switch {
	case e.Source == SourceTest:
		return "test"
	case e.Source == SourceNetwork:
		return "network"
	case strings.HasPrefix(e.Type, "login"), strings.HasPrefix(e.Type, "logout"), strings.HasPrefix(e.Type, "mfa"),
		strings.HasPrefix(e.Type, "user."), strings.HasPrefix(e.Type, "password"), strings.HasPrefix(e.Type, "session"):
		return "authentication"
	}
	return "configuration"
}

// SeverityFor rates an audit log action: failed sign-ins and deletions rank above routine
// changes, reads rank lowest.
func SeverityFor(action string) int {
	a := strings.ToLower(action)
	switch {
	case a == "login.failed", strings.Contains(a, "mfa.fail"), strings.Contains(a, "denied"):
		return SevHigh
	case strings.Contains(a, "vault.seal"), strings.Contains(a, "user.delete"), strings.Contains(a, "user.role"),
		strings.Contains(a, "credentials"), strings.Contains(a, "secret"):
		return SevMedium + 1
	case strings.Contains(a, "delete"), strings.Contains(a, "power"), strings.Contains(a, "restart"), strings.Contains(a, "shutdown"),
		strings.Contains(a, "firewall"), strings.Contains(a, "unlock"):
		return SevMedium
	case strings.Contains(a, "export"), strings.HasPrefix(a, "login"), strings.HasPrefix(a, "logout"):
		return SevLow
	}
	return SevLow
}

// SyslogSeverity maps a 0..10 severity to RFC 5424 (0 emergency .. 7 debug).
func SyslogSeverity(sev int) int {
	switch {
	case sev >= SevCritical:
		return 2 // critical
	case sev >= SevHigh:
		return 3 // error
	case sev >= SevMedium:
		return 4 // warning
	case sev >= SevLow:
		return 5 // notice
	}
	return 6 // informational
}

// SeverityWord is low, medium, high or critical (for Splunk's and Sentinel's severity fields).
func SeverityWord(sev int) string {
	switch {
	case sev >= SevCritical:
		return "critical"
	case sev >= SevHigh:
		return "high"
	case sev >= SevMedium:
		return "medium"
	case sev >= SevLow:
		return "low"
	}
	return "informational"
}

// Target is a configured SIEM connection.
type Target struct {
	ID      int64
	Name    string
	Kind    string
	Address string
	Options map[string]string
}

// Result is what a test or a delivery reports back: a line for the status page (the
// product's version, "Enterprise Security installed") and option values to save, such as a
// pinned certificate.
type Result struct {
	Info          string
	OptionUpdates map[string]string
}

// Provider talks to one kind of SIEM.
type Provider interface {
	Kind() string
	// Test checks the connection and the credentials without writing anything into the SIEM
	// where it can (it runs on every poll).
	Test(ctx context.Context, t Target, creds map[string]string) (*Result, error)
	// Send delivers events, oldest first. An error means none of the batch may be counted as
	// delivered; the forwarder sends it again later.
	Send(ctx context.Context, t Target, creds map[string]string, events []Event) (*Result, error)
}

// Options every SIEM connection has (see CommonFields).
const (
	OptAudit       = "forward_audit"   // "on": send the audit log
	OptNetwork     = "forward_network" // "on": send network events
	OptMinSeverity = "min_severity"    // drop events below this severity
	OptBackfill    = "backfill"        // "on": start from the first audit entry rather than now
)

// CommonFields are the forwarding settings shown on every SIEM form, after the vendor's own.
func CommonFields() []catalog.Field {
	return []catalog.Field{
		{Key: OptAudit, Label: "Send the audit log (sign-ins, changes, exports)", Type: catalog.Checkbox, Store: catalog.StoreOption, Default: "on",
			Section: "What to send", Help: "NCC sends new events every few seconds and retries until the SIEM accepts them."},
		{Key: OptNetwork, Label: "Send network events (connections down and back, loops, storage health)", Type: catalog.Checkbox, Store: catalog.StoreOption, Default: "on"},
		{Key: OptBackfill, Label: "Also send the audit log from before this connection was added", Type: catalog.Checkbox, Store: catalog.StoreOption, Default: "off"},
		{Key: OptMinSeverity, Label: "Lowest severity to send", Type: catalog.Select, Store: catalog.StoreOption, Default: "0", Choices: []catalog.Choice{
			{Value: "0", Label: "Everything"}, {Value: "3", Label: "Low and above"}, {Value: "5", Label: "Medium and above"}, {Value: "7", Label: "High and above"}}},
	}
}

// Wants reports whether a connection's settings let an event through.
func Wants(opts map[string]string, e Event) bool {
	switch e.Source {
	case SourceAudit:
		if opts[OptAudit] != "on" {
			return false
		}
	case SourceNetwork:
		if opts[OptNetwork] != "on" {
			return false
		}
	}
	min := 0
	fmt.Sscanf(opts[OptMinSeverity], "%d", &min)
	return e.Severity >= min
}

// Host is the name NCC reports itself as (the machine's host name).
var Host = func() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "ncc"
	}
	return h
}()

// Version is NCC's version, put in CEF and LEEF headers; main sets it.
var Version = "dev"

// Product names used in every format.
const (
	VendorName  = "NCC"
	ProductName = "Network Control Centre"
)

var (
	mu        sync.RWMutex
	providers = map[string]Provider{}
)

// Register adds a provider and its entries for the Settings wizard (see package catalog). The
// forwarding settings (CommonFields) are appended to each entry's form. Providers call it from
// init.
func Register(p Provider, entries ...catalog.Vendor) {
	mu.Lock()
	providers[p.Kind()] = p
	mu.Unlock()
	for i := range entries {
		entries[i].Groups = []string{catalog.GroupSIEM}
		entries[i].Fields = append(entries[i].Fields, CommonFields()...)
	}
	catalog.Register(p.Kind(), "siem", entries...)
}

// Get returns a registered provider.
func Get(kind string) (Provider, error) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := providers[kind]
	if !ok {
		return nil, fmt.Errorf("no SIEM provider %q", kind)
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

// TestEvent is the event "Send test event" delivers.
func TestEvent(actor string) Event {
	return Event{ID: time.Now().Unix(), Source: SourceTest, Time: time.Now().UTC(), Type: "ncc.test", Severity: SevInfo, Actor: actor,
		Target: "ncc", Message: "Test event from Network Control Centre. If you can see this, forwarding works."}
}

// Snippet shortens a response body for an error message.
func Snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// PartialError is returned by providers that deliver events one at a time (syslog, Graylog)
// when some of a batch got through: the first Sent events are delivered and are not sent
// again.
type PartialError struct {
	Sent int
	Err  error
}

func (e *PartialError) Error() string { return e.Err.Error() }
func (e *PartialError) Unwrap() error { return e.Err }
