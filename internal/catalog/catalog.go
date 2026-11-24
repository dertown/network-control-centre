// Package catalog describes every kind of connection NCC can add, for the Settings wizard:
// which group it belongs to (Virtualization, DNS, Routers, Firewalls, Switches...), the vendor
// or product name people pick, and the fields of its form.
//
// Entries are registered by the provider packages themselves, through the category registry
// they already call (drivers.Register, dns.Register, hypervisor.Register, storage.Register,
// smarthome.Register): adding a vendor is one Register call with its entry, and the wizard,
// the edit form and the server-side checks pick it up. The UI has no per-vendor code.
package catalog

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Groups are the first question of the wizard, in the order they are shown.
var Groups = []Group{
	{ID: GroupVirtualization, Label: "Virtualization", Summary: "Hypervisors and clusters: virtual machines, containers and host load."},
	{ID: GroupDNS, Label: "DNS", Summary: "DNS servers and cloud DNS: browse zones, add and change records."},
	{ID: GroupRouter, Label: "Routers & Gateways", Summary: "Internet gateways and routers: networks, clients, uplinks."},
	{ID: GroupFirewall, Label: "Firewalls", Summary: "Firewalls and security gateways: interfaces, neighbours, rules where the API offers them."},
	{ID: GroupSwitch, Label: "Switches & Access Points", Summary: "Managed switches and Wi-Fi: ports, PoE, LLDP neighbours, clients."},
	{ID: GroupStorage, Label: "Storage", Summary: "NAS and file servers: volumes, disks, shares."},
	{ID: GroupSmartHome, Label: "Smart Home", Summary: "Smart home hubs: devices, rooms, Matter."},
}

// Group ids.
const (
	GroupVirtualization = "virtualization"
	GroupDNS            = "dns"
	GroupRouter         = "router"
	GroupFirewall       = "firewall"
	GroupSwitch         = "switch"
	GroupStorage        = "storage"
	GroupSmartHome      = "smarthome"
)

// Group is one wizard category.
type Group struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Summary string `json:"summary"`
}

// Field types.
const (
	Text     = "text"     // plain text, trimmed
	Password = "password" // a password: masked, kept exactly as typed
	Token    = "token"    // an API key or token: masked and trimmed
	Select   = "select"   // one of Choices
	Checkbox = "checkbox" // "on" or "off"; an option that is "off" is not stored
)

// Where a field's value goes.
const (
	StoreOption = "option" // the connection's options (stored in the database, shown in Settings)
	StoreSecret = "secret" // the connection's vault entry (never shown again)
	StoreForm   = "form"   // only steers the form (e.g. "sign in with token or password")
)

// Choice is one value of a select field.
type Choice struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Field is one input of a connection form.
type Field struct {
	Key         string   `json:"key"`
	Label       string   `json:"label"`
	Type        string   `json:"type"`
	Store       string   `json:"store"`
	Default     string   `json:"default,omitempty"`
	Placeholder string   `json:"placeholder,omitempty"`
	Help        string   `json:"help,omitempty"`
	Choices     []Choice `json:"choices,omitempty"`
	// Required fields must be filled in when they are shown.
	Required bool `json:"required,omitempty"`
	// ShowIf shows the field only while every listed field has the listed value.
	ShowIf map[string]string `json:"show_if,omitempty"`
	// Section starts a new titled part of the form at this field.
	Section string `json:"section,omitempty"`
}

// Address kinds.
const (
	AddressURL  = "url"  // http(s)://host[:port]
	AddressHost = "host" // a host name or IP address, optionally with :port
)

// Vendor is one entry of the wizard's second question: a product NCC can connect to.
type Vendor struct {
	// ID names the entry. It is the provider kind for a provider's main entry; extra entries
	// for the same provider (e.g. "Cisco" and "Juniper" for the SNMP driver) use their own
	// id and are stored with options["vendor"] = ID.
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`     // provider kind; set by the category's Register
	Category string   `json:"category"` // target category; set by the category's Register
	Groups   []string `json:"groups"`
	Label    string   `json:"label"`
	Summary  string   `json:"summary"` // one line on the wizard's card
	Help     string   `json:"help"`    // setup steps shown above the form
	// Preset options are fixed by this entry and not shown on the form.
	Preset map[string]string `json:"preset,omitempty"`

	NameDefault        string `json:"name_default"`
	AddressKind        string `json:"address_kind"`
	AddressLabel       string `json:"address_label,omitempty"`
	AddressDefault     string `json:"address_default,omitempty"`
	AddressPlaceholder string `json:"address_placeholder,omitempty"`
	// NoLogin marks providers that need no credentials (an NFS export list).
	NoLogin bool    `json:"no_login,omitempty"`
	Fields  []Field `json:"fields"`
	// Order sorts entries within a group (lower first); ties sort by label.
	Order int `json:"-"`
}

var (
	mu      sync.RWMutex
	entries = map[string]Vendor{}
)

// Register adds entries for one provider. kind and category are filled in by the category
// registry (dns.Register etc.); an entry without an ID gets the kind as its ID.
func Register(kind, category string, vs ...Vendor) {
	mu.Lock()
	defer mu.Unlock()
	for _, v := range vs {
		v.Kind, v.Category = kind, category
		if v.ID == "" {
			v.ID = kind
		}
		if v.AddressKind == "" {
			v.AddressKind = AddressURL
		}
		if v.NameDefault == "" {
			v.NameDefault = v.ID
		}
		entries[v.ID] = v
	}
}

// List returns every entry, by group order of their first group, then Order, then label.
func List() []Vendor {
	mu.RLock()
	out := make([]Vendor, 0, len(entries))
	for _, v := range entries {
		out = append(out, v)
	}
	mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return strings.ToLower(out[i].Label) < strings.ToLower(out[j].Label)
	})
	return out
}

// Get returns an entry by id.
func Get(id string) (Vendor, bool) {
	mu.RLock()
	defer mu.RUnlock()
	v, ok := entries[id]
	return v, ok
}

// ForTarget returns the entry a stored connection was made from: options["vendor"] when it
// names an entry of this kind, otherwise the kind's main entry.
func ForTarget(kind string, options map[string]string) (Vendor, bool) {
	if v, ok := Get(options["vendor"]); ok && v.Kind == kind {
		return v, true
	}
	v, ok := Get(kind)
	return v, ok && v.Kind == kind
}

// CheckOptions validates option values against the entry's fields: select values must be
// one of the choices and checkboxes "on" or "off". Unknown keys pass (drivers save their own
// options, such as a pinned certificate).
func (v Vendor) CheckOptions(opts map[string]string) error {
	for _, f := range v.Fields {
		val, ok := opts[f.Key]
		if !ok || f.Store != StoreOption {
			continue
		}
		switch f.Type {
		case Select:
			found := false
			for _, c := range f.Choices {
				found = found || c.Value == val
			}
			if !found {
				return fmt.Errorf("%s: %q is not one of the choices", f.Label, val)
			}
		case Checkbox:
			if val != "on" && val != "off" {
				return fmt.Errorf("%s must be on or off", f.Label)
			}
		}
		if len(val) > 4096 {
			return fmt.Errorf("%s is too long", f.Label)
		}
	}
	return nil
}

// ---- shared fields, so every provider asks the same question the same way ----

// TLSField is the certificate setting most HTTPS providers use: pin the self-signed
// certificate on first use, or verify it against trusted CAs.
func TLSField(def string) Field {
	if def == "" {
		def = "pin"
	}
	return Field{Key: "tls", Label: "Certificate", Type: Select, Store: StoreOption, Default: def, Choices: []Choice{
		{"pin", "Pin on first use (self-signed)"}, {"verify", "Verify with trusted CAs"},
	}}
}

// UserPassword is a username and password pair, optionally shown only under a condition.
func UserPassword(userPlaceholder string, showIf map[string]string) []Field {
	return []Field{
		{Key: "username", Label: "Username", Type: Text, Store: StoreSecret, Placeholder: userPlaceholder, Required: true, ShowIf: showIf},
		{Key: "password", Label: "Password", Type: Password, Store: StoreSecret, Required: true, ShowIf: showIf},
	}
}

// SNMPFields is an SNMP v2c/v3 login. With toggle set, a checkbox option of that key turns
// them on; otherwise they are always shown.
func SNMPFields(toggle, toggleLabel string) []Field {
	var on map[string]string
	var out []Field
	if toggle != "" {
		out = append(out, Field{Key: toggle, Label: toggleLabel, Type: Checkbox, Store: StoreOption, Default: "off"})
		on = map[string]string{toggle: "on"}
	}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range on {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	v3 := with(map[string]string{"snmp_version": "3"})
	v2 := with(map[string]string{"snmp_version": "2c"})
	out = append(out,
		Field{Key: "snmp_version", Label: "SNMP version", Type: Select, Store: StoreForm, Default: "2c", ShowIf: on,
			Choices: []Choice{{"2c", "v2c (community)"}, {"3", "v3 (user)"}}},
		Field{Key: "snmp_community", Label: "Community", Type: Token, Store: StoreSecret, Placeholder: "not public", Required: true, ShowIf: v2},
		Field{Key: "snmp_user", Label: "User", Type: Text, Store: StoreSecret, Required: true, ShowIf: v3},
		Field{Key: "snmp_auth_proto", Label: "Auth", Type: Select, Store: StoreSecret, Default: "SHA", ShowIf: v3,
			Choices: []Choice{{"SHA", "SHA"}, {"SHA256", "SHA256"}, {"MD5", "MD5"}}},
		Field{Key: "snmp_auth_pass", Label: "Auth password", Type: Password, Store: StoreSecret, Required: true, ShowIf: v3},
		Field{Key: "snmp_priv_proto", Label: "Privacy", Type: Select, Store: StoreSecret, Default: "AES", ShowIf: v3,
			Choices: []Choice{{"AES", "AES"}, {"AES256", "AES256"}, {"DES", "DES"}}},
		Field{Key: "snmp_priv_pass", Label: "Privacy password", Type: Password, Store: StoreSecret, Required: true, ShowIf: v3},
	)
	return out
}
