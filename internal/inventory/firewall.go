package inventory

// Firewall modes: how the router's firewall is configured.
const (
	FirewallZones  = "zones"  // zone-based firewall policies (UniFi Network 9 and later)
	FirewallLegacy = "legacy" // rule sets such as WAN_IN and LAN_IN (older UniFi Network)
)

// Firewall is the router's firewall rules and port forwards, read-only.
type Firewall struct {
	// Mode is FirewallZones or FirewallLegacy; empty when no rule list could be read.
	Mode     string         `json:"mode,omitempty"`
	Rules    []FirewallRule `json:"rules"`
	Forwards []PortForward  `json:"forwards"`
	// Notes say which lists the router refused or does not have.
	Notes  []string `json:"notes,omitempty"`
	Target string   `json:"target"`
}

// FirewallRule is one firewall policy or rule.
type FirewallRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	// Action is allow, block or reject.
	Action string `json:"action"`
	Index  int    `json:"index"`
	// Builtin is set for rules the router made itself (UniFi's predefined policies).
	Builtin bool `json:"builtin,omitempty"`
	// Ruleset is the legacy rule set (WAN_IN, LAN_IN...), empty for zone policies.
	Ruleset     string           `json:"ruleset,omitempty"`
	Source      FirewallEndpoint `json:"source"`
	Destination FirewallEndpoint `json:"destination"`
	Protocol    string           `json:"protocol"`
	IPVersion   string           `json:"ip_version,omitempty"`
	// States are the connection states matched (new, established...); empty means all.
	States   []string `json:"states,omitempty"`
	Schedule string   `json:"schedule,omitempty"`
	Logging  bool     `json:"logging,omitempty"`
	Target   string   `json:"target"`
}

// FirewallEndpoint is the source or destination of a rule.
type FirewallEndpoint struct {
	Zone string `json:"zone,omitempty"` // zone name, for zone policies
	// Match is what the rule matches in that zone, e.g. "Any", "IoT network", "10.0.0.5".
	Match string `json:"match"`
	Port  string `json:"port,omitempty"`
	// Negate is set when the rule matches everything except Match.
	Negate bool `json:"negate,omitempty"`
}

// PortForward is a port forwarding (destination NAT) rule.
type PortForward struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Interface is the WAN it listens on: "WAN", "WAN2", "Both" or "All".
	Interface    string `json:"interface,omitempty"`
	Protocol     string `json:"protocol"`
	ExternalPort string `json:"external_port"`
	// Source limits who may connect: "Any", an address, or a group name.
	Source string `json:"source"`
	// Destination is the WAN address it applies to, when limited to one.
	Destination string `json:"destination,omitempty"`
	ForwardIP   string `json:"forward_ip"`
	ForwardPort string `json:"forward_port"`
	// ForwardClient is the name of the client at ForwardIP, when known.
	ForwardClient string `json:"forward_client,omitempty"`
	Logging       bool   `json:"logging,omitempty"`
	Target        string `json:"target"`
}
