# NCC architecture

How the Network Control Centre fits together, for anyone changing the code. The README covers
what NCC does and how to run it; this file covers how it is built.

## The big picture

NCC is one Go binary with the React UI embedded in it. It keeps everything in one SQLite
database (plus the local vault, which lives in the same database, encrypted).

```
 browser ──HTTPS──► internal/api ──► internal/core ──► drivers / providers ──► routers, DNS,
   ▲   (JSON + SSE)     │   │            │  (poller)        (unifi, powerdns,      hypervisors,
   │                    │   │            ▼                  proxmox, qnap...)      NAS, Home Assistant
   └──── /api/events ◄──┘   │        SQLite (internal/store)
                            ▼
                 vault (local or HashiCorp) · audit log · certificates
```

1. **Connections** ("targets" in the code, table `targets`) are the things NCC talks to: a UniFi
   console, a PowerDNS server, a Proxmox cluster, a NAS, Home Assistant. Each has a `kind`, a
   `category` (device, dns, hypervisor, storage, smarthome, siem), an address, options, and a vault
   path for its login. `internal/core/targets.go` stores them.
2. **The poller** (`internal/core/poller.go`) polls every enabled connection at once, every
   `poll` interval (30 s by default). Each category has its own collector: device snapshots
   (`collect`), VMs (`vms.go`), storage (`storage.go`), smart home (`smarthome.go`), and a
   reachability check for DNS, which also reads the resolver's addresses and forwarders into
   `dns_resolver_status` for the router DNS check (`dnschain.go`; the rules are in
   `internal/dnscheck`, served at `GET /api/dns/check`). After each poll it records `last_poll`/`last_error` on the
   connection and publishes one event on the `Hub`.
3. **Drivers and providers** do the vendor-specific work. Each package registers itself from
   `init()` and is imported for side effects in `cmd/ncc/main.go`:

   | Interface | Package | Implementations |
   |---|---|---|
   | `drivers.Driver` (network devices) | `internal/drivers` | `unifi`, `snmpnet` (any vendor over SNMP) |
   | `dns.Provider` | `internal/dns` | `powerdns`, `bind`, `windowsdns` (AD), `azuredns` (Entra ID) |
   | `hypervisor.Provider` | `internal/hypervisor` | `proxmox`, `vmware`, `hyperv` |
   | `storage.Provider` | `internal/storage` | `qnap`, `synology`, `smb`, `nfs`, `snmpnas` |
   | `smarthome.Provider` | `internal/smarthome` | `homeassistant` |
   | `siem.Provider` | `internal/siem` | `splunk`, `sentinel`, `elastic`, `graylog`, `syslog` (QRadar, ArcSight, any syslog receiver) |

   Each `Register` call also takes the provider's **catalog entries** (`internal/catalog`): the
   wizard group(s) it appears in (Virtualization, DNS, Routers & Gateways, Firewalls, Switches &
   Access Points, Storage, Smart Home, SIEM), its label and setup help, and its form fields with where
   each value is kept (an option in the database, a secret in the vault, or only on the form).
   One provider can have several entries: the SNMP driver has one per vendor, each with its own
   setup steps and preset options. `GET /api/catalog` serves them; the server checks new and
   edited connections against them. The Windows providers (`windowsdns`, `hyperv`) share
   `internal/winps`, which runs PowerShell over certificate deployment's WinRM client.

   Device drivers return a vendor-neutral `inventory.Snapshot` (devices, ports, clients, links,
   networks, firewall, loops); the other providers return their own inventory types.
4. **Storage of results.** Device snapshots go into `snapshots` (the newest 288 per connection
   are kept); `core.LatestSnapshots` reads the newest one per enabled connection, and the
   topology, devices, clients, loops, firewall and VLANs endpoints are all built from that.
   VMs, storage and smart home keep only their latest inventory (`vm_inventory`,
   `storage_inventory`, `smarthome_inventory`), plus volume capacity samples for growth
   forecasts (`storage_samples`). Per-client traffic counters are sampled every 5 minutes into
   `traffic_samples`; DNS query logs are counted per hour into `dns_queries`.
5. **The API** (`internal/api`) is plain `net/http` with Go 1.22 routing patterns. `server.go`
   lists every route with the role it needs (viewer, operator, admin). Changes go through the
   audit log (`internal/audit`, hash-chained so tampering shows).

## SIEM forwarding

SIEM connections (`category` siem) are polled like the others, but their poll is a connection
test (`siem.Provider.Test`, which writes nothing into the SIEM where the product allows it) whose
one-line result ("Splunk 9.3.1 · Enterprise Security 8.0.2 installed") goes into `siem_status.info`.

Delivery is separate: `core.SIEMForwarder` (`internal/core/siem.go`) runs every 5 s and, for each
enabled SIEM connection, reads up to 500 new rows from each source it forwards, filters them by
the connection's settings (`siem.CommonFields`: audit log, network events, lowest severity,
back-fill) and calls `siem.Provider.Send`. Two sources:

- **The audit log** (`audit_log`), read directly; NCC rates each action's severity
  (`siem.SeverityFor`: failed sign-ins high, deletions and power actions medium...).
- **Network events** (`siem_events`), journalled by the poller when a watched condition changes
  (`siem_state` keeps the last value per connection): `connection.down` / `connection.restored`
  for every connection, `network.loop` / `network.loop_cleared` from device snapshots, and
  `storage.health` from storage reads. A first look only raises an event for a problem, so adding a
  connection or upgrading NCC doesn't report every healthy device. The journal keeps 30 days.

Each connection has a cursor per source (`siem_cursors`), moved only after the SIEM accepted the
batch (or the part of it a one-at-a-time provider delivered, `siem.PartialError`), so delivery is
at least once. Failures back off from 10 s to 5 minutes. Counters and the last error are in
`siem_status`; `GET /api/siem` serves them with the backlog for the SIEM Forwarding page, and
`/metrics` exports them. The formats (CEF, LEEF 1.0, a CIM-style flat document, ECS, GELF and RFC 5424
syslog) are in `internal/siem/format.go`, shared by the providers.

## Live updates

The browser opens one Server-Sent Events stream, `GET /api/events`. The server sends one
event per finished poll (`snapshot`, `vms`, `storage`, `smarthome`, `dns_status`, `siem_status` or
`poll_error`) and a comment every 25 s to keep proxies from closing the stream.

The UI does not use the event payloads. `useLive` (`web/src/live.ts`) turns the stream into a
counter, and each page refetches its data when the counter changes. Because the poller polls
everything at once, events arrive in bursts; `useLive` waits 750 ms for a burst to settle so a
page refetches once per poll cycle, and it skips refetching while the browser tab is hidden
(catching up once when it is shown again).

## Secrets and certificates

- `internal/vault` has two backends behind one `vault.Store` interface: the built-in vault
  (AES-256-GCM envelope encryption with an Argon2id-derived master key; sealed after a restart
  until an admin unseals it or a passphrase file is configured) and HashiCorp Vault (KV v2).
  Every connection's login and every certificate's private key live there. While the vault is
  sealed, polling and DNS changes pause.
- `internal/pki` keeps the certificate inventory (certificates and CA bundles in the database,
  keys in the vault).
- `internal/certdeploy` pushes certificates to servers over SSH or WinRM. Every server type
  (`kinds.go`) turns into a plan of file writes, edits and commands that is shown as a preview
  before anything runs; deployments run in the background and are recorded with each step's
  output.

## The AI assistant

`internal/assistant` builds a `Picture` of the network from the latest reads (routers and their networks and
clients, the IoT inventory, port forwards, DNS zones), makes a rule-based plan (`Baseline`), and asks a model to
improve it (`Prompt`, `ParseAnswer`). `Check` turns any answer into `Step`s, validating each against the picture
with `core.ValidateNetwork` and `core.PlanMove`, so the model can only propose changes NCC would make itself.
Plans are stored in `ai_plans`; `Deploy` applies the picked steps through an `Env` the API implements with the
same driver calls and audit records as the VLANs page; zone steps go through `dnszones.BuildPlan`/`Apply`,
like the DNS page's Zones & VLANs tab.

Models are reached without API keys by running the vendors' CLIs (`providers.go`). Each run gets a private
temporary home with only PATH and proxy settings from NCC's environment; the tool's sign-in (a token, or its
credential files) is restored there from the vault (`ai/<kind>`) and refreshed tokens are copied back
(`runner.go`). Sign-in runs the CLI's own login under a pseudo-terminal (`signin.go`, creack/pty) whose output
the page shows and whose input the page sends.

`install.go` lets an admin install the CLIs from the page. `PlanInstall` returns the exact commands for the
confirmation dialog; `Installs.Start` runs one install at a time in the background: `npm install --prefix
<data_dir>/ai-tools/npm --registry=https://registry.npmjs.org/ <package>@latest` with the server's Node.js 20+,
or with a Node.js LTS downloaded from nodejs.org into `<data_dir>/ai-tools/node` after its SHA-256 matched
`SHASUMS256.txt` (unpacked with path and link escapes refused), then `<tool> --version`. npm runs with its
home, cache and config inside the tools folder. `BinaryPath` looks at the configured path, then the tools
folder, then the `PATH`; tools run with the tools folder and Node.js first on their `PATH`. Installs are
audited as `assistant.install`.

## Authentication

`internal/auth` stores users with Argon2id password hashes and optional TOTP, issues session
cookies, and checks roles. Every state-changing request needs the CSRF token from `/api/me`.
Logins are rate limited per address.

## The web UI

React + TypeScript, built by Vite into `web/dist` and embedded with `go:embed` (`web/embed.go`).
No UI framework beyond React; the map uses Cytoscape.js, charts are small hand-written SVGs.

```
web/src/
  App.tsx          shell: login/setup, side menu, routing by URL hash, sealed-vault banner
  api.ts           fetch wrapper (cookies + CSRF) and the TypeScript shapes of API responses
  live.ts          useLive: the SSE stream as a refetch counter; device kind labels
  format.ts        bytes, rate, pct, ago, uptime
  ui.tsx           shared pieces: Tile, Modal, PageHeader, PageLoading, SourceBanners, AlertList
  connections.tsx  shared logic for connection pages: useSourceData, Refresh now, Add connection
  connectionWizard.tsx  the Add connection wizard and the connection forms, built from /api/catalog
  charts.tsx       Donut, Sparkline, Meter
  icons.tsx        the icon set
  loops.tsx        switching-loop list and helpers (Topology and Dashboard)
  topoStyle.ts     Cytoscape stylesheet from the theme's CSS variables
  pages/           one file per page; topoLayout.ts and topoVlan.ts belong to the Topology page
  styles.css       all styles; light and dark themes are CSS variables on :root
```

Conventions:

- **Pages take `tick`** (from `useLive`) and refetch in a `useEffect` on it.
- **Every page except the Dashboard is lazy-loaded** (`React.lazy` in `App.tsx`), so the first
  load is about a quarter of the size it would otherwise be; the Topology page and Cytoscape
  only load when the map is opened.
- **Connections are managed in one place.** Settings lists every connection with edit,
  disable and remove. Pages built on connections (Virtual machines, Storage, Smart home) show
  failing connections as banners and offer an admin-only "Add connection" button in the
  header, but don't repeat the list.
- **Anything that changes a device is previewed first** (DNS changes, VLAN moves, Wi-Fi changes,
  certificate deployments) and audited.

## Wi-Fi

The UniFi driver reads `rest/wlanconf` (SSIDs), each access point's `radio_table` and
`radio_table_stats` (in `stat/device`) and the wireless clients' signal (`stat/sta`) into
`Snapshot.WiFi` and `Client.Signal/Band/Channel` (`internal/drivers/unifi/wifi.go`). The
passphrase is only looked at to set `ShortPassphrase`; it never goes into a snapshot, because
snapshots are stored unencrypted. `internal/core/wifi.go` has the weak-setting rules
(`WiFiFindings`) and the preview (`PlanWiFiChange`), which also says which findings a change fixes.
Changes go through the optional `drivers.WiFiWriter` (`UpdateWLAN`, a read-modify-write of the whole
WLAN object; `WLANPassphrase`). `drivers.WLANChange.Passphrase` is tagged `json:"-"` so a change can
be audited without leaking it; the API saves passphrases in the vault at `wifi/<connection>/<ssid id>`.

## Tests and the pretend network

`go test ./...` runs unit tests for every package plus API tests against an in-memory
database. `internal/dnszones` ties DNS zones to router networks: the assignments (`dns_zone_vlans`),
the check (`Evaluate`) and the planner (`BuildPlan`/`Apply`, over an `Env` the API server implements),
which creates zones through the optional `dns.ZoneManager` and sets DHCP domains through the optional
`drivers.NetworkDomainSetter`. `internal/mocklab` emulates a UniFi console, PowerDNS, Proxmox VE, vCenter, QNAP,
Synology and Home Assistant from recorded data; the tests use it, and `cmd/ncc-mock` serves it
on local ports so you can try the whole UI without a real network (see the README).

## Adding a new kind of connection

1. Implement the interface for its category (table above) in a new package under that
   category, and call `Register` from `init()` with its `catalog.Vendor` entry: label, summary,
   setup help, wizard group(s), address kind (URL or host) and fields. Reuse the shared field
   helpers (`catalog.TLSField`, `catalog.UserPassword`, `catalog.SNMPFields`, `winps.Fields`).
2. Import the package for side effects in `cmd/ncc/main.go` (and in
   `internal/catalog/catalog_test.go`, which checks every entry makes a usable form).
3. Nothing in the UI: the wizard (`web/src/connectionWizard.tsx`) and the edit form are built
   from the entry. Only pages that show a platform by name (e.g. `platformLabel` on the Virtual
   Machines page) may want its label.
4. Add a pretend version to `internal/mocklab`, or a fake server in the package's tests, so it
   can be tested and demoed.

## Operations

`internal/api/middleware.go` gives every request an id (`X-Request-ID`), works out the client's
address through `trusted_proxies`, counts it for `/metrics` and writes one access-log line
(`slog`, text or JSON). `internal/api/ops.go` has `/api/ready`, the hand-written Prometheus
exposition and the audit export. `internal/api/gzip.go` compresses large answers.
`core.LatestSnapshots` caches decoded snapshots by id (they never change once written), so
callers must treat the snapshots it returns as read-only.
