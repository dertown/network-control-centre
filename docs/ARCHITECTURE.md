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
   `category` (device, dns, hypervisor, storage, smarthome), an address, options, and a vault
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
   | `drivers.Driver` (network devices) | `internal/drivers` | `unifi` |
   | `dns.Provider` | `internal/dns` | `powerdns` |
   | `hypervisor.Provider` | `internal/hypervisor` | `proxmox`, `vmware` |
   | `storage.Provider` | `internal/storage` | `qnap`, `synology`, `smb`, `nfs`, `snmpnas` |
   | `smarthome.Provider` | `internal/smarthome` | `homeassistant` |

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

## Live updates

The browser opens one Server-Sent Events stream, `GET /api/events`. The server sends one
event per finished poll (`snapshot`, `vms`, `storage`, `smarthome`, `dns_status` or
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
- **Anything that changes a device is previewed first** (DNS changes, VLAN moves, certificate
  deployments) and audited.

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
   category, and call `Register` from `init()`.
2. Import the package for side effects in `cmd/ncc/main.go`.
3. In the UI, add the kind to `Kind` and the add/edit forms in `pages/Settings.tsx`, and to the
   `addKinds` list of the page that shows it.
4. Add a pretend version to `internal/mocklab` so it can be tested and demoed.
