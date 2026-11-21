# Network Control Centre (NCC)

A self-hosted web control centre for a home or small-office network. It talks to your
routers, switches and DNS servers, keeps their credentials and your certificates in a vault,
and draws the network as a live map.

This first release (the MVP) covers:

- **UniFi discovery (read-only).** Connects to a UniFi OS console such as the Dream Router 7
  and lists every gateway, switch and access point with **make, model, firmware, IP, ports,
  PoE, uplinks and clients**. Switches are found three ways:
  1. Switches adopted by UniFi report their own model code (for example `USL16LP` is shown as
     "Switch Lite 16 PoE"). Codes NCC does not recognise are still shown as the raw code.
  2. Switches from other vendors that speak **LLDP** are identified from their LLDP system
     name and description (for example "NETGEAR GS308E").
  3. When several wired clients share one UniFi switch port, NCC adds an **inferred unmanaged
     switch** on that port, so dumb switches still appear on the map.
- **Topology map** built from uplinks, LLDP and client tables, with live updates.
- **VLANs and firewall zones on the map**: networks, port VLAN profiles (untagged and tagged), Wi-Fi to VLAN mapping and zone-based firewall zones (Internal, Guest, DMZ, custom) from UniFi. Clients are coloured by VLAN, DMZ hosts are ringed in red, "Group by VLAN" boxes each network, and clicking a network highlights the links that carry it. Consoles without zone-based firewall get zones guessed from network purpose and name.
- **Switching loop detection**: finds switch ports that loop back to each other and names the
  exact switch and ports, on the Topology map (looping cables drawn in red or amber) and as a
  Dashboard alert. NCC spots a switch hearing its own LLDP (two of its ports cabled together,
  directly or through a dumb switch), duplicate cables between two devices, rings of cables
  through several devices, ports spanning tree is blocking, and UniFi's own loop-protection,
  STP and MAC-flapping events from the last 24 hours. LAGs are not counted as loops. A loop
  with an STP-blocked port is shown as contained (amber); one with nothing blocking it is red.
  Try it with `go run ./cmd/ncc-mock -loops`.
- **VLANs and clients** (VLANs page): create VLAN networks on the UniFi router (name, VLAN ID,
  subnet, DHCP range, isolation, internet access) and move clients between networks by drag and
  drop, one at a time or as a selection ("Select likely IoT" picks smart-home gear by vendor and
  name). Wi-Fi clients move with UniFi's per-client network override, so they keep the same SSID
  and password; wired clients move by changing the untagged VLAN of their switch port (everything
  on that port moves together, and ports leading to other switches or access points are never
  changed). Every change is previewed first and audited. Changes need a UniFi account with a
  Network role that can change settings (Site Admin or Full Management), not View Only.
- **Firewall rules and port forwards (read-only)**: the **Firewall** page lists the router's
  zone-based firewall policies (UniFi Network 9+) or older rule sets (WAN_IN, LAN_IN...), with
  zones, networks, address and port groups and clients named, and every port forward with where it
  lands and who may reach it. "Enabled only" is on by default; UniFi's built-in policies are
  hidden unless you ask for them. A View Only account is enough.
- **PowerDNS**: browse zones and records; add, edit and delete records with a preview step;
  matching **PTR records are created and removed automatically** in your reverse zone.
- **Virtual machines**: every VM and container on **Proxmox VE** (API token or user login) and
  **VMware vCenter or standalone ESXi** in one list, with state, host or node, vCPUs and CPU use,
  memory, disk, guest IP addresses (QEMU guest agent / VMware Tools), guest OS and uptime, plus
  per-host CPU and memory load. Operators can start, shut down, restart and power off machines;
  admins can edit name, vCPUs, memory and notes, and delete stopped machines (typing the name to
  confirm). Every change is in the audit log. Changes need a login with write rights (Proxmox:
  e.g. PVEVMAdmin, or a token with privilege separation off; VMware: not the Read-only role).
  Saved connections can be edited in Settings (address, certificate pin, login).
- **Vault**: a built-in encrypted vault (AES-256-GCM envelope encryption, Argon2id-derived
  master key) or **HashiCorp Vault** (KV v2, token or AppRole). All device and DNS credentials
  live there; values never reach the browser unless an admin reveals them.
- **Certificates**: import certificates and keys (keys go into the vault) and track expiry.
- **Security**: HTTPS by default, Argon2id passwords, TOTP two-factor sign-in, roles
  (viewer, operator, admin), CSRF protection, login rate limiting, and a hash-chained audit log.
- **Accounts**: anyone can change their own password under **Settings** (it asks for the current
  one and logs out every other browser). Admins can reset another user's password, which logs
  that user out everywhere, and delete users. The last admin cannot be deleted.

The design and the phased plan are in the project's architecture document. Port profile editing, BIND (RFC 2136), ACME / Let's Encrypt and more vendors come in later phases.

## Quick start

Requires Go 1.26+ and Node 22+ (or just Docker).

```sh
make build
cp config.example.yaml config.yaml
./bin/ncc -config config.yaml
```

Open `https://<host>:8443`. The browser warns about the self-signed certificate on first visit;
set `tls_cert`/`tls_key` to use your own. The first page asks you to create the admin account
and the **vault passphrase**. Keep the passphrase safe: without it, stored credentials cannot be
decrypted. After a restart the vault is sealed until an admin unseals it in the UI (or set
`passphrase_file` / `NCC_VAULT_PASSPHRASE` for unattended starts).

### Proxmox VE

[`deploy/proxmox`](deploy/proxmox) has Terraform that creates an Ubuntu VM on Proxmox and
deploys NCC on it as a systemd service. See its README.

### Docker

```sh
cd deploy && docker compose up -d --build
```

## Connecting your network

### Dream Router 7 (or any UniFi OS console)

1. In UniFi OS, go to **Admins & Users** and add an admin with **Restrict to local access only**
   and Network role **View Only**. NCC only reads, so view-only is enough.
2. In NCC, **Settings → Add UniFi console**: address `https://<router LAN IP>`, site `default`,
   that username and password. Leave **Certificate** on "Pin on first use": the console's
   self-signed certificate is pinned on the first connection, and NCC refuses to connect if it
   ever changes.
3. NCC polls every 30 seconds and reuses its login session, so it will not trip UniFi's login
   rate limit.

An API key (UniFi Network 9+) also works. If the console only accepts it on the official
Integration API, NCC falls back to that, which gives devices and clients but no uplink or LLDP
detail, so the map is less complete.

### PowerDNS

Enable the API in `pdns.conf`:

```
api=yes
api-key=<a long random key>
webserver=yes
webserver-address=0.0.0.0
webserver-allow-from=<NCC host>/32
```

Then **Settings → Add PowerDNS server** with `http://<pdns host>:8081` and the key. To get
automatic PTR records, create the reverse zone (for example `1.168.192.in-addr.arpa.`) on the
same server.

### Traffic: top clients, traffic types and sites

The **Traffic** page ranks clients by how much data they moved (last hour, 24 hours, 7 days, or
since each client connected), shows live download and upload rates, and breaks traffic down by
type. It uses three sources, each optional beyond the first:

1. **Per-client totals and live rates** come from the UniFi console you already added. Nothing
   to set up. NCC samples the counters every 5 minutes, so the hour/day/week totals fill in
   after it has been running for a while.
2. **Traffic types** (streaming, gaming, social networks, file transfer, VoIP and so on) come from
   the gateway's deep packet inspection. In UniFi Network turn on **Settings → Traffic & Security
   → Traffic Identification**. The UniFi API reports these as category numbers; NCC names the
   categories, and applications show as "category (app N)" because the API does not send names.
3. **Sites each client looks up** (for example YouTube, Netflix, instagram.com) come from DNS
   query logs. HTTPS hides what is on a page, so this is as close to "what they are viewing" as
   the network can see. It needs a PowerDNS **Recursor** or **dnsdist** that your clients use
   as their resolver (the Authoritative server alone cannot log client lookups). Turn on NCC's
   receiver in `config.yaml`:

   ```yaml
   dns_log:
     listen: ":4242"
     allow: ["192.168.1.70"]   # the resolver's address; other senders are refused
   ```

   then point the resolver at it. PowerDNS Recursor 5 (`recursor.yml`):

   ```yaml
   logging:
     protobuf_servers:
       - servers: ["<NCC host>:4242"]
         logQueries: true
         logResponses: false
   ```

   (older Recursors: `protobufServer("<NCC host>:4242", {logQueries=true, logResponses=false})`
   in the Lua config file). dnsdist:

   ```lua
   rl = newRemoteLogger("<NCC host>:4242")
   addAction(AllRule(), RemoteLogAction(rl))
   ```

   NCC keeps hourly counts per client address and site for 7 days (`dns_log.retain`), not
   individual queries. Lookups are matched to clients by IP address. If your clients use the
   router as their DNS server and the router forwards to PowerDNS, every lookup looks like it
   came from the router; hand out the resolver's address in DHCP instead. The receiver is plain
   TCP with no authentication, so keep `allow` set and the port off the internet.

## Try it without touching your network

```sh
go run ./cmd/ncc-mock      # pretend UniFi :9443, PowerDNS :9081, Proxmox VE :9006, vCenter :9007
./bin/ncc -config config.example.yaml
```

To fill the Traffic page's site lists too, uncomment `dns_log` in the config and run
`go run ./cmd/ncc-mock -dnslog localhost:4242`. Add `-loops` to cable two switching loops into the
pretend network.

Add a UniFi console at `https://localhost:9443` (user `ncc`, password `demo-password`) and a
PowerDNS server at `http://localhost:9081` (API key `demo-pdns-key`). On the **Virtual machines**
page, add Proxmox VE at `https://localhost:9006` (token `ncc@pve!monitor`, secret
`demo-token-secret`) and VMware at `https://localhost:9007` (user `ncc`, password `demo-password`).

## Development

```sh
make test                  # go vet, go test, TypeScript check
cd web && npm run dev      # UI dev server on :5173, proxies /api to a local NCC
```

The UI dev proxy expects NCC on plain HTTP at `localhost:8080`. Run NCC with `plain_http: true`
and `listen: ":8080"` while you work on the UI.

### Layout

```
cmd/ncc/                 server entry point
cmd/ncc-mock/            pretend UniFi console, PowerDNS, Proxmox VE and vCenter for demos
internal/api/            HTTP API, auth middleware, static UI
internal/auth/           users, Argon2id, TOTP, sessions, roles
internal/audit/          hash-chained audit log
internal/core/           targets, poller, snapshots, topology graph
internal/drivers/        device driver interface; unifi/
internal/dns/            DNS provider interface; powerdns/
internal/hypervisor/     virtual machine provider interface; proxmox/, vmware/
internal/dnslog/         PowerDNS Recursor / dnsdist protobuf query-log receiver
internal/vault/          secret store interface; local and HashiCorp backends
internal/pki/            certificate inventory
internal/mocklab/        recorded UniFi data and an in-memory PowerDNS, used by tests and the demo
web/                     React + TypeScript UI (Vite, Cytoscape.js), embedded into the binary
```

### Adding a device driver or DNS provider

Implement `drivers.Driver` (`Collect`, `Test`) or `dns.Provider` (`ListZones`, `ListRecords`,
`Apply`), call `Register` from `init()`, and import the package in `cmd/ncc/main.go`.
