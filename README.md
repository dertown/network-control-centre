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
- **PowerDNS**: browse zones and records; add, edit and delete records with a preview step;
  matching **PTR records are created and removed automatically** in your reverse zone.
- **Vault**: a built-in encrypted vault (AES-256-GCM envelope encryption, Argon2id-derived
  master key) or **HashiCorp Vault** (KV v2, token or AppRole). All device and DNS credentials
  live there; values never reach the browser unless an admin reveals them.
- **Certificates**: import certificates and keys (keys go into the vault) and track expiry.
- **Security**: HTTPS by default, Argon2id passwords, TOTP two-factor sign-in, roles
  (viewer, operator, admin), CSRF protection, login rate limiting, and a hash-chained audit log.
- **Accounts**: anyone can change their own password under **Settings** (it asks for the current
  one and logs out every other browser). Admins can reset another user's password, which logs
  that user out everywhere, and delete users. The last admin cannot be deleted.

The design and the phased plan are in the project's architecture document. Device writes
(VLANs, port profiles), BIND (RFC 2136), ACME / Let's Encrypt and more vendors come in later phases.

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

## Try it without touching your network

```sh
go run ./cmd/ncc-mock      # pretend UniFi console on :9443 and PowerDNS on :9081
./bin/ncc -config config.example.yaml
```

Add a UniFi console at `https://localhost:9443` (user `ncc`, password `demo-password`) and a
PowerDNS server at `http://localhost:9081` (API key `demo-pdns-key`).

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
cmd/ncc-mock/            pretend UniFi console + PowerDNS for demos
internal/api/            HTTP API, auth middleware, static UI
internal/auth/           users, Argon2id, TOTP, sessions, roles
internal/audit/          hash-chained audit log
internal/core/           targets, poller, snapshots, topology graph
internal/drivers/        device driver interface; unifi/
internal/dns/            DNS provider interface; powerdns/
internal/vault/          secret store interface; local and HashiCorp backends
internal/pki/            certificate inventory
internal/mocklab/        recorded UniFi data and an in-memory PowerDNS, used by tests and the demo
web/                     React + TypeScript UI (Vite, Cytoscape.js), embedded into the binary
```

### Adding a device driver or DNS provider

Implement `drivers.Driver` (`Collect`, `Test`) or `dns.Provider` (`ListZones`, `ListRecords`,
`Apply`), call `Register` from `init()`, and import the package in `cmd/ncc/main.go`.
