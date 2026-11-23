# Network Control Centre (NCC)

A self-hosted web control centre for a home or small-office network. It talks to your
routers, switches and DNS servers, keeps their credentials and your certificates in a vault,
and draws the network as a live map.

This first release (the MVP) covers:

- **Dashboard**: one screen for a quick look at the whole network. A status tile per area (internet
  link and live throughput, network devices, clients, virtual machines, storage, smart home, the
  next certificate to expire, and how many ports are open to the internet), then **Needs attention**:
  every problem from every area in one list, critical first (internet down, switching loops,
  offline devices or VM hosts, NAS disk and volume alerts, smart home alerts, expiring
  certificates, connections NCC can't read), each linking to the page that fixes it.
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
  changed). Moved devices get an address in the new network straight away: Wi-Fi devices are
  disconnected and rejoin, PoE ports are power-cycled and other ports are switched off for about
  10 seconds. A fixed IP moves with the device, keeping its last number in the new subnet when
  free. Devices still on an old address are flagged, with a button to reconnect them. Every
  change is previewed first and audited. Changes need a UniFi account with a
  Network role that can change settings (Site Admin or Full Management), not View Only.
- **Firewall rules and port forwards (read-only)**: the **Firewall** page lists the router's
  zone-based firewall policies (UniFi Network 9+) or older rule sets (WAN_IN, LAN_IN...), with
  zones, networks, address and port groups and clients named, and every port forward with where it
  lands and who may reach it. "Enabled only" is on by default; UniFi's built-in policies are
  hidden unless you ask for them. A View Only account is enough.
- **PowerDNS**: browse zones and records; add, edit and delete records with a preview step;
  matching **PTR records are created and removed automatically** in your reverse zone.
- **DNS zones and VLANs** (DNS → Zones & VLANs): create zones and **subdomains** (e.g. `iot.home.lan`,
  `dmz.home.lan`, delegated from the parent with NS records) and **assign a zone to each VLAN**. NCC can
  also create the VLAN's reverse zone and make the router hand out the zone as the network's DHCP domain
  name (UniFi `domain_name`), so clients resolve short names in it. A check lists every router network
  with its zone and flags what's off: no zone, a zone the DNS server doesn't have, a zone named for another
  VLAN (IoT put in `dmz.home.lan`), one zone shared by several VLANs, the router handing out another domain,
  no reverse zone for the subnet, and assignments to networks that no longer exist. Missing zones are
  suggested under your main domain, and **Create suggested zones** plans them all in one preview. Every step
  is previewed and audited; admins only. Zones on each DNS server are shown as a tree, and unused ones can
  be deleted. The planner (`internal/dnszones`, `POST /api/dns/zoneplan`) takes the same request from
  anything that proposes changes. PowerDNS can create zones today; BIND comes with its provider.
- **Virtual machines**: every VM and container on **Proxmox VE** (API token or user login) and
  **VMware vCenter or standalone ESXi** in one list, with state, host or node, vCPUs and CPU use,
  memory, disk, guest IP addresses (QEMU guest agent / VMware Tools), guest OS and uptime, plus
  per-host CPU and memory load. Operators can start, shut down, restart and power off machines;
  admins can edit name, vCPUs, memory and notes, and delete stopped machines (typing the name to
  confirm). Every change is in the audit log. Changes need a login with write rights (Proxmox:
  e.g. PVEVMAdmin, or a token with privilege separation off; VMware: not the Read-only role).
  Saved connections can be edited in Settings (address, certificate pin, login).
- **Storage** (Monitor → Storage): NAS and file servers in one place. **QNAP** (QTS and QuTS hero) is read
  through its own HTTP API: model, firmware, CPU, memory, system and CPU temperature, fans, network ports,
  volumes with capacity, every disk's SMART health and temperature, shared folders with their size, and
  firmware updates. QNAP's API doesn't report RAID or volume state, so a QNAP connection can also read
  QNAP's NAS-MIB over **SNMP** (v2c or v3) for degraded or rebuilding volumes. **Synology DSM** shows
  pools, volumes, disks, shares and Btrfs share snapshots. Any **SMB** server (Windows, Samba, a router's USB
  share) shows its shares with size and free space, any **NFS** server its versions and export list (and
  warns about exports open to everyone), and anything else that speaks **SNMP** (TrueNAS, Unraid, ASUSTOR...)
  its disks and file systems. Alerts are raised for failing or warm disks, degraded volumes, volumes over
  85% / 95% full, hot systems, stopped fans and new firmware, and each volume shows its growth per day
  and when it will be full. Management, each one audited: create a folder in a share (QNAP, Synology, SMB;
  operators), take a snapshot (Synology; operators), delete a snapshot (Synology; admins; snapshots kept by
  retention can't be deleted), create a shared folder (Synology; admins), and restart or shut down the NAS
  (QNAP, Synology; admins, typing the connection name to confirm). QNAP's public API has no share or
  snapshot calls, so those stay in QTS. Use a dedicated admin account without two-step verification for
  QNAP and Synology. Try it with `go run ./cmd/ncc-mock` (QNAP on :9050, Synology on :9051).
- **Wi-Fi** (Configure → Wi-Fi): the router's Wi-Fi networks (name, on/off, security, bands, network/VLAN,
  guest, hidden, clients), every access point's radios (channel, width, transmit power, clients, channel use;
  a Dream Router's built-in Wi-Fi counts as an access point) and the wireless clients with the weakest signal.
  NCC flags weak settings: open networks, WEP, WPA1 or WPA/WPA2 mixed mode, TKIP, passphrases under 12 characters,
  an IoT Wi-Fi that isn't on an IoT VLAN, a guest Wi-Fi on your LAN, 40 MHz or overlapping channels on 2.4 GHz,
  busy channels and access points sharing a channel; critical ones also show on the Dashboard. Admins can rename an
  SSID, switch it on or off, hide it, put it on another network (VLAN), set WPA2, WPA2/WPA3 or WPA3 and change its
  passphrase (or generate one), always through a preview that says what changes, which flags it fixes and who gets
  disconnected. NCC never makes a network open or weaker than WPA2. Passphrases NCC sets, or reads from the router
  with "Show current passphrase", are kept in the vault under `wifi/<connection>/<ssid id>`; the audit log records
  the change without the passphrase. Needs a UniFi account that can change settings.
- **IoT devices** (Configure → IoT devices): an inventory of the company's IoT gear, found among the router's
  clients by vendor and name: IP cameras and NVRs, door and badge controllers, printers, desk and conference
  phones, meeting-room systems, displays and signage, building (HVAC/BMS) controllers, UPSs, PDUs, sensors,
  lighting and speakers. Each device records its site, building, floor, room, owner and notes (edit one, or select
  many and set them together), with its network, VLAN, switch port or access point, IP, last seen and, when Home
  Assistant knows it, model and firmware. Choose which networks are IoT networks (NCC guesses from names like IoT,
  Cameras, BMS, OT until an admin does): devices elsewhere are flagged, with a link that preselects them on the VLANs
  page to move, or an exception with a reason. Devices NCC missed are added by hand; ones that aren't IoT are marked
  so they stay out. Export to CSV. Operators edit, admins choose the networks and remove devices; every change is
  in the audit log. Try it with `go run ./cmd/ncc-mock -office`, which adds an office's IoT devices to the pretend network.
- **AI assistant** (Configure → AI assistant): asks a model for a plan for the whole network (VLANs, every
  client, the IoT inventory, port forwards and DNS zones): which IoT devices move to which VLAN (creating an IoT or
  Security VLAN when needed), which internet-facing devices belong in a DMZ, and which DNS zones to create and hand out
  on each VLAN. Every step is checked against the network by NCC (unknown devices are dropped, VLAN and subnet clashes,
  switch ports shared with other devices and ports to other switches are flagged, exactly as on the VLANs page) and
  shown with the reason for it. Nothing changes until an admin picks the steps and confirms; deploys reuse the VLAN
  create and move code and are audited. **No API keys**: models are reached through subscriptions you already have,
  by running each vendor's own command-line tool on the NCC server: **Claude Code** (Claude Pro/Max/Team/Enterprise),
  **GitHub Copilot CLI** (any Copilot plan), **Gemini CLI** (Login with Google) and **OpenAI Codex CLI** (ChatGPT
  plans), or a local **Ollama** model that needs no account. Sign-in runs the tool's own sign-in (device code or
  browser link) in a terminal shown on the page; the result goes into the vault and is only written to a private,
  temporary home folder while the tool runs. Without a connected model, NCC's own rules make the plan.
- **Smart home** (the IoT page's Smart home controls tab): lights, plugs, fans, thermostats, locks, garage doors, speakers,
  robot vacuums, cameras, sensors and scenes from **Google Home, Alexa, Matter, Google Nest, Cast, Hue, TP-Link** and
  anything else **Home Assistant** controls, grouped by room or by type. Google Home and Alexa have no open control
  API, so NCC talks to Home Assistant (WebSocket and REST API, long-lived token in the vault). Operators switch,
  dim, set temperatures, lock and run scenes; unlocking doors, opening garage doors and gates and disarming alarms
  need an admin and a confirmation. Offline devices and low batteries are flagged. **Add Matter device** shares a
  device from Google Home, Alexa or Apple Home with a pairing code (checked before pairing: format and check digit)
  so it stays in those apps too. Every change is audited. Setup: [deploy/homeassistant](deploy/homeassistant/README.md).
  Try it with `go run ./cmd/ncc-mock` (Home Assistant on :9123, token `demo-ha-token`).
- **Vault**: a built-in encrypted vault (AES-256-GCM envelope encryption, Argon2id-derived
  master key) or **HashiCorp Vault** (KV v2, token or AppRole). All device and DNS credentials
  live there; values never reach the browser unless an admin reveals them.
- **Certificates**: import certificates and keys (keys go into the vault) with an optional **CA bundle**
  (intermediates and root, in any order; NCC orders them and drops ones that did not issue the certificate),
  add or replace the CA bundle of a stored certificate later, and track expiry.
- **Certificate deployment**: push a certificate from the vault to your servers: **nginx**, **Apache**,
  **Tomcat** (PKCS#12 keystore or PEM), **Splunk Enterprise** (Splunk Web and/or splunkd, web.conf and
  server.conf updated), **Splunk SOAR**, **Foundry VTT** (options.json updated), any **other Linux service**
  (HAProxy, Caddy...) over SSH, and **IIS** over WinRM (PFX import and HTTPS binding). Each server's login
  lives in the vault. Every deployment shows a preview of each file, edit and command first, keeps the old
  files as `.ncc-bak`, then checks that the server now serves the new certificate. See
  [Deploying certificates](#deploying-certificates).
- **Security**: HTTPS by default, Argon2id passwords, TOTP two-factor sign-in, roles
  (viewer, operator, admin), CSRF protection, login rate limiting, and a hash-chained audit log.
- **Accounts**: anyone can change their own password under **Settings** (it asks for the current
  one and logs out every other browser). Admins can reset another user's password, which logs
  that user out everywhere, and delete users. The last admin cannot be deleted.

How NCC is built is described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Port profile editing, BIND (RFC 2136), ACME / Let's Encrypt and more vendors come in later phases.

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

### AI assistant

Open **Configure → AI assistant**, press **Install** on the card for the subscription you have, then
**Sign in** and follow the link and code it shows.

**Install** (admins only) shows the exact commands first and runs them only once you confirm. NCC installs
the tool's official npm package from `registry.npmjs.org` into its own data folder (`<data_dir>/ai-tools`), as
the NCC service user: no root, nothing else on the server changes, and the output streams into the page. It
uses the server's Node.js 20+ (including `/usr/local/node` from the Proxmox installer); when there is none it
downloads the current Node.js LTS from `nodejs.org` into the same folder, after checking it against the
`SHASUMS256.txt` published with it. At the end it runs `<tool> --version` and shows the result. **Settings →
Update** gets the latest version the same way. NCC's own copy is used before one on the `PATH`; a path set in
the card's settings wins over both. The Docker image has no system libraries for Node.js, so there install the
tools in a derived image or run NCC on a VM. You can also install them by hand:

| Provider | Install by hand | Account |
|---|---|---|
| Claude | `npm install -g @anthropic-ai/claude-code` | Claude Pro, Max, Team or Enterprise (`claude setup-token`) |
| GitHub Copilot | `npm install -g @github/copilot` | GitHub with any Copilot plan (device code) |
| Gemini | `npm install -g @google/gemini-cli` | Google account, Login with Google |
| ChatGPT | `npm install -g @openai/codex` | ChatGPT Plus, Pro, Business or Enterprise (device code) |
| Ollama | https://ollama.com | none; set its address and model in the card's settings |

Each card can instead take a sign-in made on another computer (**Paste sign-in**): the `claude setup-token`
output, a `gh auth token`, `~/.gemini/oauth_creds.json` or `~/.codex/auth.json`. API keys are refused.
Anthropic's terms allow a Claude subscription to be used through the unmodified Claude Code tool for your own
use, not to serve other people: connect only your own account, for your own network. **What is sent?** on the
page shows exactly what the model receives (no passwords, keys or certificates). DNS zone steps use the same planner
as the DNS page's Zones & VLANs tab: new zones are delegated from their parent, assigned to the VLAN, and the
router hands them out as that network's DHCP domain.

### Dream Router 7 (or any UniFi OS console)

1. In UniFi OS, go to **Admins & Users** and add an admin with **Restrict to local access only**
   and Network role **View Only**. View-only is enough for everything NCC shows; give it **Site Admin**
   instead if you want to change VLANs or Wi-Fi from NCC.
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

### Router DNS check

The **DNS** page (and the Dashboard's *Needs attention* list) checks the DNS chain:

```
clients ──DHCP DNS──► internal DNS server ──forwarders──► your ISP's DNS servers
```

- **Every router network hands out the internal DNS server.** NCC reads each network's DHCP DNS
  setting from the UniFi console. A network on *Auto* hands out the router itself, which sends
  queries straight to the ISP and bypasses the internal server (fail); handing out a public
  server as a backup (e.g. `8.8.8.8`) is a warning. Guest networks and networks without DHCP on
  the router are not checked.
- **The internal DNS server forwards internet queries to the ISP.** The PowerDNS Authoritative
  server never forwards, so NCC reads the forward zone for `.` from the **PowerDNS Recursor**
  your clients use. Turn on its API in `recursor.conf` (`webserver=yes`, `api-key=…`) and fill in
  **Recursor API URL** (e.g. `http://192.168.1.10:8082`) on the PowerDNS connection in Settings.
  The Recursor should have `forward-zones-recurse=.=<ISP DNS 1>;<ISP DNS 2>`.

The ISP's DNS servers are what the router learned on its WAN (WAN DNS on *Auto*). If you set the
router's WAN DNS by hand, type the ISP's servers into **ISP DNS servers** on the connection. The
address clients should get defaults to the Recursor's address; set **Address clients use** when
that differs (or when NCC reaches it on `localhost`).

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

### Deploying certificates

Open **Certificate deployment**, choose **Add server**, pick the type, and enter the host, the login and
where the files go (sensible defaults are filled in; `{cert}` in a path is the certificate's name). Then
**Deploy**: NCC builds the preview, logs in to test it, and on the first connection shows the server's SSH
host key (or WinRM certificate) for you to confirm. It is pinned from then on, and a changed key stops the
deployment. Deployments run in the background, so closing the browser does not stop one, and they are listed
with every step's output under **Recent deployments** and in the audit log. A **Deploy** link on each
certificate in **Vault & certificates** jumps here with that certificate chosen.

- **Linux servers (SSH)**: log in with a password and/or a private key. File writes and restarts run as root
  through `sudo` (the login password, or a separate sudo password, is passed on stdin), or log in as root.
  Files are uploaded to a private temp file and moved into place; existing files keep their owner and a
  `.ncc-bak` copy. Splunk's default restart is `systemctl restart Splunkd` and it can take a couple of
  minutes to come back; SOAR, Foundry and the generic type can run their restart as a service user.
- **CA bundles**: every server type gets the leaf plus intermediates (never the root, which servers should not
  send). Set the optional **CA bundle file** on a server to also write the intermediates and root to one file
  (for nginx `ssl_trusted_certificate`, Apache `SSLCACertificateFile`, HAProxy `ca-file`...). On Splunk with
  splunkd included it is also set as `sslRootCAPath`. Tomcat keystores and IIS PFX files carry the whole
  bundle; on IIS, **Trust the root CA** adds the root to Trusted Root Certification Authorities.
- **Tomcat**: with the PKCS#12 format NCC makes a keystore password on the first deploy and keeps it in the
  vault, so `server.xml` (`certificateKeystoreFile`, `certificateKeystorePassword`) never has to change.
  The preview shows the `<Certificate>` element to use.
- **IIS (Windows)**: NCC uses WinRM over **HTTPS (port 5986)** with NTLM (local or domain accounts) or Basic.
  If the server has no HTTPS listener yet, run this in an elevated PowerShell on it:

  ```powershell
  $c = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
  New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $c.Thumbprint -Force
  New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow
  ```

  The certificate goes into Local Machine\Personal with its intermediates in the Intermediate store, and is
  bound to the site's HTTPS binding (added if missing; tick **Require SNI** for host-name bindings). The
  previous certificate stays in the store so you can switch back in IIS Manager.

## Try it without touching your network

```sh
go run ./cmd/ncc-mock      # pretend UniFi :9443, PowerDNS :9081, Proxmox VE :9006, vCenter :9007
./bin/ncc -config config.example.yaml
```

To fill the Traffic page's site lists too, uncomment `dns_log` in the config and run
`go run ./cmd/ncc-mock -dnslog localhost:4242`. Add `-loops` to cable two switching loops into the
pretend network.

Add a UniFi console at `https://localhost:9443` (user `ncc`, password `demo-password`) and a
PowerDNS server at `http://localhost:9081` (API key `demo-pdns-key`, Recursor API URL
`http://localhost:9082`, address clients use `192.168.1.10`). On the **Virtual machines**
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

How the pieces fit together (polling, live updates, the vault, the UI's conventions) is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

```
cmd/ncc/                 server entry point
cmd/ncc-mock/            pretend UniFi, PowerDNS, Proxmox VE, vCenter, QNAP, Synology and Home Assistant
internal/api/            HTTP API, auth middleware, static UI
internal/auth/           users, Argon2id, TOTP, sessions, roles
internal/audit/          hash-chained audit log
internal/config/         config.yaml loading and defaults
internal/core/           connections (targets), poller, snapshots, topology, VLAN moves, traffic
internal/inventory/      vendor-neutral network model that device drivers produce
internal/store/          SQLite database and migrations
internal/drivers/        device driver interface; unifi/
internal/dns/            DNS provider interface; powerdns/
internal/hypervisor/     virtual machine provider interface; proxmox/, vmware/
internal/storage/        NAS provider interface; qnap/, synology/, smb/, nfs/, snmpnas/
internal/iot/            IoT inventory: device classification, locations, IoT network policy
internal/smarthome/      smart home provider interface and Matter codes; homeassistant/
internal/dnslog/         PowerDNS Recursor / dnsdist protobuf query-log receiver
internal/vault/          secret store interface; local and HashiCorp backends
internal/pki/            certificate inventory
internal/certdeploy/     certificate deployment over SSH and WinRM
internal/netutil/        shared HTTP client helpers (certificate pinning)
internal/mocklab/        recorded and emulated devices, used by tests and the demo
web/                     React + TypeScript UI (Vite, Cytoscape.js), embedded into the binary
deploy/                  Docker Compose, Proxmox Terraform, Home Assistant setup
```

### Adding a device driver or provider

Implement the interface for the category (`drivers.Driver`, `dns.Provider`,
`hypervisor.Provider`, `storage.Provider` or `smarthome.Provider`), call `Register` from
`init()`, and import the package in `cmd/ncc/main.go`. The steps for the UI side are in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#adding-a-new-kind-of-connection).
