# Running NCC in an organisation

This guide covers the settings and habits that matter once more than one person relies on
Network Control Centre: who may do what, how to watch it, how to keep its secrets and how to
back it up. Every setting named here is in [config.example.yaml](../config.example.yaml).

## Roles

Each user has one role. A higher role can do everything a lower one can.

| Role | Can | Typical holder |
| --- | --- | --- |
| viewer | See every page, inventory, topology, DNS zones, VMs, storage and smart-home state. | Help desk, auditors |
| operator | Also: change DNS records (plan + apply), poll a connection now, power VMs on and off, create storage folders and snapshots, control smart-home devices, label IoT devices, ask the assistant for a plan. | Network and systems operators |
| admin | Also: add, edit and remove connections and their credentials, users, the vault, certificates, VLAN and Wi-Fi changes, VM settings and deletion, the audit log and its export. | The team that owns NCC |

Every write is checked on the server, never only in the browser, and needs a CSRF header as
well as the session cookie. Sign-ins last `session_ttl` (default 12h, 5m to 720h); changing or
resetting a password signs that user out everywhere. Turn on two-factor sign-in (Settings,
"Two-factor sign-in") for every admin.

## Audit log

Every change, sign-in and failed sign-in is written to a hash-chained audit log, so an edited
or deleted row is detected by **Audit Log → Verify chain**. Admins can download it as CSV or
JSON Lines (`GET /api/audit/export?format=csv` or `?format=jsonl`, with the hash columns so the receiver can check the chain) to keep it in a SIEM. The
download itself is recorded. Cells that a spreadsheet would run as a formula are escaped.

## Health, readiness and metrics

| Endpoint | Use |
| --- | --- |
| `GET /api/health` | Liveness: the process answers. Returns the version. |
| `GET /api/ready` | Readiness: 200 while the database answers, 503 when it doesn't. A sealed vault still counts as ready (the UI is needed to unseal it); the answer and `ncc_vault_sealed` say so. Use it for load balancers. |
| `GET /metrics` | Prometheus metrics when `metrics.enabled` is true: HTTP requests by method and status, durations, polls by connection type and result, connections by state, vault sealed. Protect it with `metrics.token_file`. |
| `ncc healthcheck` | The same as `/api/ready` from inside the container; the Docker image's `HEALTHCHECK` uses it. |

## Logging and request IDs

`log.format: json` writes one JSON object per line on stderr for Loki, Elastic or Splunk;
`log.level` picks the detail. Every request gets an `X-Request-ID` (kept from the caller when it
is a sensible value), which appears in the access log and the response, so a user's error can
be matched to the log line.

Behind a reverse proxy, list it in `trusted_proxies`. NCC then uses the client address from
`X-Forwarded-For` for the sign-in rate limit, the access log and the audit log. Addresses from
anyone else are ignored, so the header cannot be forged.

## Secrets

Device credentials never leave the vault: the API returns them only to admins who ask to
reveal one, and that is audited.

- **Local vault** (default): AES-GCM, sealed until unlocked with the passphrase. For unattended
  starts use `vault.passphrase_file` (mode 600) or `NCC_VAULT_PASSPHRASE`.
- **HashiCorp Vault**: KV v2 with AppRole or a token. Keep the token or secret id out of the
  config with `vault.token_file` / `vault.secret_id_file` (a Docker or Kubernetes secret, a
  systemd credential). Vault Enterprise namespaces are supported.

## TLS

NCC serves HTTPS itself (`tls_cert`/`tls_key`, or a self-signed certificate in `data_dir`), or
plain HTTP behind a proxy that terminates HTTPS (`plain_http` + `behind_tls_proxy` so cookies keep
the Secure flag). Connections to devices verify their certificates, or pin a fingerprint the
first time (trust on first use) for appliances with self-signed certificates.

## Checking a configuration

`ncc -config config.yaml -check-config` validates the file and exits: unknown keys are reported
as warnings, and impossible values (a bad listen address, a poll interval under 5s, half a TLS
pair, an unknown vault backend) as errors naming the setting. NCC does the same at startup.

## Backup and restore

Everything NCC keeps is in `data_dir`: `ncc.db` (SQLite: connections, users, audit log,
history and, with the local vault, the encrypted secrets) and the generated TLS certificate. Back up the whole directory, and the vault
passphrase separately; without the passphrase the vault cannot be opened. For a consistent copy
while NCC runs use `sqlite3 ncc.db ".backup ncc-backup.db"`. To restore, stop NCC, put the
files back and start it.

## Not done yet

These are planned but not part of NCC today:

- Single sign-on (OIDC / SAML, Entra ID sign-in) and LDAP / AD group mapping to roles.
- Running several NCC instances against one database (it is a single process with SQLite).
- Forwarding the audit log to syslog as it is written (export it on a schedule instead).
- Per-connection permissions (roles apply to every connection).
