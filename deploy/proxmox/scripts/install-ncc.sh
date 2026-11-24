#!/usr/bin/env bash
# Builds Network Control Centre from source and runs it as a systemd service.
# Run as root by Terraform (deploy/proxmox). Safe to re-run: it updates in place.
#
# Usage: install-ncc.sh <bundle.env>
set -euo pipefail

BUNDLE=${1:?usage: install-ncc.sh <bundle.env>}
BUNDLE_DIR=$(dirname "$BUNDLE")
# shellcheck disable=SC1090
source "$BUNDLE"

b64() { base64 -d <<<"$1"; }
REPO_URL=$(b64 "$NCC_REPO_URL_B64")
GIT_REF=$(b64 "$NCC_GIT_REF_B64")
GIT_TOKEN=$(b64 "$NCC_GIT_TOKEN_B64" | tr -d '[:space:]')
PASSPHRASE=$(b64 "$NCC_PASSPHRASE_B64")
VAULT_CA=$(b64 "$NCC_VAULT_CA_B64")

SRC=/opt/ncc/src
log() { echo "==> $*"; }

# --- packages --------------------------------------------------------------
log "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q --no-install-recommends \
  git make curl ca-certificates python3 qemu-guest-agent ufw
systemctl enable --now qemu-guest-agent || true

case "$(dpkg --print-architecture)" in
  amd64) GO_ARCH=amd64 NODE_ARCH=x64 ;;
  arm64) GO_ARCH=arm64 NODE_ARCH=arm64 ;;
  *) echo "unsupported architecture" >&2; exit 1 ;;
esac

# --- Go (latest stable; go.mod needs 1.26+) --------------------------------
GO_VERSION=$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -n1)
if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "${GO_VERSION} "; then
  log "Installing ${GO_VERSION}"
  rm -rf /usr/local/go
  curl -fsSL "https://go.dev/dl/${GO_VERSION}.linux-${GO_ARCH}.tar.gz" | tar -C /usr/local -xz
fi

# --- Node.js 22 (for the web UI build) -------------------------------------
NODE_VERSION=$(curl -fsSL https://nodejs.org/dist/index.json |
  python3 -c 'import json,sys; print(next(r["version"] for r in json.load(sys.stdin) if r["version"].startswith("v22.")))')
if [ "$(/usr/local/node/bin/node --version 2>/dev/null || true)" != "$NODE_VERSION" ]; then
  log "Installing Node.js ${NODE_VERSION}"
  rm -rf "/usr/local/lib/node-${NODE_VERSION}"
  mkdir -p "/usr/local/lib/node-${NODE_VERSION}"
  curl -fsSL "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-${NODE_ARCH}.tar.gz" |
    tar -C "/usr/local/lib/node-${NODE_VERSION}" --strip-components=1 -xz
  ln -sfn "/usr/local/lib/node-${NODE_VERSION}" /usr/local/node
fi

# --- service user ----------------------------------------------------------
if ! id ncc >/dev/null 2>&1; then
  useradd --system --home-dir /opt/ncc --create-home --shell /usr/sbin/nologin ncc
fi
install -d -o ncc -g ncc -m 0750 /var/lib/ncc
install -d -o root -g ncc -m 0750 /etc/ncc

# --- source ----------------------------------------------------------------
log "Fetching ${REPO_URL} @ ${GIT_REF}"
GIT_AUTH=()
if [ -n "$GIT_TOKEN" ]; then
  # Sent as a header for this command only; never written to .git/config.
  GIT_AUTH=(-c "http.extraHeader=Authorization: Basic $(printf 'x-access-token:%s' "$GIT_TOKEN" | base64 -w0)")
fi
as_ncc() { runuser -u ncc -- env HOME=/opt/ncc PATH="/usr/local/go/bin:/usr/local/node/bin:/usr/bin:/bin" "$@"; }
if [ ! -d "$SRC/.git" ]; then
  as_ncc git init -q "$SRC"
  as_ncc git -C "$SRC" remote add origin "$REPO_URL"
fi
as_ncc git -C "$SRC" remote set-url origin "$REPO_URL"
as_ncc git "${GIT_AUTH[@]}" -C "$SRC" fetch -q --tags --force origin "$GIT_REF"
as_ncc git -C "$SRC" checkout -q --force FETCH_HEAD
as_ncc git -C "$SRC" clean -q -fdx -e web/node_modules

# --- build -----------------------------------------------------------------
log "Building (UI + Go binary)"
as_ncc make -C "$SRC" build
install -m 0755 "$SRC/bin/ncc" /usr/local/bin/ncc.new
mv -f /usr/local/bin/ncc.new /usr/local/bin/ncc
log "Built $(/usr/local/bin/ncc version)"

# --- config and secrets ----------------------------------------------------
umask 027
b64 "$NCC_CONFIG_B64" >/etc/ncc/config.yaml
if [ -n "$(tr -d '[:space:]' <<<"$PASSPHRASE")" ]; then
  printf '%s' "$PASSPHRASE" >/etc/ncc/vault-passphrase
else
  rm -f /etc/ncc/vault-passphrase
fi
if [ -n "$(tr -d '[:space:]' <<<"$VAULT_CA")" ]; then
  printf '%s\n' "$VAULT_CA" >/etc/ncc/vault-ca.pem
else
  rm -f /etc/ncc/vault-ca.pem
fi
chown root:ncc /etc/ncc/*
chmod 0640 /etc/ncc/*
umask 022

# --- systemd ---------------------------------------------------------------
cat >/etc/systemd/system/ncc.service <<'UNIT'
[Unit]
Description=Network Control Centre
After=network-online.target
Wants=network-online.target

[Service]
User=ncc
Group=ncc
ExecStart=/usr/local/bin/ncc -config /etc/ncc/config.yaml
Restart=on-failure
RestartSec=5
WorkingDirectory=/var/lib/ncc

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
ReadWritePaths=/var/lib/ncc
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable ncc >/dev/null
systemctl restart ncc

# --- firewall --------------------------------------------------------------
log "Configuring firewall"
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
for cidr in $NCC_ALLOWED_CIDRS; do
  ufw allow from "$cidr" to any port 22 proto tcp >/dev/null
  ufw allow from "$cidr" to any port "$NCC_PORT" proto tcp >/dev/null
done
# DNS query logs (dns_log): only the resolvers that send them may connect.
if [ -n "${NCC_DNS_LOG_PORT:-}" ]; then
  for src in ${NCC_DNS_LOG_ALLOW:-}; do
    ufw allow from "$src" to any port "$NCC_DNS_LOG_PORT" proto tcp >/dev/null
  done
fi
ufw --force enable >/dev/null

# --- health check ----------------------------------------------------------
log "Waiting for NCC to answer on :${NCC_PORT}"
for _ in $(seq 1 30); do
  if curl -fsk "https://127.0.0.1:${NCC_PORT}/api/health" >/dev/null; then
    rm -rf "$BUNDLE_DIR"
    log "NCC is running"
    exit 0
  fi
  sleep 2
done
rm -rf "$BUNDLE_DIR"
echo "NCC did not become healthy. Recent logs:" >&2
journalctl -u ncc -n 50 --no-pager >&2
exit 1
