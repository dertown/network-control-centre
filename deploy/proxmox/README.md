# Deploy NCC to Proxmox VE with Terraform

This creates an Ubuntu 24.04 VM on Proxmox, then builds Network Control Centre from this
repository on the VM and runs it as a hardened systemd service.

What `terraform apply` does:

1. The Proxmox node downloads the Ubuntu cloud image into `image_datastore`.
2. A VM is created from it (2 vCPU, 4 GiB RAM, 20 GiB disk by default) with a static IP,
   your SSH keys and a passwordless-sudo admin user, via cloud-init.
3. Terraform SSHes to the VM and runs [`scripts/install-ncc.sh`](scripts/install-ncc.sh), which
   - installs Go (latest stable) and Node.js 22, clones the repo at `ncc_git_ref` and runs `make build`;
   - writes `/etc/ncc/config.yaml` (and the vault passphrase / CA files if you set them), readable
     only by root and the `ncc` service user;
   - installs and starts `ncc.service` as the unprivileged `ncc` user, data in `/var/lib/ncc`;
   - enables a `ufw` firewall that allows SSH and the NCC port only from `ssh_allowed_cidrs`;
   - waits for `https://127.0.0.1:8443/api/health` and fails the apply (with logs) if NCC does not start.

Changing `ncc_git_ref` (or any NCC setting) and running `terraform apply` again rebuilds and
restarts NCC in place without recreating the VM.

## Requirements

- Terraform 1.6+ (or OpenTofu) on a machine that can reach the Proxmox API **and** the VM's IP over SSH.
- The Proxmox node needs internet access to download the cloud image, and the VM needs it
  to fetch Go, Node.js and the source.
- A Proxmox API token.

## 1. Create a Proxmox API token

In the Proxmox UI: **Datacenter → Permissions → API Tokens → Add**. Pick the user (for example
`root@pam`), give it an ID (for example `claude`) and either untick **Privilege Separation**, or
leave it ticked and grant the token the `PVEAdmin` role on `/`. Copy the secret; Proxmox shows it once.

Export it in the shell you run Terraform from. The value is `<user>@<realm>!<token id>=<secret>`:

```sh
export PROXMOX_VE_API_TOKEN='root@pam!claude=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
```

Never put the token in `terraform.tfvars` or commit it. Password login also works
(`PROXMOX_VE_USERNAME` / `PROXMOX_VE_PASSWORD`) but a token is easier to scope and revoke.

Some provider operations use SSH to the node (as `root`, through your ssh-agent). If the apply
fails with an SSH error, run `ssh-add` with a key the node accepts, or
`export PROXMOX_VE_SSH_PASSWORD=...`.

## 2. Configure

```sh
cd deploy/proxmox
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars
```

At minimum set `proxmox_node`, `vm_ipv4_cidr`, `vm_ipv4_gateway` and `ssh_public_keys`.
Check that `image_datastore` (default `local`) allows the *ISO image* content type and
`vm_datastore` (default `local-lvm`) exists. All variables are documented in [`variables.tf`](variables.tf).

## 3. Apply

```sh
terraform init
terraform apply
```

The first apply takes about 5 to 10 minutes, mostly the UI and Go build. When it finishes,
open the `ncc_url` output, accept the self-signed certificate, and create the admin account
and vault passphrase.

## Vault options

- **Built-in vault (default).** After a reboot NCC starts sealed until an admin unseals it in
  the UI. For unattended restarts, set the passphrase you chose on first sign-in and apply again:
  `export TF_VAR_ncc_vault_passphrase='...' && terraform apply`.
- **HashiCorp Vault.** Set `ncc_vault_backend = "hashicorp"` and pass `hashicorp_vault`
  (address, AppRole `role_id`/`secret_id` or `token`, optional `ca_cert_pem`), ideally through
  `TF_VAR_hashicorp_vault`.

Secrets you pass are written only to the VM's `/etc/ncc` and to Terraform state as a hash. The
state still records variable-derived values, so keep it private (or use an encrypted backend).

## Checking changes offline

`terraform test` runs plan-only checks in [`tests/`](tests/) against a mocked Proxmox provider,
so it needs no Proxmox server or credentials.

## Day-2

- Update NCC: change `ncc_git_ref` (a tag or commit) and `terraform apply`.
- Logs: `ssh ncc-admin@<ip> journalctl -u ncc -f`.
- Data and the local vault live in `/var/lib/ncc` on the VM disk; include the VM in your
  Proxmox backups.
- `terraform destroy` deletes the VM and its data.
