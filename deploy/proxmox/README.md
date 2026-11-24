# Deploy NCC to Proxmox VE with Terraform

This creates an Ubuntu 24.04 VM on Proxmox, then builds Network Control Centre from this
repository on the VM and runs it as a hardened systemd service.

What `terraform apply` does:

1. The Proxmox node downloads the Ubuntu cloud image into `image_datastore`.
2. A VM is created from it (2 vCPU, 4 GiB RAM, 20 GiB disk by default) with your SSH keys and
   a passwordless-sudo admin user, via cloud-init. It uses DHCP by default (or a static IP), and
   a small cloud-init vendor-data snippet installs the QEMU guest agent so Terraform can read
   the address the VM was given.
3. Terraform SSHes to the VM and runs [`scripts/install-ncc.sh`](scripts/install-ncc.sh), which
   - installs Go (latest stable) and Node.js 22, clones the repo at `ncc_git_ref` and runs `make build`;
   - writes `/etc/ncc/config.yaml` (and the vault passphrase / CA files if you set them), readable
     only by root and the `ncc` service user;
   - installs and starts `ncc.service` as the unprivileged `ncc` user, data in `/var/lib/ncc`;
   - enables a `ufw` firewall that allows SSH and the NCC port only from `ssh_allowed_cidrs`
     (and, with `ncc_dns_log`, the DNS query log port only from the resolvers in its `allow`);
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

At minimum set `proxmox_node` and `ssh_public_keys`. The VM uses DHCP unless you set
`vm_ipv4_cidr` and `vm_ipv4_gateway`. With DHCP, add a reservation for the VM on your router
once it is created, so the NCC address does not change.

Check the datastores on the node:

- `image_datastore` (default `local`) must allow the *ISO image* content type.
- `snippets_datastore` (default `local`) must allow *Snippets*. It does not by default; enable it
  under **Datacenter → Storage → local → Edit → Content**, or on the node:
  `pvesm set local --content iso,vztmpl,backup,snippets`.
- `vm_datastore` (default `local-lvm`) must exist.

Snippets are uploaded over SSH to the node, so the provider needs SSH as `root` to it (see above). All variables are documented in [`variables.tf`](variables.tf).

## 3. Apply

```sh
terraform init
terraform apply
```

The first apply takes about 5 to 10 minutes, mostly the UI and Go build. When it finishes,
open the `ncc_url` output, accept the self-signed certificate, and create the admin account
and vault passphrase.

## Proxmox 7.x notes

The defaults work on Proxmox 7.3 and later (tested on 7.3-4). On 7.x the provider may report
`Disk resize ... the server did not include a data object in the response` while creating the
VM even though the resize succeeded. Check `qm config <vmid>` shows the right disk size, then run
`terraform untaint proxmox_virtual_environment_vm.ncc` and `terraform apply` again so the VM is
not recreated. Proxmox 8 does not have this problem.

## Running from Windows

Use PowerShell (MobaXterm's local terminal also works, but the commands below are PowerShell).

1. Install Terraform and Git: `winget install Hashicorp.Terraform Git.Git`, then open a new PowerShell window.
2. Get the code: `git clone https://github.com/dertown/network-control-centre.git` and `cd network-control-centre\deploy\proxmox`.
   This repo's `.gitattributes` keeps `scripts/install-ncc.sh` on LF line endings, which the VM needs.
3. Create `terraform.tfvars` (see step 2 above). On Windows, set `proxmox_ssh_agent = false` and give
   the node's root password through the environment instead (step 4).
4. Make the private key that matches `ssh_public_keys` available to Terraform, one of:
   - **Pageant / MobAgent**: Terraform uses Pageant as its SSH agent on Windows. In MobaXterm, enable
     *Settings → SSH → SSH agents → MobAgent* and load your `.ppk`, or load it in Pageant. Leave
     `ssh_private_key_path` unset.
   - **Key file**: Terraform cannot read `.ppk` files. In PuTTYgen (or *MobaXterm → Tools → MobaKeyGen*),
     load the `.ppk` and use *Conversions → Export OpenSSH key*, save it as
     `C:\Users\<you>\.ssh\id_ed25519`, and set `ssh_private_key_path = "~/.ssh/id_ed25519"`.
5. Set credentials for this PowerShell session only (single quotes keep the `!` literal):

   ```powershell
   $env:PROXMOX_VE_API_TOKEN    = 'root@pam!claude=<token secret>'
   $env:PROXMOX_VE_SSH_PASSWORD = '<root password of the Proxmox node>'
   ```

6. `terraform init`, then `terraform apply` and type `yes`. When it finishes, open the `ncc_url` it prints.

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
