# ---------------------------------------------------------------------------
# Proxmox connection (credentials come from environment variables, see versions.tf)
# ---------------------------------------------------------------------------

variable "proxmox_endpoint" {
  description = "Proxmox VE API URL."
  type        = string
  default     = "https://192.168.1.100:8006/"
}

variable "proxmox_insecure" {
  description = "Skip TLS verification of the Proxmox API. Proxmox uses a self-signed certificate by default."
  type        = bool
  default     = true
}

variable "proxmox_ssh_agent" {
  description = "Use the local ssh-agent when the provider needs SSH to the Proxmox node."
  type        = bool
  default     = true
}

variable "proxmox_ssh_username" {
  description = "SSH user on the Proxmox node, used only for operations the API cannot do."
  type        = string
  default     = "root"
}

variable "proxmox_node" {
  description = "Name of the Proxmox node to create the VM on (shown in the left tree of the Proxmox UI)."
  type        = string
  default     = "pve"
}

variable "image_datastore" {
  description = "Datastore that holds the downloaded cloud image. Must allow the 'ISO image' content type."
  type        = string
  default     = "local"
}

variable "snippets_datastore" {
  description = "Datastore for the cloud-init vendor-data snippet that installs the QEMU guest agent. Must allow the 'Snippets' content type (Datacenter > Storage > local > Content)."
  type        = string
  default     = "local"
}

variable "vm_datastore" {
  description = "Datastore for the VM disk and cloud-init drive."
  type        = string
  default     = "local-lvm"
}

variable "cloud_image_url" {
  description = "Ubuntu cloud image to boot from."
  type        = string
  default     = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
}

# ---------------------------------------------------------------------------
# VM
# ---------------------------------------------------------------------------

variable "vm_name" {
  description = "VM name and hostname."
  type        = string
  default     = "ncc"
}

variable "vm_id" {
  description = "Proxmox VM ID. Null picks the next free ID."
  type        = number
  default     = null
}

variable "vm_cores" {
  description = "vCPU cores. Building the app needs at least 2."
  type        = number
  default     = 2
}

variable "vm_cpu_type" {
  description = "QEMU CPU model. \"host\" works on every Proxmox version; \"x86-64-v2-AES\" (Proxmox 8+) allows live migration between different CPUs."
  type        = string
  default     = "host"
}

variable "vm_memory_mb" {
  description = "Memory in MiB. The UI build needs about 2 GiB; 4 GiB leaves headroom."
  type        = number
  default     = 4096
}

variable "vm_disk_gb" {
  description = "Boot disk size in GiB."
  type        = number
  default     = 20
}

variable "vm_bridge" {
  description = "Proxmox bridge for the VM's network card."
  type        = string
  default     = "vmbr0"
}

variable "vm_vlan_id" {
  description = "VLAN tag for the VM's network card. Null for untagged."
  type        = number
  default     = null
}

variable "vm_ipv4_cidr" {
  description = "\"dhcp\" (default), or a static IPv4 address with prefix such as 192.168.1.50/24. With DHCP, Terraform learns the address from the QEMU guest agent; give the VM a DHCP reservation so the NCC URL stays the same."
  type        = string
  default     = "dhcp"

  validation {
    condition     = var.vm_ipv4_cidr == "dhcp" || can(cidrhost(var.vm_ipv4_cidr, 0))
    error_message = "vm_ipv4_cidr must be \"dhcp\" or look like 192.168.1.50/24."
  }
}

variable "vm_ipv4_gateway" {
  description = "Default gateway for a static address, for example 192.168.1.1. Ignored with DHCP."
  type        = string
  default     = null
}

variable "vm_dns_servers" {
  description = "DNS resolvers for a static address. Ignored with DHCP, which supplies its own."
  type        = list(string)
  default     = ["1.1.1.1", "9.9.9.9"]
}

variable "vm_user" {
  description = "Admin user created on the VM (passwordless sudo, SSH key login only)."
  type        = string
  default     = "ncc-admin"
}

variable "ssh_public_keys" {
  description = "SSH public keys allowed to log in as vm_user."
  type        = list(string)

  validation {
    condition     = length(var.ssh_public_keys) > 0
    error_message = "Give at least one SSH public key."
  }
}

variable "ssh_private_key_path" {
  description = "Private key Terraform uses to deploy the app over SSH. Null uses your ssh-agent."
  type        = string
  default     = null
}

variable "ssh_allowed_cidrs" {
  description = "Networks allowed to reach SSH (22) and the NCC web UI on the VM firewall."
  type        = list(string)
  default     = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
}

# ---------------------------------------------------------------------------
# Network Control Centre
# ---------------------------------------------------------------------------

variable "ncc_repo_url" {
  description = "Git repository to build NCC from."
  type        = string
  default     = "https://github.com/dertown/network-control-centre.git"
}

variable "ncc_git_ref" {
  description = "Branch, tag or commit to deploy. Changing it rebuilds and restarts NCC on the next apply."
  type        = string
  default     = "main"
}

variable "ncc_git_token" {
  description = "GitHub token for cloning a private repository. Leave null for a public repository."
  type        = string
  default     = null
  sensitive   = true
}

variable "ncc_port" {
  description = "HTTPS port NCC listens on."
  type        = number
  default     = 8443
}

variable "ncc_poll_interval" {
  description = "How often NCC polls devices."
  type        = string
  default     = "30s"
}

variable "ncc_vault_backend" {
  description = "\"local\" (built-in encrypted vault) or \"hashicorp\"."
  type        = string
  default     = "local"

  validation {
    condition     = contains(["local", "hashicorp"], var.ncc_vault_backend)
    error_message = "ncc_vault_backend must be local or hashicorp."
  }
}

variable "ncc_vault_passphrase" {
  description = "Local vault passphrase for unattended unseal after a restart. Must match the passphrase you choose on first sign-in. Null means you unseal in the UI after each restart."
  type        = string
  default     = null
  sensitive   = true
}

variable "hashicorp_vault" {
  description = "HashiCorp Vault settings, used when ncc_vault_backend = \"hashicorp\". Use AppRole (role_id + secret_id) or a token."
  type = object({
    address     = string
    mount       = optional(string, "secret")
    prefix      = optional(string, "ncc")
    namespace   = optional(string)
    role_id     = optional(string)
    secret_id   = optional(string)
    token       = optional(string)
    ca_cert_pem = optional(string)
  })
  default   = null
  sensitive = true
}
