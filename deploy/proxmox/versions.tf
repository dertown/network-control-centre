terraform {
  required_version = ">= 1.6.0"

  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "~> 0.123"
    }
  }
}

# Credentials are never set here. Export one of these before running Terraform:
#   PROXMOX_VE_API_TOKEN='terraform@pve!ncc=<uuid>'         (recommended)
#   PROXMOX_VE_USERNAME='root@pam' PROXMOX_VE_PASSWORD='...'  (works, not recommended)
# See README.md in this folder.
provider "proxmox" {
  endpoint = var.proxmox_endpoint
  insecure = var.proxmox_insecure

  # Some provider operations (for example importing a cloud image as a VM disk on older
  # Proxmox releases) run over SSH to the node. Uses your ssh-agent; set
  # PROXMOX_VE_SSH_PASSWORD instead if you do not use an agent.
  ssh {
    agent    = var.proxmox_ssh_agent
    username = var.proxmox_ssh_username
  }
}
