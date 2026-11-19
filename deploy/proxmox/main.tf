locals {
  use_dhcp = var.vm_ipv4_cidr == "dhcp"

  # With DHCP the address comes from the QEMU guest agent: the first non-loopback IPv4.
  vm_ip = local.use_dhcp ? try(
    [for ip in flatten(proxmox_virtual_environment_vm.ncc.ipv4_addresses) : ip if !startswith(ip, "127.")][0],
    null
  ) : split("/", var.vm_ipv4_cidr)[0]

  use_hashicorp = var.ncc_vault_backend == "hashicorp"
  hc            = local.use_hashicorp ? var.hashicorp_vault : null
  hc_ca_pem     = local.use_hashicorp ? try(coalesce(local.hc.ca_cert_pem, ""), "") : ""

  # /etc/ncc/config.yaml on the VM. Secrets (HashiCorp token / secret_id) end up in this
  # file, which is readable only by root and the ncc service user.
  ncc_config = merge(
    {
      listen   = ":${var.ncc_port}"
      data_dir = "/var/lib/ncc"
      poll     = var.ncc_poll_interval
    },
    {
      vault = local.use_hashicorp ? {
        for k, v in {
          backend   = "hashicorp"
          address   = local.hc.address
          mount     = local.hc.mount
          prefix    = local.hc.prefix
          namespace = local.hc.namespace
          role_id   = local.hc.role_id
          secret_id = local.hc.secret_id
          token     = local.hc.token
          ca_cert   = local.hc_ca_pem != "" ? "/etc/ncc/vault-ca.pem" : null
        } : k => v if v != null
        } : merge(
        { backend = "local" },
        var.ncc_vault_passphrase != null ? { passphrase_file = "/etc/ncc/vault-passphrase" } : {}
      )
    }
  )

  ncc_config_yaml = yamlencode(local.ncc_config)

  # Everything the install script needs, as one shell-sourceable file. Values are base64
  # so that no secret ever has to survive shell quoting or appear on a command line.
  deploy_bundle = join("\n", [
    "NCC_REPO_URL_B64=${base64encode(var.ncc_repo_url)}",
    "NCC_GIT_REF_B64=${base64encode(var.ncc_git_ref)}",
    "NCC_GIT_TOKEN_B64=${base64encode(coalesce(var.ncc_git_token, " "))}",
    "NCC_CONFIG_B64=${base64encode(local.ncc_config_yaml)}",
    "NCC_PASSPHRASE_B64=${base64encode(coalesce(var.ncc_vault_passphrase, " "))}",
    "NCC_VAULT_CA_B64=${base64encode(coalesce(local.hc_ca_pem, " "))}",
    "NCC_PORT=${var.ncc_port}",
    "NCC_ALLOWED_CIDRS='${join(" ", var.ssh_allowed_cidrs)}'",
    "",
  ])
}

# Ubuntu cloud image, downloaded by the Proxmox node itself.
resource "proxmox_download_file" "cloud_image" {
  node_name    = var.proxmox_node
  datastore_id = var.image_datastore
  content_type = "iso"
  url          = var.cloud_image_url
  file_name    = "${var.vm_name}-${basename(var.cloud_image_url)}"
  overwrite    = false
}

# Cloud-init vendor data: installs the QEMU guest agent on first boot so Proxmox (and
# Terraform) can see the VM's IP address. Kept free of secrets; user and SSH keys come
# from the user_account block below.
resource "proxmox_virtual_environment_file" "vendor_data" {
  node_name    = var.proxmox_node
  datastore_id = var.snippets_datastore
  content_type = "snippets"

  source_raw {
    file_name = "${var.vm_name}-vendor-data.yaml"
    data      = <<-EOT
      #cloud-config
      package_update: true
      packages:
        - qemu-guest-agent
      runcmd:
        - systemctl enable --now qemu-guest-agent
    EOT
  }
}

resource "proxmox_virtual_environment_vm" "ncc" {
  name        = var.vm_name
  description = "Network Control Centre. Managed by Terraform (deploy/proxmox)."
  tags        = ["ncc", "terraform"]
  node_name   = var.proxmox_node
  vm_id       = var.vm_id

  on_boot         = true
  started         = true
  stop_on_destroy = true

  # The guest agent is installed on first boot by the vendor-data snippet below. The
  # provider waits for it to report the VM's IP address.
  agent {
    enabled = true
    timeout = "15m"
    trim    = true
  }

  cpu {
    cores = var.vm_cores
    type  = "x86-64-v2-AES"
  }

  memory {
    dedicated = var.vm_memory_mb
  }

  operating_system {
    type = "l26"
  }

  disk {
    datastore_id = var.vm_datastore
    file_id      = proxmox_download_file.cloud_image.id
    interface    = "virtio0"
    iothread     = true
    discard      = "on"
    size         = var.vm_disk_gb
  }

  network_device {
    bridge  = var.vm_bridge
    vlan_id = var.vm_vlan_id
  }

  # Ubuntu cloud images log to the serial console.
  serial_device {}

  initialization {
    datastore_id = var.vm_datastore

    ip_config {
      ipv4 {
        address = var.vm_ipv4_cidr
        gateway = local.use_dhcp ? null : var.vm_ipv4_gateway
      }
    }

    dynamic "dns" {
      for_each = local.use_dhcp ? [] : [1]
      content {
        servers = var.vm_dns_servers
      }
    }

    vendor_data_file_id = proxmox_virtual_environment_file.vendor_data.id

    user_account {
      username = var.vm_user
      keys     = var.ssh_public_keys
    }
  }

  lifecycle {
    # A new cloud image upstream should not rebuild a running server.
    ignore_changes = [disk[0].file_id]

    precondition {
      condition     = local.use_dhcp || var.vm_ipv4_gateway != null
      error_message = "Set vm_ipv4_gateway when vm_ipv4_cidr is a static address."
    }
  }
}

# Builds NCC from source on the VM and runs it as a systemd service. Re-runs whenever
# the VM is replaced, the git ref changes, or the rendered config/secrets change.
resource "terraform_data" "deploy_ncc" {
  triggers_replace = [
    proxmox_virtual_environment_vm.ncc.id,
    var.ncc_git_ref,
    sha256(local.deploy_bundle),
    filesha256("${path.module}/scripts/install-ncc.sh"),
  ]

  lifecycle {
    precondition {
      condition     = local.vm_ip != null
      error_message = "The QEMU guest agent did not report an IPv4 address for the VM. Check that the VM got a DHCP lease and that the vendor-data snippet ran (Proxmox VM > Summary > IPs)."
    }
  }

  connection {
    type        = "ssh"
    host        = local.vm_ip
    user        = var.vm_user
    private_key = var.ssh_private_key_path != null ? file(pathexpand(var.ssh_private_key_path)) : null
    agent       = var.ssh_private_key_path == null
    timeout     = "10m"
  }

  provisioner "remote-exec" {
    inline = [
      "cloud-init status --wait >/dev/null || true",
      "install -d -m 0700 \"$HOME/.ncc-deploy\"",
    ]
  }

  provisioner "file" {
    source      = "${path.module}/scripts/install-ncc.sh"
    destination = "/home/${var.vm_user}/.ncc-deploy/install-ncc.sh"
  }

  provisioner "file" {
    content     = local.deploy_bundle
    destination = "/home/${var.vm_user}/.ncc-deploy/bundle.env"
  }

  provisioner "remote-exec" {
    inline = [
      "sudo bash \"$HOME/.ncc-deploy/install-ncc.sh\" \"$HOME/.ncc-deploy/bundle.env\"",
    ]
  }
}
