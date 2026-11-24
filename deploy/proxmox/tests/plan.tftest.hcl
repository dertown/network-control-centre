# Offline checks: `terraform test` with a mocked Proxmox provider (no Proxmox needed).
mock_provider "proxmox" {}

variables {
  ssh_public_keys = ["ssh-ed25519 AAAAtest test@example"]
}

run "dhcp_by_default" {
  command = plan

  assert {
    condition     = proxmox_virtual_environment_vm.ncc.initialization[0].ip_config[0].ipv4[0].address == "dhcp"
    error_message = "VM should use DHCP by default"
  }
  assert {
    condition     = proxmox_virtual_environment_vm.ncc.agent[0].enabled
    error_message = "guest agent must be enabled to discover the DHCP address"
  }
}

run "local_vault_defaults" {
  command = plan
  variables {
    vm_ipv4_cidr    = "192.168.1.50/24"
    vm_ipv4_gateway = "192.168.1.1"
  }

  assert {
    condition     = yamldecode(local.ncc_config_yaml).vault.backend == "local"
    error_message = "default vault backend should be local"
  }
  assert {
    condition     = !can(yamldecode(local.ncc_config_yaml).vault.passphrase_file)
    error_message = "no passphrase file unless a passphrase is set"
  }
  assert {
    condition     = yamldecode(local.ncc_config_yaml).listen == ":8443"
    error_message = "listen address"
  }
  assert {
    condition     = output.ncc_url == "https://192.168.1.50:8443"
    error_message = "ncc_url output"
  }
}

run "local_vault_with_passphrase" {
  command = plan
  variables {
    ncc_vault_passphrase = "correct horse"
  }
  assert {
    condition     = yamldecode(local.ncc_config_yaml).vault.passphrase_file == "/etc/ncc/vault-passphrase"
    error_message = "passphrase file should be configured"
  }
}

run "hashicorp_vault" {
  command = plan
  variables {
    ncc_vault_backend = "hashicorp"
    hashicorp_vault = {
      address     = "https://vault.home.lan:8200"
      role_id     = "role"
      secret_id   = "secret"
      ca_cert_pem = "-----BEGIN CERTIFICATE-----"
    }
  }
  assert {
    condition = yamldecode(local.ncc_config_yaml).vault == {
      backend   = "hashicorp"
      address   = "https://vault.home.lan:8200"
      mount     = "secret"
      prefix    = "ncc"
      role_id   = "role"
      secret_id = "secret"
      ca_cert   = "/etc/ncc/vault-ca.pem"
    }
    error_message = "hashicorp vault config"
  }
}

run "static_needs_gateway" {
  command = plan
  variables {
    vm_ipv4_cidr = "192.168.1.50/24"
  }
  expect_failures = [proxmox_virtual_environment_vm.ncc]
}

run "rejects_bad_ip" {
  command = plan
  variables {
    vm_ipv4_cidr = "192.168.1.50"
  }
  expect_failures = [var.vm_ipv4_cidr]
}

run "dns_log_off_by_default" {
  command = plan
  assert {
    condition     = !can(yamldecode(local.ncc_config_yaml).dns_log)
    error_message = "dns_log should be absent unless ncc_dns_log is set"
  }
  assert {
    condition     = strcontains(local.deploy_bundle, "NCC_DNS_LOG_PORT=\n")
    error_message = "no DNS log port should be opened by default"
  }
}

run "dns_log_on" {
  command = plan
  variables {
    ncc_dns_log = { allow = ["192.168.1.70"] }
  }
  assert {
    condition = yamldecode(local.ncc_config_yaml).dns_log == {
      listen = ":4242"
      allow  = ["192.168.1.70"]
      retain = "168h"
    }
    error_message = "dns_log config"
  }
  assert {
    condition     = strcontains(local.deploy_bundle, "NCC_DNS_LOG_PORT=4242\nNCC_DNS_LOG_ALLOW='192.168.1.70'")
    error_message = "firewall should open 4242 to the resolver only"
  }
}

run "dns_log_needs_allow" {
  command = plan
  variables {
    ncc_dns_log = { allow = [] }
  }
  expect_failures = [var.ncc_dns_log]
}
