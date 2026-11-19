# Offline checks: `terraform test` with a mocked Proxmox provider (no Proxmox needed).
mock_provider "proxmox" {}

variables {
  vm_ipv4_cidr    = "192.168.1.50/24"
  vm_ipv4_gateway = "192.168.1.1"
  ssh_public_keys = ["ssh-ed25519 AAAAtest test@example"]
}

run "local_vault_defaults" {
  command = plan

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

run "rejects_bad_ip" {
  command = plan
  variables {
    vm_ipv4_cidr = "192.168.1.50"
  }
  expect_failures = [var.vm_ipv4_cidr]
}
