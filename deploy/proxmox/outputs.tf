output "vm_id" {
  description = "Proxmox VM ID."
  value       = proxmox_virtual_environment_vm.ncc.vm_id
}

output "ssh" {
  description = "SSH command for the VM."
  value       = "ssh ${var.vm_user}@${local.vm_ip}"
}

output "ncc_url" {
  description = "Network Control Centre web UI. The first visit asks you to create the admin account and vault passphrase."
  value       = "https://${local.vm_ip}:${var.ncc_port}"
}
