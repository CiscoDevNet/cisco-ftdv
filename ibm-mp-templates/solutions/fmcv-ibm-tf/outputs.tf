output "instance_id" {
  description = "Owned VSI ID."
  value       = ibm_is_instance.fmcv.id
}

output "instance_name" {
  description = "Owned VSI name."
  value       = ibm_is_instance.fmcv.name
}

output "instance_status" {
  description = "Infrastructure status; running is not proof guest bootstrap is complete."
  value       = ibm_is_instance.fmcv.status
}

output "availability_zone" {
  description = "Zone derived from the existing management subnet."
  value       = local.deployment_zone
}

output "secure_boot_enabled" {
  description = "Boot mode reported by IBM for this VSI."
  value       = ibm_is_instance.fmcv.enable_secure_boot
}

output "management_private_ip" {
  description = "Private management address."
  value       = try(ibm_is_virtual_network_interface.management.primary_ip[0].address, null)
}

output "management_floating_ip" {
  description = "Optional management public address; null when disabled."
  value       = try(ibm_is_floating_ip.management[0].address, null)
}

output "selected_fmcv_image" {
  description = "Selected product image label, exact Catalog version and source digest."
  value = {
    image_label            = local.selected_fmcv_image_version
    catalog_version        = local.selected_fmcv_image.catalog_version
    version_crn            = local.catalog_version_crn
    catalog_sha256         = local.selected_fmcv_image.catalog_sha256
    minimum_boot_volume_gb = local.selected_fmcv_image.minimum_boot_volume_gb
  }
}

output "interface_map" {
  description = "Expected IBM attachment position, product role and owned VNI/IP. Verify the guest mapping after first boot."
  value = {
    eth0 = {
      role       = "management"
      vni_id     = ibm_is_virtual_network_interface.management.id
      private_ip = try(ibm_is_virtual_network_interface.management.primary_ip[0].address, null)
      subnet_id  = data.ibm_is_subnet.management.id
    }
  }
}

output "management_public_url" {
  description = "HTTPS URL only when a management FIP is created; use the private address through a reachable private path otherwise."
  value       = try("https://${ibm_is_floating_ip.management[0].address}", null)
}
