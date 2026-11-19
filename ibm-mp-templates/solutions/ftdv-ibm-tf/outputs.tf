output "instance_id" {
  description = "Owned VSI ID."
  value       = ibm_is_instance.ftdv.id
}

output "instance_name" {
  description = "Owned VSI name."
  value       = ibm_is_instance.ftdv.name
}

output "instance_status" {
  description = "Infrastructure status; running is not proof guest bootstrap is complete."
  value       = ibm_is_instance.ftdv.status
}

output "availability_zone" {
  description = "Zone derived from the existing management subnet."
  value       = local.deployment_zone
}

output "secure_boot_enabled" {
  description = "Boot mode reported by IBM for this VSI."
  value       = ibm_is_instance.ftdv.enable_secure_boot
}

output "management_private_ip" {
  description = "Private management address."
  value       = try(ibm_is_virtual_network_interface.management.primary_ip[0].address, null)
}

output "management_floating_ip" {
  description = "Optional management public address; null when disabled."
  value       = try(ibm_is_floating_ip.management[0].address, null)
}

output "selected_ftdv_image" {
  description = "Selected product image label, exact Catalog version and source digest."
  value = {
    image_label            = local.selected_ftdv_image_version
    catalog_version        = local.selected_ftdv_image.catalog_version
    version_crn            = local.catalog_version_crn
    catalog_sha256         = local.selected_ftdv_image.catalog_sha256
    minimum_boot_volume_gb = local.selected_ftdv_image.minimum_boot_volume_gb
  }
}

output "interface_map" {
  description = "Expected IBM attachment position, product role and owned VNI/IP. Verify the guest mapping after first boot."
  value = {
    eth0 = {
      role       = "data-1"
      vni_id     = ibm_is_virtual_network_interface.data_1.id
      private_ip = try(ibm_is_virtual_network_interface.data_1.primary_ip[0].address, null)
      subnet_id  = data.ibm_is_subnet.data_1.id
    }
    eth1 = {
      role       = "data-2"
      vni_id     = ibm_is_virtual_network_interface.data_2.id
      private_ip = try(ibm_is_virtual_network_interface.data_2.primary_ip[0].address, null)
      subnet_id  = data.ibm_is_subnet.data_2.id
    }
    eth2 = {
      role       = "management"
      vni_id     = ibm_is_virtual_network_interface.management.id
      private_ip = try(ibm_is_virtual_network_interface.management.primary_ip[0].address, null)
      subnet_id  = data.ibm_is_subnet.management.id
    }
    eth3 = {
      role       = "data-3"
      vni_id     = ibm_is_virtual_network_interface.data_3.id
      private_ip = try(ibm_is_virtual_network_interface.data_3.primary_ip[0].address, null)
      subnet_id  = data.ibm_is_subnet.data_3.id
    }
  }
}

output "route_next_hops" {
  description = "Data-interface private IPs for separately managed topology-specific customer routes; the module does not edit routes."
  value = {
    data_1 = try(ibm_is_virtual_network_interface.data_1.primary_ip[0].address, null)
    data_2 = try(ibm_is_virtual_network_interface.data_2.primary_ip[0].address, null)
    data_3 = try(ibm_is_virtual_network_interface.data_3.primary_ip[0].address, null)
  }
}
