output "instance_id" {
  description = "ID of the deployed ASAv virtual server instance."
  value       = ibm_is_instance.asav.id
}

output "instance_name" {
  description = "Name of the deployed ASAv virtual server instance."
  value       = ibm_is_instance.asav.name
}

output "instance_status" {
  description = "Current status reported by IBM Cloud for the ASAv VSI."
  value       = ibm_is_instance.asav.status
}

output "availability_zone" {
  description = "Availability zone derived from the existing management subnet."
  value       = local.deployment_zone
}

output "selected_asav_image" {
  description = "ASAv and Catalog image version selected for this deployment."
  value = {
    asav_version    = local.selected_asav_image_version
    catalog_version = local.selected_asav_image.catalog_version
    version_crn     = local.catalog_version_crn
    catalog_sha256  = local.selected_asav_image.catalog_sha256
  }
}

output "secure_boot_enabled" {
  description = "Secure Boot mode reported for the deployed ASAv VSI."
  value       = ibm_is_instance.asav.enable_secure_boot
}

output "management_floating_ip" {
  description = "Management floating IP when create_management_floating_ip is true; otherwise null."
  value       = try(ibm_is_floating_ip.management[0].address, null)
}

output "interface_map" {
  description = "Validated IBM NIC-to-ASAv interface mapping. Confirm it on first boot with show interface ip brief."
  value = {
    eth0 = {
      role           = "management"
      example_role   = "management"
      asav_interface = "Management0/0"
      vni_id         = ibm_is_virtual_network_interface.management.id
      private_ip     = try(ibm_is_virtual_network_interface.management.primary_ip[0].address, null)
      subnet_id      = data.ibm_is_subnet.management.id
    }
    eth1 = {
      role           = "data-1"
      example_role   = "inside/trusted"
      asav_interface = "GigabitEthernet0/0"
      vni_id         = ibm_is_virtual_network_interface.data_1.id
      private_ip     = try(ibm_is_virtual_network_interface.data_1.primary_ip[0].address, null)
      subnet_id      = data.ibm_is_subnet.data_1.id
    }
    eth2 = {
      role           = "data-2"
      example_role   = "outside/untrusted"
      asav_interface = "GigabitEthernet0/1"
      vni_id         = ibm_is_virtual_network_interface.data_2.id
      private_ip     = try(ibm_is_virtual_network_interface.data_2.primary_ip[0].address, null)
      subnet_id      = data.ibm_is_subnet.data_2.id
    }
  }
}

output "route_next_hops" {
  description = "Data-interface private IPs that a network administrator can use as next hops in topology-specific VPC custom routes."
  value = {
    data_1 = try(ibm_is_virtual_network_interface.data_1.primary_ip[0].address, null)
    data_2 = try(ibm_is_virtual_network_interface.data_2.primary_ip[0].address, null)
  }
}
