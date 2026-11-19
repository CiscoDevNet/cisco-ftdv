resource "ibm_is_virtual_network_interface" "management" {
  name                          = "${var.prefix}-mgmt-vni"
  subnet                        = data.ibm_is_subnet.management.id
  security_groups               = [var.management_security_group_id]
  resource_group                = data.ibm_resource_group.target.id
  auto_delete                   = false
  enable_infrastructure_nat     = true
  allow_ip_spoofing             = false
  protocol_state_filtering_mode = "auto"
}

resource "ibm_is_instance" "fmcv" {
  name               = "${var.prefix}-vsi"
  vpc                = data.ibm_is_vpc.target.id
  zone               = local.deployment_zone
  profile            = data.ibm_is_instance_profile.selected.name
  resource_group     = data.ibm_resource_group.target.id
  enable_secure_boot = var.enable_secure_boot

  catalog_offering {
    version_crn = local.catalog_version_crn
    plan_crn    = local.catalog_plan_crn == "" ? null : local.catalog_plan_crn
  }

  primary_network_attachment {
    name = "management"
    virtual_network_interface {
      id = ibm_is_virtual_network_interface.management.id
    }
  }

  keys      = [data.ibm_is_ssh_key.selected.id]
  user_data = local.effective_user_data
  tags      = var.tags

  metadata_service {
    enabled            = var.enable_metadata_service
    protocol           = var.metadata_service_protocol
    response_hop_limit = 1
  }
  boot_volume {
    name               = "${var.prefix}-boot"
    auto_delete_volume = true
  }
  timeouts {
    create = "60m"
    update = "60m"
    delete = "60m"
  }
  lifecycle {
    precondition {
      condition     = local.catalog_reference_ready
      error_message = "Publisher action required: verify the exact accessible VSI version CRN and locator in the product image JSON before deployment."
    }
    precondition {
      condition     = length(toset(local.subnet_ids)) == 1
      error_message = "Use the existing management subnet for this one-interface topology."
    }
    precondition {
      condition     = alltrue([for vpc in local.subnet_vpc_ids : vpc == data.ibm_is_vpc.target.id])
      error_message = "All selected subnets must belong to vpc_id."
    }
    precondition {
      condition     = length(toset(local.subnet_zones)) == 1
      error_message = "All interfaces of this VSI must be in the same availability zone."
    }
    precondition {
      condition     = local.deployment_region == var.region
      error_message = "region must match the selected subnet zone."
    }
    precondition {
      condition     = contains(local.catalog_supported_regions, var.region)
      error_message = "The selected image is not published in the requested region."
    }
    precondition {
      condition     = length(local.missing_security_group_ids) == 0
      error_message = "Every selected SG must belong to the requested VPC."
    }
    precondition {
      condition     = try(one(data.ibm_is_instance_profile.selected.network_attachment_count).max, 0) >= 1
      error_message = "The selected live profile must support at least one network attachment."
    }
    precondition {
      condition     = contains(local.catalog_supported_profiles, var.instance_profile)
      error_message = "The selected image does not qualify the requested profile."
    }
    precondition {
      condition     = contains([for zone in data.ibm_is_instance_profile.selected.zones : zone.name], local.deployment_zone)
      error_message = "The profile is not available in the selected subnet zone."
    }
    precondition {
      condition     = contains(local.catalog_supported_secure_boot_modes, var.enable_secure_boot) && try(contains(one(data.ibm_is_instance_profile.selected.secure_boot_modes).values, var.enable_secure_boot), false)
      error_message = "The selected boot mode must be allowed by both the image entry and live profile."
    }
  }
}

resource "ibm_is_floating_ip" "management" {
  count          = var.create_management_floating_ip ? 1 : 0
  name           = "${var.prefix}-mgmt-fip"
  target         = ibm_is_virtual_network_interface.management.id
  resource_group = data.ibm_resource_group.target.id
  tags           = var.tags
  depends_on     = [ibm_is_instance.fmcv]
}
