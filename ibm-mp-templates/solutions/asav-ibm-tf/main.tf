resource "ibm_is_virtual_network_interface" "management" {
  name                          = "${var.prefix}-mgmt-vni"
  subnet                        = data.ibm_is_subnet.management.id
  security_groups               = [var.management_security_group_id]
  resource_group                = data.ibm_resource_group.target.id
  auto_delete                   = false
  enable_infrastructure_nat     = true
  allow_ip_spoofing             = var.all_interface_allow_ip_spoofing
  protocol_state_filtering_mode = var.all_interface_protocol_state_filtering_mode
}

resource "ibm_is_virtual_network_interface" "data_1" {
  name                          = "${var.prefix}-data-1-vni"
  subnet                        = data.ibm_is_subnet.data_1.id
  security_groups               = [var.data_security_group_1_id]
  resource_group                = data.ibm_resource_group.target.id
  auto_delete                   = false
  enable_infrastructure_nat     = true
  allow_ip_spoofing             = var.all_interface_allow_ip_spoofing
  protocol_state_filtering_mode = var.all_interface_protocol_state_filtering_mode
}

resource "ibm_is_virtual_network_interface" "data_2" {
  name                          = "${var.prefix}-data-2-vni"
  subnet                        = data.ibm_is_subnet.data_2.id
  security_groups               = [var.data_security_group_2_id]
  resource_group                = data.ibm_resource_group.target.id
  auto_delete                   = false
  enable_infrastructure_nat     = true
  allow_ip_spoofing             = var.all_interface_allow_ip_spoofing
  protocol_state_filtering_mode = var.all_interface_protocol_state_filtering_mode
}

resource "ibm_is_instance" "asav" {
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

  network_attachments {
    name = "data-1"

    virtual_network_interface {
      id = ibm_is_virtual_network_interface.data_1.id
    }
  }

  network_attachments {
    name = "data-2"

    virtual_network_interface {
      id = ibm_is_virtual_network_interface.data_2.id
    }
  }

  keys      = sort([for ssh_key in data.ibm_is_ssh_key.selected : ssh_key.id])
  user_data = local.effective_user_data
  tags      = var.tags

  metadata_service {
    enabled            = var.enable_metadata_service
    protocol           = var.metadata_service_protocol
    response_hop_limit = 1
  }

  boot_volume {
    name = "${var.prefix}-boot"
  }

  timeouts {
    create = "60m"
    update = "60m"
    delete = "60m"
  }

  lifecycle {
    precondition {
      condition     = length(toset(local.subnet_ids)) == 3
      error_message = "The management, data-1, and data-2 interfaces must use three distinct subnets."
    }

    precondition {
      condition     = alltrue([for subnet_vpc_id in local.subnet_vpc_ids : subnet_vpc_id == data.ibm_is_vpc.target.id])
      error_message = "All three subnets must belong to vpc_id."
    }

    precondition {
      condition     = length(toset(local.subnet_zones)) == 1
      error_message = "All three subnets must be in the same availability zone because one VSI cannot span zones."
    }

    precondition {
      condition     = local.deployment_region == var.region
      error_message = "region must match the region derived from the selected subnet zone."
    }

    precondition {
      condition     = contains(local.catalog_supported_regions, var.region)
      error_message = "The selected Cisco ASAv image version is not published in the selected region. Choose a supported image-version and region combination."
    }

    precondition {
      condition     = length(local.missing_security_group_ids) == 0
      error_message = "Every security group must belong to the selected VPC."
    }

    precondition {
      condition     = try(one(data.ibm_is_instance_profile.selected.network_attachment_count).max, 0) >= 3
      error_message = "The selected instance profile must support at least three network attachments."
    }

    precondition {
      condition     = contains(local.catalog_supported_profiles, var.instance_profile)
      error_message = "The selected instance profile is not qualified for the selected ASAv image version."
    }

    precondition {
      condition     = contains([for zone in data.ibm_is_instance_profile.selected.zones : zone.name], local.deployment_zone)
      error_message = "The selected instance profile is not available in the subnet availability zone. Choose another profile or same-zone subnet set."
    }

    precondition {
      condition = (
        contains(local.catalog_supported_secure_boot_modes, var.enable_secure_boot) &&
        try(contains(one(data.ibm_is_instance_profile.selected.secure_boot_modes).values, var.enable_secure_boot), false)
      )
      error_message = "The requested Secure Boot mode is not qualified for the selected ASAv image version or supported by the selected instance profile."
    }

    precondition {
      condition = (
        local.catalog_version_crn != "" &&
        startswith(local.catalog_version_crn, local.asav_version_crn_prefix)
      )
      error_message = "The selected ASAv image version must resolve to an exact version CRN owned by the approved Cisco ASAv VSI offering."
    }
  }
}

resource "ibm_is_floating_ip" "management" {
  count = var.create_management_floating_ip ? 1 : 0

  name           = "${var.prefix}-mgmt-fip"
  target         = ibm_is_virtual_network_interface.management.id
  resource_group = data.ibm_resource_group.target.id
  tags           = var.tags

  depends_on = [ibm_is_instance.asav]
}
