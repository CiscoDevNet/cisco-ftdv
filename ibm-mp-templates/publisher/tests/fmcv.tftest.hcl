# All resources/data are mocked. No credentials or IBM API calls.
mock_provider "ibm" {
  mock_data "ibm_resource_group" { defaults = { id = "rg-test" } }
  mock_data "ibm_is_vpc" { defaults = { id = "vpc-test" } }
  mock_data "ibm_is_ssh_key" { defaults = { id = "key-test" } }
  mock_data "ibm_is_security_groups" { defaults = { security_groups = [{ id = "sg-mgmt" }, { id = "sg-one" }, { id = "sg-two" }, { id = "sg-three" }] } }
  mock_data "ibm_is_instance_profile" { defaults = {
    network_attachment_count = [{ min = 1, max = 5, type = "range" }]
    zones                    = [{ name = "us-east-1" }]
    secure_boot_modes        = [{ values = [true, false], default = true, type = "enum" }]
  } }
}
override_data {
  target = data.ibm_is_subnet.management
  values = { id = "subnet-mgmt", vpc = "vpc-test", zone = "us-east-1" }
}
variables {
  resource_group_name          = "test-rg"
  prefix                       = "product-unit"
  vpc_id                       = "vpc-test"
  management_subnet_id         = "subnet-mgmt"
  management_security_group_id = "sg-mgmt"
  ssh_key_id                   = "key-test"
}
run "deploy_defaults" {
  command = apply
  assert {
    condition = (
      ibm_is_instance.fmcv.name == "product-unit-vsi" &&
      ibm_is_instance.fmcv.boot_volume[0].name == "product-unit-boot" &&
      ibm_is_virtual_network_interface.management.name == "product-unit-mgmt-vni"
    )
    error_message = "The legacy prefix must still determine the VSI, boot volume, and management VNI names."
  }
  assert {
    condition     = length(ibm_is_instance.fmcv.network_attachments) == 0 && length(output.interface_map) == 1 && length(ibm_is_floating_ip.management) == 0 && length(ibm_is_instance.fmcv.keys) == 1 && contains(ibm_is_instance.fmcv.keys, var.ssh_key_id) && local.effective_user_data == null && ibm_is_virtual_network_interface.management.allow_ip_spoofing == false && ibm_is_virtual_network_interface.management.protocol_state_filtering_mode == "auto"
    error_message = "deploy_defaults contract failed."
  }
}
run "primary_management" {
  command = plan
  assert {
    condition     = ibm_is_instance.fmcv.primary_network_attachment[0].virtual_network_interface[0].id == ibm_is_virtual_network_interface.management.id && output.management_public_url == null
    error_message = "primary_management contract failed."
  }
}
run "cleanup_ownership" {
  command = plan
  assert {
    condition     = ibm_is_instance.fmcv.boot_volume[0].auto_delete_volume && !ibm_is_virtual_network_interface.management.auto_delete
    error_message = "cleanup_ownership contract failed."
  }
}
run "update_tags" {
  command = apply
  variables {
    tags = ["cisco", "changed"]
  }
  assert {
    condition     = output.instance_id == run.deploy_defaults.instance_id && contains(ibm_is_instance.fmcv.tags, "changed")
    error_message = "update_tags contract failed."
  }
}
run "enable_management_fip" {
  command = apply
  variables {
    create_management_floating_ip = true
  }
  assert {
    condition     = length(ibm_is_floating_ip.management) == 1 && ibm_is_floating_ip.management[0].name == "product-unit-mgmt-fip" && ibm_is_floating_ip.management[0].target == ibm_is_virtual_network_interface.management.id && output.instance_id == run.deploy_defaults.instance_id
    error_message = "enable_management_fip contract failed."
  }
}
run "rename_prefix_without_changing_names" {
  command = plan
  variables {
    prefix                        = null
    resource_name_prefix          = "product-unit"
    create_management_floating_ip = true
  }
  assert {
    condition = (
      output.instance_id == run.deploy_defaults.instance_id &&
      output.interface_map.eth0.vni_id == run.deploy_defaults.interface_map.eth0.vni_id &&
      output.management_floating_ip == run.enable_management_fip.management_floating_ip &&
      ibm_is_instance.fmcv.name == "product-unit-vsi" &&
      ibm_is_instance.fmcv.boot_volume[0].name == "product-unit-boot" &&
      ibm_is_virtual_network_interface.management.name == "product-unit-mgmt-vni" &&
      ibm_is_floating_ip.management[0].name == "product-unit-mgmt-fip"
    )
    error_message = "Moving the same prefix to the new key must preserve instance and VNI identity and all resource names."
  }
}
run "default_prefix_without_either_key" {
  command = plan
  variables {
    prefix                        = null
    create_management_floating_ip = true
  }
  assert {
    condition = (
      ibm_is_instance.fmcv.name == "cisco-fmcv-vsi" &&
      ibm_is_instance.fmcv.boot_volume[0].name == "cisco-fmcv-boot" &&
      ibm_is_virtual_network_interface.management.name == "cisco-fmcv-mgmt-vni" &&
      ibm_is_floating_ip.management[0].name == "cisco-fmcv-mgmt-fip"
    )
    error_message = "Omitting both prefix inputs must keep the original fallback for every resource name."
  }
}
run "allow_matching_prefix_keys" {
  command = plan
  variables {
    resource_name_prefix          = "product-unit"
    create_management_floating_ip = true
  }
  assert {
    condition     = output.instance_id == run.deploy_defaults.instance_id && ibm_is_floating_ip.management[0].name == "product-unit-mgmt-fip"
    error_message = "Matching legacy and new prefix values must preserve the deployment."
  }
}
run "reject_conflicting_prefix_keys" {
  command = plan
  variables {
    resource_name_prefix = "different-prefix"
  }
  expect_failures = [var.resource_name_prefix]
}
run "reject_empty_resource_name_prefix" {
  command = plan
  variables {
    prefix               = null
    resource_name_prefix = ""
  }
  expect_failures = [var.resource_name_prefix]
}
run "disable_management_fip" {
  command = apply
  assert {
    condition     = length(ibm_is_floating_ip.management) == 0 && output.instance_id == run.deploy_defaults.instance_id
    error_message = "disable_management_fip contract failed."
  }
}
run "day0_passthrough" {
  command = apply
  variables {
    user_data = jsonencode({ AdminPassword = "TEST_ONLY_NOT_A_CREDENTIAL", Hostname = "unit-test", AdditionalImageField = "pass-through" })
  }
  assert {
    condition     = nonsensitive(ibm_is_instance.fmcv.user_data) == nonsensitive(var.user_data)
    error_message = "day0_passthrough contract failed."
  }
}
run "blank_day0" {
  command = plan
  variables {
    user_data = "  \n "
  }
  assert {
    condition     = local.effective_user_data == null
    error_message = "blank_day0 contract failed."
  }
}
run "packaged_default_image" {
  command = plan
  assert {
    condition     = output.selected_fmcv_image.image_label == local.fmcv_image_catalog.default_version && local.catalog_version_crn == local.fmcv_image_releases[local.fmcv_image_catalog.default_version].version_crn
    error_message = "The omitted image selector must follow the packaged JSON default."
  }
}
run "explicit_image" {
  command = plan
  variables {
    fmcv_image_version = "__mock_alternate__"
  }
  assert {
    condition     = output.selected_fmcv_image.image_label == var.fmcv_image_version && local.catalog_version_crn != local.fmcv_image_releases[local.fmcv_image_catalog.default_version].version_crn
    error_message = "explicit_image contract failed."
  }
}
run "reject_empty_key" {
  command = plan
  variables {
    ssh_key_id = " "
  }
  expect_failures = [var.ssh_key_id]
}
run "reject_bad_prefix" {
  command = plan
  variables {
    prefix = "Bad_Prefix"
  }
  expect_failures = [var.prefix]
}
run "reject_https" {
  command = plan
  variables {
    metadata_service_protocol = "https"
  }
  expect_failures = [var.metadata_service_protocol]
}
run "reject_metadata_off" {
  command = plan
  variables {
    enable_metadata_service = false
  }
  expect_failures = [var.enable_metadata_service]
}
run "reject_bad_profile" {
  command = plan
  variables {
    instance_profile = "not-a-profile"
  }
  expect_failures = [var.instance_profile]
}
run "reject_unknown_image" {
  command = plan
  variables {
    fmcv_image_version = "missing"
  }
  expect_failures = [var.fmcv_image_version]
}
run "reject_day0_scalar" {
  command = plan
  variables {
    user_data = "true"
  }
  expect_failures = [var.user_data]
}
run "reject_day0_array" {
  command = plan
  variables {
    user_data = "[]"
  }
  expect_failures = [var.user_data]
}
run "reject_day0_malformed" {
  command = plan
  variables {
    user_data = "{"
  }
  expect_failures = [var.user_data]
}
run "reject_wrong_region" {
  command = plan
  variables {
    region = "us-south"
  }
  expect_failures = [ibm_is_instance.fmcv]
}
run "reject_wrong_sg" {
  command = plan
  variables {
    management_security_group_id = "sg-other"
  }
  expect_failures = [ibm_is_instance.fmcv]
}
run "reject_image_boot_mode" {
  command = plan
  variables {
    enable_secure_boot = true
  }
  expect_failures = [ibm_is_instance.fmcv]
}
run "reject_cross_vpc" {
  command = plan
  override_data {
    target = data.ibm_is_subnet.management
    values = { id = "subnet-mgmt", vpc = "wrong", zone = "us-east-1" }
  }
  expect_failures = [ibm_is_instance.fmcv]
}
run "reject_nic_capacity" {
  command = plan
  override_data {
    target = data.ibm_is_instance_profile.selected
    values = { network_attachment_count = [{ min = 0, max = 0, type = "range" }], zones = [{ name = "us-east-1" }], secure_boot_modes = [{ values = [true, false], default = true, type = "enum" }] }
  }
  expect_failures = [ibm_is_instance.fmcv]
}
run "reject_profile_zone" {
  command = plan
  override_data {
    target = data.ibm_is_instance_profile.selected
    values = { network_attachment_count = [{ min = 0, max = 5, type = "range" }], zones = [{ name = "us-east-2" }], secure_boot_modes = [{ values = [true, false], default = true, type = "enum" }] }
  }
  expect_failures = [ibm_is_instance.fmcv]
}
run "reject_profile_boot" {
  command = plan
  override_data {
    target = data.ibm_is_instance_profile.selected
    values = { network_attachment_count = [{ min = 0, max = 5, type = "range" }], zones = [{ name = "us-east-1" }], secure_boot_modes = [{ values = [true], default = true, type = "enum" }] }
  }
  expect_failures = [ibm_is_instance.fmcv]
}
