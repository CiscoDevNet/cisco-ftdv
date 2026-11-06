# All IBM resources/data are mocked. No cloud calls or credentials are used.
# These checks do not qualify real provider updates or guest forwarding.
mock_provider "ibm" {
  mock_data "ibm_resource_group" { defaults = { id = "rg-test" } }
  mock_data "ibm_is_vpc" { defaults = { id = "vpc-test" } }
  mock_data "ibm_is_security_groups" {
    defaults = { security_groups = [{ id = "sg-mgmt" }, { id = "sg-one" }, { id = "sg-two" }] }
  }
  mock_data "ibm_is_instance_profile" {
    defaults = {
      network_attachment_count = [{ min = 1, max = 5, type = "range" }]
      zones                    = [{ name = "us-east-1" }]
      secure_boot_modes        = [{ values = [true, false], default = true, type = "enum" }]
    }
  }
}
override_data {
  target = data.ibm_is_subnet.management
  values = { id = "subnet-mgmt", vpc = "vpc-test", zone = "us-east-1" }
}
override_data {
  target = data.ibm_is_subnet.data_1
  values = { id = "subnet-one", vpc = "vpc-test", zone = "us-east-1" }
}
override_data {
  target = data.ibm_is_subnet.data_2
  values = { id = "subnet-two", vpc = "vpc-test", zone = "us-east-1" }
}
variables {
  resource_group_name          = "test-rg"
  prefix                       = "asav-unit"
  vpc_id                       = "vpc-test"
  management_subnet_id         = "subnet-mgmt"
  data_subnet_1_id             = "subnet-one"
  data_subnet_2_id             = "subnet-two"
  management_security_group_id = "sg-mgmt"
  data_security_group_1_id     = "sg-one"
  data_security_group_2_id     = "sg-two"
  ssh_key_ids                  = ["key-test"]
}
run "deploy_defaults" {
  command = apply
  assert {
    condition     = length(ibm_is_instance.asav.network_attachments) == 2 && ibm_is_instance.asav.enable_secure_boot && length(ibm_is_floating_ip.management) == 0
    error_message = "Default topology must be three NICs, Secure Boot on and private management."
  }
  assert {
    condition     = ibm_is_virtual_network_interface.management.allow_ip_spoofing && ibm_is_virtual_network_interface.data_1.allow_ip_spoofing && ibm_is_virtual_network_interface.data_2.allow_ip_spoofing && ibm_is_virtual_network_interface.management.protocol_state_filtering_mode == "disabled"
    error_message = "Intended forwarding defaults must be retained."
  }
  assert {
    condition     = output.selected_asav_image.asav_version == local.asav_image_catalog.default_version
    error_message = "Null image input must resolve to the packaged default."
  }
}
run "update_tags" {
  command = apply
  variables { tags = ["cisco", "changed-tag"] }
  assert {
    condition     = output.instance_id == run.deploy_defaults.instance_id && contains(ibm_is_instance.asav.tags, "changed-tag")
    error_message = "Mock tag update should retain the managed instance identity."
  }
}
run "enable_management_fip" {
  command = apply
  variables { create_management_floating_ip = true }
  assert {
    condition     = length(ibm_is_floating_ip.management) == 1 && output.instance_id == run.deploy_defaults.instance_id
    error_message = "Public-management toggle must add one FIP without a new mock VSI."
  }
}
run "disable_management_fip" {
  command = apply
  assert {
    condition     = length(ibm_is_floating_ip.management) == 0 && output.instance_id == run.deploy_defaults.instance_id
    error_message = "Private management must remove only the mock FIP."
  }
}
run "blank_day0" {
  command = plan
  variables { user_data = "  \n  " }
  assert {
    condition     = local.effective_user_data == null
    error_message = "Whitespace-only Day-0 must be omitted."
  }
}
run "explicit_current_image" {
  command = plan
  variables { asav_image_version = run.deploy_defaults.selected_asav_image.asav_version }
  assert {
    condition     = output.selected_asav_image.asav_version == run.deploy_defaults.selected_asav_image.asav_version
    error_message = "An explicit retained label must stay pinned."
  }
}
run "reject_missing_keys" {
  command = plan
  variables { ssh_key_ids = [] }
  expect_failures = [var.ssh_key_ids]
}
run "reject_duplicate_keys" {
  command = plan
  variables { ssh_key_ids = ["key-test", "key-test"] }
  expect_failures = [var.ssh_key_ids]
}
run "reject_bad_prefix" {
  command = plan
  variables { prefix = "Invalid-Prefix" }
  expect_failures = [var.prefix]
}
run "reject_https_metadata" {
  command = plan
  variables { metadata_service_protocol = "https" }
  expect_failures = [var.metadata_service_protocol]
}
run "reject_disabled_metadata" {
  command = plan
  variables { enable_metadata_service = false }
  expect_failures = [var.enable_metadata_service]
}
run "reject_wrong_region" {
  command = plan
  variables { region = "us-south" }
  expect_failures = [ibm_is_instance.asav]
}
run "reject_wrong_sg" {
  command = plan
  variables { data_security_group_1_id = "sg-other" }
  expect_failures = [ibm_is_instance.asav]
}
run "reject_duplicate_subnets" {
  command = plan
  override_data {
    target = data.ibm_is_subnet.data_1
    values = { id = "subnet-mgmt", vpc = "vpc-test", zone = "us-east-1" }
  }
  expect_failures = [ibm_is_instance.asav]
}
run "reject_cross_vpc" {
  command = plan
  override_data {
    target = data.ibm_is_subnet.data_1
    values = { id = "subnet-one", vpc = "other-vpc", zone = "us-east-1" }
  }
  expect_failures = [ibm_is_instance.asav]
}
run "reject_cross_zone" {
  command = plan
  override_data {
    target = data.ibm_is_subnet.data_1
    values = { id = "subnet-one", vpc = "vpc-test", zone = "us-east-2" }
  }
  expect_failures = [ibm_is_instance.asav]
}
run "reject_insufficient_nic_capacity" {
  command = plan
  override_data {
    target = data.ibm_is_instance_profile.selected
    values = { network_attachment_count = [{ min = 1, max = 2, type = "range" }], zones = [{ name = "us-east-1" }], secure_boot_modes = [{ values = [true, false], default = true, type = "enum" }] }
  }
  expect_failures = [ibm_is_instance.asav]
}
run "reject_unavailable_profile_zone" {
  command = plan
  override_data {
    target = data.ibm_is_instance_profile.selected
    values = { network_attachment_count = [{ min = 1, max = 5, type = "range" }], zones = [{ name = "us-east-2" }], secure_boot_modes = [{ values = [true, false], default = true, type = "enum" }] }
  }
  expect_failures = [ibm_is_instance.asav]
}
run "reject_profile_secure_boot_mode" {
  command = plan
  override_data {
    target = data.ibm_is_instance_profile.selected
    values = { network_attachment_count = [{ min = 1, max = 5, type = "range" }], zones = [{ name = "us-east-1" }], secure_boot_modes = [{ values = [false], default = false, type = "enum" }] }
  }
  expect_failures = [ibm_is_instance.asav]
}

run "reject_unknown_image" {
  command = plan
  variables { asav_image_version = "not-a-configured-image" }
  expect_failures = [var.asav_image_version]
}
