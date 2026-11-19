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
override_data {
  target = data.ibm_is_subnet.data_1
  values = { id = "subnet-one", vpc = "vpc-test", zone = "us-east-1" }
}
override_data {
  target = data.ibm_is_subnet.data_2
  values = { id = "subnet-two", vpc = "vpc-test", zone = "us-east-1" }
}
override_data {
  target = data.ibm_is_subnet.data_3
  values = { id = "subnet-three", vpc = "vpc-test", zone = "us-east-1" }
}
variables {
  resource_group_name          = "test-rg"
  prefix                       = "product-unit"
  vpc_id                       = "vpc-test"
  management_subnet_id         = "subnet-mgmt"
  management_security_group_id = "sg-mgmt"
  ssh_key_id                   = "key-test"
  data_subnet_1_id             = "subnet-one"
  data_security_group_1_id     = "sg-one"
  data_subnet_2_id             = "subnet-two"
  data_security_group_2_id     = "sg-two"
  data_subnet_3_id             = "subnet-three"
  data_security_group_3_id     = "sg-three"
}
run "reject_unverified_public_reference" {
  command         = plan
  expect_failures = [ibm_is_instance.ftdv]
}
