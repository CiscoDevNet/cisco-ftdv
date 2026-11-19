data "ibm_resource_group" "target" {
  name = var.resource_group_name
}

data "ibm_is_vpc" "target" {
  identifier = var.vpc_id
}

data "ibm_is_subnet" "management" {
  identifier = var.management_subnet_id
}

data "ibm_is_security_groups" "target_vpc" {
  vpc_id = data.ibm_is_vpc.target.id
}

data "ibm_is_ssh_key" "selected" {
  id = var.ssh_key_id
}

data "ibm_is_instance_profile" "selected" {
  name = var.instance_profile
}
