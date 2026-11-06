data "ibm_resource_group" "target" {
  name = var.resource_group_name
}

data "ibm_is_vpc" "target" {
  identifier = var.vpc_id
}

data "ibm_is_subnet" "management" {
  identifier = var.management_subnet_id
}

data "ibm_is_subnet" "data_1" {
  identifier = var.data_subnet_1_id
}

data "ibm_is_subnet" "data_2" {
  identifier = var.data_subnet_2_id
}

data "ibm_is_security_groups" "target_vpc" {
  vpc_id = data.ibm_is_vpc.target.id
}

data "ibm_is_ssh_key" "selected" {
  for_each = toset(var.ssh_key_ids)

  id = each.value
}

data "ibm_is_instance_profile" "selected" {
  name = var.instance_profile
}
