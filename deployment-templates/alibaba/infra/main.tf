provider "alicloud" {
  access_key = "${var.access_key}"
  secret_key = "${var.secret_key}"
  region     = "${var.region}"
}

resource "alicloud_vpc" "vpc" {
  vpc_name   = "${var.prefix}-vpc"
  cidr_block = var.vpc_cidr
  enable_ipv6 = true
}

resource "alicloud_vswitch" "mgmt_vswitch" {
  vpc_id       = alicloud_vpc.vpc.id
  cidr_block   = var.mgmt_vswitch_cidr
  zone_id      = data.alicloud_zones.available_zones.zones.0.id
  vswitch_name = "${var.prefix}-mgmt-vswitch"
  enable_ipv6 = true
  ipv6_cidr_block_mask = 1

  depends_on = [alicloud_vpc.vpc]
}

resource "alicloud_vswitch" "inside_vswitch" {
  vpc_id       = alicloud_vpc.vpc.id
  cidr_block   = var.inside_vswitch_cidr
  zone_id      = data.alicloud_zones.available_zones.zones.0.id
  vswitch_name = "${var.prefix}-inside-vswitch"
  enable_ipv6 = true
  ipv6_cidr_block_mask = 2

  depends_on = [alicloud_vswitch.mgmt_vswitch]
}

resource "alicloud_vswitch" "outside_vswitch" {
  vpc_id       = alicloud_vpc.vpc.id
  cidr_block   = var.outside_vswitch_cidr
  zone_id      = data.alicloud_zones.available_zones.zones.0.id
  vswitch_name = "${var.prefix}-outside-vswitch"
  enable_ipv6 = true
  ipv6_cidr_block_mask = 3

  depends_on = [alicloud_vswitch.inside_vswitch]
}

locals {
  create_diag_vswitch = (var.device_type == "ftdv" && var.disable_diag == false) ? true : false
}

resource "alicloud_vswitch" "diag_vswitch" {
  count = local.create_diag_vswitch ? 1 : 0

  vpc_id       = alicloud_vpc.vpc.id
  cidr_block   = var.diag_vswitch_cidr
  zone_id      = data.alicloud_zones.available_zones.zones.0.id
  vswitch_name = "${var.prefix}-diag-vswitch"
  enable_ipv6 = true
  ipv6_cidr_block_mask = 4

  depends_on = [alicloud_vswitch.outside_vswitch]
}

data "alicloud_zones" "available_zones" {
  available_resource_creation = "VSwitch"
}

resource "alicloud_route_table" "inside_route_table" {
  vpc_id = alicloud_vpc.vpc.id
  route_table_name = "${var.prefix}-inside-rt"
}

resource "alicloud_route_table_attachment" "inside_rt_attach" {
  vswitch_id     = alicloud_vswitch.inside_vswitch.id
  route_table_id = alicloud_route_table.inside_route_table.id
}

resource "alicloud_security_group" "security_group" {
  vpc_id = alicloud_vpc.vpc.id
  security_group_name = "${var.prefix}-sg"
}

resource "alicloud_security_group_rule" "ipv4_rules" {
  for_each = toset(var.ipv4_security_group_rules)

  type              = "ingress"
  ip_protocol       = "all"
  port_range        = "all"
  security_group_id = alicloud_security_group.security_group.id
  cidr_ip           = each.key
  priority          = 1
  description       = "Allow all traffic from ${each.key}"
}

resource "alicloud_security_group_rule" "ipv6_rules" {
  for_each = toset(var.ipv6_security_group_rules)

  type              = "ingress"
  ip_protocol       = "all"
  port_range        = "all"
  security_group_id = alicloud_security_group.security_group.id
  ipv6_cidr_ip      = each.key
  priority          = 1
  description       = "Allow all traffic from ${each.key}"
}

output "vpc_id" {
    value = alicloud_vpc.vpc.id
}

output "mgmt_vswitch_id" {
    value = alicloud_vswitch.mgmt_vswitch.id
}

output "inside_vswitch_id" {
    value = alicloud_vswitch.inside_vswitch.id
}

output "outside_vswitch_id" {
    value = alicloud_vswitch.outside_vswitch.id
}

output "diag_vswitch_id" {
    value = length(alicloud_vswitch.diag_vswitch) > 0 ? alicloud_vswitch.diag_vswitch[0].id : null
}

output "vpc_ipv6_cidr" {
    value = alicloud_vpc.vpc.ipv6_cidr_block
}

output "inside_ipv6_cidr" {
    value = alicloud_vswitch.inside_vswitch.ipv6_cidr_block
}

output "outside_ipv6_cidr" {
    value = alicloud_vswitch.outside_vswitch.ipv6_cidr_block
}

output "security_group_id" {
    value = alicloud_security_group.security_group.id
}

output "inside_rt_id" {
    value = alicloud_route_table.inside_route_table.id
}

output "zone_id" {
  value = data.alicloud_zones.available_zones.zones.0.id
}