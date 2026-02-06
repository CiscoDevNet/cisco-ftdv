provider "alicloud" {
  access_key = "${var.access_key}"
  secret_key = "${var.secret_key}"
  region     = "${var.region}"
}

resource "alicloud_instance" "ftdv" {
  security_groups = [var.security_group_id]

  image_id = data.alicloud_images.image.images.0.id
  instance_type = var.instance_type
  instance_name = var.instance_name

  system_disk_category = startswith(var.instance_type, "ecs.g5ne") ? "cloud_efficiency" : "cloud_essd"
  system_disk_name = var.instance_name
  system_disk_size = data.alicloud_images.image.images.0.size

  vpc_id = var.vpc_id
  vswitch_id = var.mgmt_vswitch_id

  user_data = var.user_data

  tags = {
    autostop = false
  }
  ipv6_address_count = 1
}

data "alicloud_images" "image" {
  image_id = var.image_id
  owners = "self"
}

resource "alicloud_eip_address" "instance_eip" {
  address_name = "${var.prefix}-ftdv-eip"
}

resource "alicloud_eip_association" "instance_eip_association" {
  allocation_id = alicloud_eip_address.instance_eip.id
  instance_id = alicloud_instance.ftdv.id

  depends_on = [alicloud_instance.ftdv]
}

resource "alicloud_eip_address" "outside_interface_eip" {
  address_name = "${var.prefix}-ftdv-outside-int-eip"
}

resource "alicloud_eip_association" "outside_interface_eip_association" {
  allocation_id = alicloud_eip_address.outside_interface_eip.id
  instance_type = "NetworkInterface"
  instance_id = alicloud_ecs_network_interface.outside_interface.id

  depends_on = [alicloud_ecs_network_interface.outside_interface]
}

resource "alicloud_ecs_network_interface" "diag_interface" {
  count = var.disable_diag ? 0 : 1
  network_interface_name = "${var.prefix}-diag"
  vswitch_id = var.diag_vswitch_id
  security_group_ids = [var.security_group_id]
  ipv6_address_count = 1
}

resource "alicloud_ecs_network_interface" "inside_interface" {
  network_interface_name = "${var.prefix}-inside"
  vswitch_id = var.inside_vswitch_id
  security_group_ids = [var.security_group_id]
  ipv6_address_count = 1
}

resource "alicloud_ecs_network_interface" "outside_interface" {
  network_interface_name = "${var.prefix}-outside"
  vswitch_id = var.outside_vswitch_id
  security_group_ids = [var.security_group_id]
  ipv6_address_count = 1
}

resource "alicloud_ecs_network_interface_attachment" "diag_attachment" {
  count = var.disable_diag ? 0 : 1
  instance_id = alicloud_instance.ftdv.id
  network_interface_id = alicloud_ecs_network_interface.diag_interface[count.index].id

  depends_on = [alicloud_instance.ftdv]
}

resource "alicloud_ecs_network_interface_attachment" "inside_attachment" {
  instance_id = alicloud_instance.ftdv.id
  network_interface_id = alicloud_ecs_network_interface.inside_interface.id

  depends_on = [alicloud_ecs_network_interface_attachment.diag_attachment]
}

resource "alicloud_ecs_network_interface_attachment" "outside_attachment" {
  instance_id = alicloud_instance.ftdv.id
  network_interface_id = alicloud_ecs_network_interface.outside_interface.id

  depends_on = [alicloud_ecs_network_interface_attachment.inside_attachment]
}

data "alicloud_eip_addresses" "instance_eip" {
  ids = [alicloud_eip_address.instance_eip.id]

  depends_on = [alicloud_eip_address.instance_eip]
}

data "alicloud_eip_addresses" "outside_interface_eip" {
  ids = [alicloud_eip_address.instance_eip.id]

  depends_on = [alicloud_eip_address.outside_interface_eip]
}

output "instance_id" {
  value = alicloud_instance.ftdv.id
}

output "eip_address" {
  value = data.alicloud_eip_addresses.instance_eip.addresses.0.ip_address
}

output "inside_interface_id" {
  value = alicloud_ecs_network_interface.inside_interface.id
}

output "outside_interface_id" {
  value = alicloud_ecs_network_interface.outside_interface.id
}

output "outside_interface_eip_address" {
  value = data.alicloud_eip_addresses.outside_interface_eip.addresses.0.ip_address
}