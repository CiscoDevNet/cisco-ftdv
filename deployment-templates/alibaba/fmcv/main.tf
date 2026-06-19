provider "alicloud" {
  access_key = "${var.access_key}"
  secret_key = "${var.secret_key}"
  region     = "${var.region}"
}

resource "alicloud_instance" "fmcv" {
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
  address_name = "${var.prefix}-fmcv-eip"
}

resource "alicloud_eip_association" "instance_eip_association" {
  allocation_id = alicloud_eip_address.instance_eip.id
  instance_id = alicloud_instance.fmcv.id

  depends_on = [alicloud_instance.fmcv]
}

data "alicloud_eip_addresses" "instance_eip" {
  ids = [alicloud_eip_address.instance_eip.id]

  depends_on = [alicloud_eip_address.instance_eip]
}

output "instance_id" {
  value = alicloud_instance.fmcv.id
}

output "eip_address" {
  value = data.alicloud_eip_addresses.instance_eip.addresses.0.ip_address
}