provider "alicloud" {
  access_key = "${var.access_key}"
  secret_key = "${var.secret_key}"
  region     = "${var.region}"
}

resource "alicloud_instance" "endpoint" {
  security_groups = [var.security_group_id]

  image_id = data.alicloud_images.image.images.0.id
  instance_type = var.instance_type
  instance_name = var.instance_name

  system_disk_category = "cloud_auto"
  system_disk_name = var.instance_name
  system_disk_size = data.alicloud_images.image.images.0.size

  vpc_id = var.vpc_id
  vswitch_id = var.mgmt_vswitch_id

  user_data = base64encode(<<-EOF
    #! /bin/bash
    useradd -m -s /bin/bash -G sudo ${var.username}
    echo '${var.username}:${var.password}' | chpasswd
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication no/g' /etc/ssh/sshd_config
    sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^PubkeyAuthentication yes/PubkeyAuthentication no/g' /etc/ssh/sshd_config
    systemctl restart sshd
    iptables -I INPUT -p tcp --dport 5201 --syn -j ACCEPT
    sudo cp /etc/skel/.bashrc /home/${var.username}/
    sudo cp /etc/skel/.profile /home/${var.username}/
    sudo chown ${var.username}:${var.username} /home/${var.username}/.bashrc /home/${var.username}/.profile
  EOF
  )
  
  tags = {
    autostop = false
  }
  ipv6_address_count = 1
}

resource "alicloud_eip_address" "instance_eip" {
  address_name = "${var.instance_name}-eip"
}

resource "alicloud_eip_association" "instance_eip_association" {
  allocation_id = alicloud_eip_address.instance_eip.id
  instance_id = alicloud_instance.endpoint.id

  depends_on = [alicloud_instance.endpoint]
}

resource "alicloud_ecs_network_interface" "traffic_interface" {
  network_interface_name = "${var.prefix}-${var.instance_name}-traffic"
  vswitch_id = var.traffic_intf_vswitch_id
  security_group_ids = [var.security_group_id]
  ipv6_address_count = 1
}

resource "alicloud_ecs_network_interface_attachment" "traffic_interface_attachment" {
  instance_id = alicloud_instance.endpoint.id
  network_interface_id = alicloud_ecs_network_interface.traffic_interface.id

  depends_on = [alicloud_instance.endpoint]
}

data "alicloud_eip_addresses" "instance_eip" {
  ids = [alicloud_eip_address.instance_eip.id]

  depends_on = [alicloud_eip_address.instance_eip]
}

data "alicloud_images" "image" {
  image_id = var.image_id
  owners = "system"
}

output "instance_id" {
  value = alicloud_instance.endpoint.id
}

output "eip_address" {
  value = data.alicloud_eip_addresses.instance_eip.addresses.0.ip_address
}

output "traffic_interface_id" {
  value = alicloud_ecs_network_interface.traffic_interface.id
}