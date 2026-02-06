variable "project_id" {} # GCP Project ID : 
variable "region" {}     # e.g., us-central1, us-east1
variable "zone" {}       # a,b,c,d, any alphabetical character
variable "resource_name_prefix" {
  default = "automation"
}
variable "linux_username" {}
variable "linux_password" {}
variable "image" {
  default = "projects/ubuntu-os-cloud/global/images/ubuntu-2004-focal-v20220712"
}
variable "machine_type" {
  default = "n1-standard-1"
}
variable "linux_name" {
  default = "linux-01"
}
variable "mgmt_vpc_name" {}
variable "mgmt_subnet_name" {}
variable "data_vpc_name" {}
variable "data_subnet_name" {}

provider "google" {
  project     = var.project_id
  region      = var.region
}

resource "google_compute_instance" "linux_vm" {
  name         = "${var.resource_name_prefix}-${var.linux_name}"
  zone         = var.zone
  machine_type = var.machine_type
  
  can_ip_forward = true

  boot_disk {
    initialize_params {
      image = var.image
      type  = "pd-standard"
      size  = 10
    }
    auto_delete = true
  }

  network_interface {
    stack_type = "IPV4_IPV6"
    network    = var.mgmt_vpc_name
    subnetwork = var.mgmt_subnet_name
    
    access_config {
      network_tier = "PREMIUM"
    }
    
    ipv6_access_config {
      name         = "external-ipv6"
      network_tier = "PREMIUM"
    }
  }

  network_interface {
    stack_type = "IPV4_IPV6"
    network    = var.data_vpc_name
    subnetwork = var.data_subnet_name
    ipv6_access_config {
      network_tier = "PREMIUM"
    }
  }

  metadata_startup_script = <<-EOF
    useradd -m -s /bin/bash -G sudo ${var.linux_username}
    echo '${var.linux_username}:${var.linux_password}' | chpasswd
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication no/g' /etc/ssh/sshd_config
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
    systemctl restart sshd
    apt-get update
    apt-get install nmap --quiet --yes
    apt-get install apache2 --quiet --yes
    apt-get install iperf3 --quiet --yes
    apt-get install net-tools --quiet --yes
    # Shell setup
    sudo cp /etc/skel/.bashrc /home/${var.linux_username}/
    sudo cp /etc/skel/.profile /home/${var.linux_username}/
    sudo chown ${var.linux_username}:${var.linux_username} /home/${var.linux_username}/.bashrc /home/${var.linux_username}/.profile
  EOF

  scheduling {
    on_host_maintenance = "MIGRATE"
    automatic_restart   = true
  }

  labels = {
    autostop = "false"
  }
}
output "linux_name" {
  value = google_compute_instance.linux_vm.name
  
}
output "linux_ssh_ip" {
  value = length(google_compute_instance.linux_vm.network_interface[0].access_config) > 0 ? google_compute_instance.linux_vm.network_interface[0].access_config[0].nat_ip : null
}
output "linux_mgmt_ip" {
  value = google_compute_instance.linux_vm.network_interface[0].network_ip
}
output "linux_data_ip" {
  value = google_compute_instance.linux_vm.network_interface[1].network_ip
}
output "linux_mgmt_ipv6" {
  value = google_compute_instance.linux_vm.network_interface[0].ipv6_access_config[0].external_ipv6
}
output "linux_data_ipv6" {
  value = google_compute_instance.linux_vm.network_interface[1].ipv6_access_config[0].external_ipv6
}