variable "project_id" {} # GCP Project ID : 
variable "region" {}     # e.g., us-central1, us-east1
variable "zone" {}       # a,b,c,d, any alphabetical character
variable "resource_name_prefix" {
  default = "automation"
}

variable "image" {
  default = "projects/cisco-public/global/images/cisco-ftdv-7-7-0-89"
}
variable "machine_type" {
  default = "n1-standard-4"
}
# variable "admin_password" {}
variable "day0_config" {}

variable "mgmt_vpc_name" {}
variable "mgmt_subnet_name" {}
variable "inside_vpc_name" {}
variable "inside_subnet_name" {}
variable "outside_vpc_name" {}
variable "outside_subnet_name" {}

variable "with_diagnostic" {
  default = false
}
variable "diag_vpc_name" {
  default  = ""
  nullable = true
}
variable "diag_subnet_name" {
  default  = ""
  nullable = true
}

############################################################################################

provider "google" {
  project     = var.project_id
  region      = var.region
}

resource "google_compute_instance" "ftdv_instance" {
  name         = "${var.resource_name_prefix}-ftdv"
  machine_type = var.machine_type
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = var.image
      type  = "pd-standard"
    }
  }

  network_interface {
    network    = var.inside_vpc_name
    subnetwork = var.inside_subnet_name
    stack_type = "IPV4_IPV6"
    ipv6_access_config {
      network_tier = "PREMIUM"
    }
  }

  network_interface {
    network    = var.outside_vpc_name
    subnetwork = var.outside_subnet_name
    stack_type = "IPV4_IPV6"
    ipv6_access_config {
      network_tier = "PREMIUM"
    }
  }

  network_interface {
    network    = var.mgmt_vpc_name
    subnetwork = var.mgmt_subnet_name
    stack_type = "IPV4_IPV6"
    access_config {
      network_tier = "PREMIUM"
      }
    ipv6_access_config {
      network_tier = "PREMIUM"
    }
  }

  dynamic "network_interface" {
    for_each = var.with_diagnostic && var.diag_vpc_name != "" && var.diag_subnet_name != "" ? [1] : []
    content {
      network    = var.diag_vpc_name
      subnetwork = var.diag_subnet_name
      stack_type = "IPV4_IPV6"
    ipv6_access_config {
      network_tier = "PREMIUM"
    }
    }
  }

  can_ip_forward = true

  metadata_startup_script = var.day0_config

  # metadata_startup_script = <<EOF
  # {
  #   "AdminPassword": "${var.admin_password}",
  #   "Hostname": "cim-tf-ftdv",
  #   "DNS1": "8.8.8.8",
  #   "FirewallMode": "routed",
  #   "IPv4Mode": "dhcp",
  #   "IPv6Mode": "dhcp",
  #   "ManageLocally": "No" ${var.with_diagnostic == false ? ",\n    \"Diagnostic\": \"OFF\"" : ""}
  # }
  # EOF
  labels = {
    autostop = "false"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Outputs
output "ftdv_ssh_ip" {
  description = "Public IP address of the management interface"
  value = length(google_compute_instance.ftdv_instance.network_interface[2].access_config) > 0 ? google_compute_instance.ftdv_instance.network_interface[2].access_config[0].nat_ip : null
}
output "ftdv_inside_ip" {
  description = "Private IP address of the inside interface"
  value = google_compute_instance.ftdv_instance.network_interface[0].network_ip
}
output "ftdv_inside_ipv6" {
  description = "IPv6 address of inside interface"
  value = google_compute_instance.ftdv_instance.network_interface[0].ipv6_access_config[0].external_ipv6
}
output "ftdv_outside_ip" {
  description = "Private IP address of the outside interface"
  value = google_compute_instance.ftdv_instance.network_interface[1].network_ip
}
output "ftdv_outside_ipv6" {
  description = "IPv6 address of outside interface"
  value = google_compute_instance.ftdv_instance.network_interface[1].ipv6_access_config[0].external_ipv6
}
output "ftdv_mgmt_ip" {
  description = "Private IP address of the management interface"
  value = google_compute_instance.ftdv_instance.network_interface[2].network_ip
}
output "ftdv_mgmt_ipv6" {
  description = "IPv6 address of the management interface"
  value = google_compute_instance.ftdv_instance.network_interface[2].ipv6_access_config[0].external_ipv6
}
output "ftdv_diag_ip" {
  description = "Private IP address of the diagnostic interface"
  value = var.with_diagnostic && var.diag_vpc_name != "" && var.diag_subnet_name != "" ? google_compute_instance.ftdv_instance.network_interface[3].network_ip : null
}
output "ftdv_diag_ipv6" {
  description = "IPv6 address of the diagnostic interface"
  value = var.with_diagnostic && var.diag_vpc_name != "" && var.diag_subnet_name != "" ? google_compute_instance.ftdv_instance.network_interface[3].ipv6_access_config[0].external_ipv6 : null
}

output "ftdv_instance_name" {
  description = "Name of the FTDv instance"
  value = google_compute_instance.ftdv_instance.name
}

