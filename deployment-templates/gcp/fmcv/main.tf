variable "project_id" {} # GCP Project ID : 
variable "region" {}     # e.g., us-central1, us-east1
variable "zone" {}       # a,b,c,d, any alphabetical character
variable "resource_name_prefix" {
  default = "automation"
}

variable "image" {
  default = "projects/cisco-public/global/images/cisco-fmcv-7-7-0-91"
}
variable "machine_type" {
  default = "n2-standard-8"
}

variable "mgmt_vpc_name" {}
variable "mgmt_subnet_name" {}

variable "day0_config" {}

variable "dualstack" {}

############################################################################################

provider "google" {
  project     = var.project_id
  region      = var.region
  # credentials = file(env("CREDENTIALS_FILE_PATH"))
}

resource "google_compute_instance" "fmcv_instance" {
  name         = "${var.resource_name_prefix}-fmcv"
  machine_type = var.machine_type
  zone         = var.zone


  boot_disk {
    initialize_params {
      image = var.image
      type  = "pd-standard"
    }
  }

  network_interface {
    network    = var.mgmt_vpc_name
    subnetwork = var.mgmt_subnet_name
    stack_type = var.dualstack ? "IPV4_IPV6" : "IPV4_ONLY"    
    access_config {
      network_tier = "PREMIUM"
    }
    dynamic "ipv6_access_config" {
      for_each = var.dualstack ? [1] : []
      content {
        network_tier = "PREMIUM"
      }
    }
  }
  can_ip_forward = true
  metadata_startup_script = var.day0_config

  labels = {
    autostop = "false"
  }

  lifecycle {
    create_before_destroy = true
  }

}

# Outputs
output "fmcv_ssh_ip" {
  description = "Public IPv4 address of the management interface"
  value = length(google_compute_instance.fmcv_instance.network_interface[0].access_config) > 0 ? google_compute_instance.fmcv_instance.network_interface[0].access_config[0].nat_ip : null
}
output "fmcv_mgmt_ip" {
  description = "Private IP address of the FMCv"
  value = google_compute_instance.fmcv_instance.network_interface[0].network_ip
}
output "fmcv_mgmt_ipv6" {
  description = "IPv6 address of the FMCv"
  value = var.dualstack ? google_compute_instance.fmcv_instance.network_interface[0].ipv6_access_config[0].external_ipv6 : null
}
output "fmcv_instance_name" {
  description = "Name of the fmcv instance"
  value = google_compute_instance.fmcv_instance.name
}