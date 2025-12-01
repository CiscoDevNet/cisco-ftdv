##################################################
# Variables
##################################################
# Variables with Validation
variable "project_id" {}
variable "resource_name_prefix" {}
variable "region" {}
variable "mgmt_ip_cidr_range" {}
variable "vpc_connector_ip_cidr_range" {}
variable "with_diagnostic" {}
variable "diag_ip_cidr_range" {
  default = ""
  nullable = false

}
variable "inside_ip_cidr_range" {}
variable "outside_ip_cidr_range" {}
variable "ccl_ip_cidr_range" {}
##################################################
# VPC and Subnet Resources

provider "google" {
  project     = var.project_id
  region      = var.region
}

resource "google_compute_network" "mgmt_vpc" {
  name                    = "${var.resource_name_prefix}-ftdv-mgmt-vpc"
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
}

resource "google_compute_subnetwork" "mgmt_subnet" {
  name          = "${var.resource_name_prefix}-ftdv-mgmt-subnet"
  network       = google_compute_network.mgmt_vpc.self_link
  ip_cidr_range = var.mgmt_ip_cidr_range
  region        = var.region
}

resource "google_compute_subnetwork" "mgmt_vpc_connector_subnet" {
  name          = "${var.resource_name_prefix}-vpc-connector-subnet28"
  network       = google_compute_network.mgmt_vpc.self_link
  ip_cidr_range = var.vpc_connector_ip_cidr_range
  region        = var.region
}

resource "google_compute_network" "diag_vpc" {
  name                    = "${var.resource_name_prefix}-ftdv-diag-vpc"
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
  count                   = var.with_diagnostic ? 1 : 0
}

resource "google_compute_subnetwork" "diag_subnet" {
  name          = "${var.resource_name_prefix}-ftdv-diag-subnet"
  network       = google_compute_network.diag_vpc[0].self_link
  ip_cidr_range = var.diag_ip_cidr_range
  region        = var.region
  count         = var.with_diagnostic ? 1 : 0
}

resource "google_compute_network" "inside_vpc" {
  name                    = "${var.resource_name_prefix}-ftdv-inside-vpc"
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
  mtu = 8896
}

resource "google_compute_subnetwork" "inside_subnet" {
  name          = "${var.resource_name_prefix}-ftdv-inside-subnet"
  network       = google_compute_network.inside_vpc.self_link
  ip_cidr_range = var.inside_ip_cidr_range
  region        = var.region
}

resource "google_compute_network" "outside_vpc" {
  name                    = "${var.resource_name_prefix}-ftdv-outside-vpc"
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
  mtu = 8896
}

resource "google_compute_subnetwork" "outside_subnet" {
  name          = "${var.resource_name_prefix}-ftdv-outside-subnet"
  network       = google_compute_network.outside_vpc.self_link
  ip_cidr_range = var.outside_ip_cidr_range
  region        = var.region
}

resource "google_compute_network" "ccl_vpc" {
  name                    = "${var.resource_name_prefix}-ftdv-ccl-vpc"
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
  mtu = 8896
}

resource "google_compute_subnetwork" "ccl_subnet" {
  name          = "${var.resource_name_prefix}-ftdv-ccl-subnet"
  network       = google_compute_network.ccl_vpc.self_link
  ip_cidr_range = var.ccl_ip_cidr_range
  region        = var.region
}

resource "google_compute_firewall" "mgmt_firewall" {
  name    = "${var.resource_name_prefix}-ftdv-mgmt-firewall-rule"
  network = google_compute_network.mgmt_vpc.self_link

  allow {
    protocol = "tcp"
    ports    = ["22", "443", "8305"]
  }
  allow {
    protocol = "icmp"
  }

  source_ranges = [var.mgmt_ip_cidr_range]
}

resource "google_compute_firewall" "diag_firewall" {
  count   = var.with_diagnostic ? 1 : 0
  name    = "${var.resource_name_prefix}-ftdv-diag-firewall-rule"
  network = google_compute_network.diag_vpc[0].self_link

  allow {
    protocol = "tcp"
    ports    = ["22", "443", "8305"]
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = [var.diag_ip_cidr_range]
}

resource "google_compute_firewall" "inside_firewall" {
  name    = "${var.resource_name_prefix}-ftdv-in-firewall-rule"
  network = google_compute_network.inside_vpc.self_link

  allow {
    protocol = "tcp"
    ports    = ["80", "443", "22"]
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = [var.inside_ip_cidr_range, "130.211.0.0/22", "35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22"]
}

resource "google_compute_firewall" "outside_firewall" {
  name    = "${var.resource_name_prefix}-ftdv-out-firewall-rule"
  network = google_compute_network.outside_vpc.self_link

  allow {
    protocol = "tcp"
    ports    = ["80", "443", "22"]
  }
  allow {
    protocol = "icmp"
  }

  source_ranges = [var.outside_ip_cidr_range, "130.211.0.0/22", "35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22"]
}

resource "google_compute_firewall" "ccl_firewall" {
  name    = "${var.resource_name_prefix}-ftdv-ccl-firewall-rule"
  network = google_compute_network.ccl_vpc.self_link

  allow {
    protocol = "all"
  }

  source_ranges = [var.ccl_ip_cidr_range]
}

resource "google_compute_firewall" "vpc_connector_ingress" {
  name    = "${var.resource_name_prefix}-vpc-connector-ingress"
  network = google_compute_network.mgmt_vpc.self_link

  allow {
    protocol = "all"
  }

  source_ranges = [var.vpc_connector_ip_cidr_range]
}

resource "google_vpc_access_connector" "connector" {
  name          = "${var.resource_name_prefix}-connector"
  subnet {
    name = google_compute_subnetwork.mgmt_vpc_connector_subnet.name
  }
  max_instances = 10
  min_instances = 2
}

