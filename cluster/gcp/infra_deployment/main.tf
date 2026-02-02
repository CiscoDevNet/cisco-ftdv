provider "google" {
  project     = var.project_id
  region      = var.region
}

# Variables
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
variable "ftd_reg_via_public_ip" {
  description = "Whether to register FTDv using it's public IP or not."
  type        = bool
}


# VPC and Subnet Resources
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

  source_ranges = [var.inside_ip_cidr_range]
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

  source_ranges = [var.outside_ip_cidr_range]
}

resource "google_compute_firewall" "ccl_firewall" {
  name    = "${var.resource_name_prefix}-ftdv-ccl-firewall-rule"
  network = google_compute_network.ccl_vpc.self_link

  allow {
    protocol = "all"
  }

  source_ranges = [var.ccl_ip_cidr_range]
}

resource "google_compute_firewall" "inside_hc_firewall" {
  name    = "${var.resource_name_prefix}-ftdv-in-hc-firewall-rule"
  network = google_compute_network.inside_vpc.self_link

  allow {
    protocol = "tcp"
  }
  disabled = true
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22"]
}

resource "google_compute_firewall" "outside_hc_firewall" {
  name    = "${var.resource_name_prefix}-ftdv-out-hc-firewall-rule"
  network = google_compute_network.outside_vpc.self_link

  allow {
    protocol = "tcp"
  }
  disabled = true
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22"]
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

# If FTDv registration is via Public IP, Google Function needs to access FMCv over public IP.
# We need static IP to allow Google Function access in FMCv ingress security group.
# So when "ftd_reg_via_public_ip" is set to true, Google Function traffic will go via NAT GW's Public IP.

# Create a static Public Address to assign to NAT GW
resource "google_compute_address" "mgmtgw_public_ip" {
  count  = var.ftd_reg_via_public_ip ? 1 : 0
  name   = "${var.resource_name_prefix}-mgmtgw-public-ip"
  region = var.region
}

# Management NAT Router
resource "google_compute_router" "mgmt_nat_router" {
  count   = var.ftd_reg_via_public_ip ? 1 : 0
  name    = "${var.resource_name_prefix}-mgmt-nat-router"
  network = google_compute_network.mgmt_vpc.self_link
  region  = var.region
}

# Management NAT Gateway configuration
resource "google_compute_router_nat" "mgmt_nat" {
  count                              = var.ftd_reg_via_public_ip ? 1 : 0
  name                               = "${var.resource_name_prefix}-cloud-nat"
  router                             = google_compute_router.mgmt_nat_router[0].name
  region                             = var.region
  nat_ip_allocate_option             = "MANUAL_ONLY"
  nat_ips                            = [google_compute_address.mgmtgw_public_ip[0].self_link]
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}


output "mgmt_vpc_self_link" {
  value = google_compute_network.mgmt_vpc.self_link
}

output "mgmt_subnet_self_link" {
  value = google_compute_subnetwork.mgmt_subnet.self_link
}

output "inside_vpc_self_link" {
  value = google_compute_network.inside_vpc.self_link
}

output "inside_subnet_self_link" {
  value = google_compute_subnetwork.inside_subnet.self_link
}

output "outside_vpc_self_link" {
  value = google_compute_network.outside_vpc.self_link
}

output "outside_subnet_self_link" {
  value = google_compute_subnetwork.outside_subnet.self_link
}

output "ccl_vpc_self_link" {
  value = google_compute_network.ccl_vpc.self_link
}

output "ccl_subnet_self_link" {
  value = google_compute_subnetwork.ccl_subnet.self_link
}

output "vpc_connector_name" {
  value = google_vpc_access_connector.connector.name
}

output "mgmt_nat_ip" {
  value = var.ftd_reg_via_public_ip && length(google_compute_address.mgmtgw_public_ip) > 0 ? google_compute_address.mgmtgw_public_ip[0].address : null
}
