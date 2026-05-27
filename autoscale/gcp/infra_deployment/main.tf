provider "google" {
  project     = var.project_id
  region      = var.region
}

##################################################
# Variables
variable "project_id" {
  description = "The GCP project ID where resources will be deployed."
  type        = string
  validation {
    condition     = length(var.project_id) > 0
    error_message = "The project_id must not be empty."
  }
}

variable "resource_name_prefix" {
  description = "Prefix for naming resources to ensure uniqueness."
  type        = string
  validation {
    condition     = length(var.resource_name_prefix) > 0 && can(regex("^[a-zA-Z][0-9A-Za-z-_]*$", var.resource_name_prefix)) && length(var.resource_name_prefix) < 12
    error_message = "The resource_name_prefix must not be empty."
  }
}

variable "region" {
  description = "The region where the resources will be deployed."
  type        = string
  validation {
    condition     = length(var.region) > 0
    error_message = "The region must not be empty."
  }
}

variable "mgmt_vpc_routing_mode" {
  description = "The routing mode for the management VPC."
  type        = string
  default     = "REGIONAL"
  validation {
    condition     = var.mgmt_vpc_routing_mode == "REGIONAL" || var.mgmt_vpc_routing_mode == "GLOBAL"
    error_message = "The mgmt_vpc_routing_mode must be either 'REGIONAL' or 'GLOBAL'."
  }
}

variable "mgmt_ip_cidr_range" {
  description = "CIDR range for the management VPC."
  type        = string

}

variable "vpc_connector_ip_cidr_range" {
  description = "CIDR range for the VPC connector."
  type        = string
}

variable "with_diagnostic" {
  description = "Flag to enable diagnostic features."
  type        = bool
  default     = false
}

variable "diag_vpc_routing_mode" {
  description = "The routing mode for the diagnostic VPC."
  type        = string
  default     = "REGIONAL"
  validation {
    condition     = var.diag_vpc_routing_mode == "REGIONAL" || var.diag_vpc_routing_mode == "GLOBAL"
    error_message = "The diag_vpc_routing_mode must be either 'REGIONAL' or 'GLOBAL'."
  }
}

variable "diag_ip_cidr_range" {
  description = "CIDR range for the diagnostic VPC."
  type        = string

}

variable "inside_vpc_routing_mode" {
  description = "The routing mode for the inside VPC."
  type        = string
  default     = "REGIONAL"
  validation {
    condition     = var.inside_vpc_routing_mode == "REGIONAL" || var.inside_vpc_routing_mode == "GLOBAL"
    error_message = "The inside_vpc_routing_mode must be either 'REGIONAL' or 'GLOBAL'."
  }
}

variable "inside_ip_cidr_range" {
  description = "CIDR range for the inside VPC."
  type        = string
}

variable "outside_vpc_routing_mode" {
  description = "The routing mode for the outside VPC."
  type        = string
  default     = "REGIONAL"
  validation {
    condition     = var.outside_vpc_routing_mode == "REGIONAL" || var.outside_vpc_routing_mode == "GLOBAL"
    error_message = "The outside_vpc_routing_mode must be either 'REGIONAL' or 'GLOBAL'."
  }
}

variable "outside_ip_cidr_range" {
  description = "CIDR range for the outside VPC."
  type        = string
}

variable "ftd_reg_via_public_ip" {
  description = "Whether Cloud Functions and FTDv reach FMC via public IPs (enables management NAT path)."
  type        = bool
  default     = false
}

##################################################
# VPC and Subnet Resources

resource "google_compute_network" "mgmt_vpc" {
  name                    = "${var.resource_name_prefix}-mgmt-vpc"
  auto_create_subnetworks = false
  routing_mode            = var.mgmt_vpc_routing_mode
}

resource "google_compute_subnetwork" "mgmt_subnet" {
  name          = "${var.resource_name_prefix}-mgmt-subnet"
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
  name                    = "${var.resource_name_prefix}-diag-vpc"
  auto_create_subnetworks = false
  routing_mode            = var.diag_vpc_routing_mode
  count                   = var.with_diagnostic ? 1 : 0
}

resource "google_compute_subnetwork" "diag_subnet" {
  name          = "${var.resource_name_prefix}-diag-subnet"
  network       = google_compute_network.diag_vpc[0].self_link
  ip_cidr_range = var.diag_ip_cidr_range
  region        = var.region
  count         = var.with_diagnostic ? 1 : 0
}

resource "google_compute_network" "inside_vpc" {
  name                    = "${var.resource_name_prefix}-inside-vpc"
  auto_create_subnetworks = false
  routing_mode            = var.inside_vpc_routing_mode
}

resource "google_compute_subnetwork" "inside_subnet" {
  name          = "${var.resource_name_prefix}-inside-subnet"
  network       = google_compute_network.inside_vpc.self_link
  ip_cidr_range = var.inside_ip_cidr_range
  region        = var.region
}

resource "google_compute_network" "outside_vpc" {
  name                    = "${var.resource_name_prefix}-outside-vpc"
  auto_create_subnetworks = false
  routing_mode            = var.outside_vpc_routing_mode
}

resource "google_compute_subnetwork" "outside_subnet" {
  name          = "${var.resource_name_prefix}-outside-subnet"
  network       = google_compute_network.outside_vpc.self_link
  ip_cidr_range = var.outside_ip_cidr_range
  region        = var.region
}

resource "google_compute_firewall" "mgmt_firewall" {
  name    = "${var.resource_name_prefix}-mgmt-firewall-rule"
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
  name    = "${var.resource_name_prefix}-diag-firewall-rule"
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
  name    = "${var.resource_name_prefix}-in-firewall-rule"
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
  name    = "${var.resource_name_prefix}-out-firewall-rule"
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


resource "google_compute_firewall" "hc_firewall_inside" {
  name    = "${var.resource_name_prefix}-hc-firewall-rule-inside"
  network = google_compute_network.inside_vpc.self_link

  allow {
    protocol = "all"
  }

  source_ranges = ["130.211.0.0/22", "35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22"]
}

resource "google_compute_firewall" "hc_firewall_outside" {
  name    = "${var.resource_name_prefix}-hc-firewall-rule-outside"
  network = google_compute_network.outside_vpc.self_link

  allow {
    protocol = "all"
  }

  source_ranges = ["130.211.0.0/22", "35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22"]
}

resource "google_vpc_access_connector" "connector" {
  name = "${var.resource_name_prefix}-connector"
  subnet {
    name = google_compute_subnetwork.mgmt_vpc_connector_subnet.name
  }
  max_instances = 10
  min_instances = 2
}

# Create a static Public Address to assign to NAT GW
resource "google_compute_address" "mgmt_gw_public_ip" {
  count  = var.ftd_reg_via_public_ip ? 1 : 0
  name   = "${var.resource_name_prefix}-mgmt-gw-public-ip"
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
  name                               = "${var.resource_name_prefix}-mgmt-nat"
  router                             = google_compute_router.mgmt_nat_router[0].name
  region                             = var.region
  nat_ip_allocate_option             = "MANUAL_ONLY"
  nat_ips                            = [google_compute_address.mgmt_gw_public_ip[0].self_link]
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

## VPC and Subnet Outputs
output "mgmt_vpc_name" {
  value = google_compute_network.mgmt_vpc.name
}

output "inside_vpc_name" {
  value = google_compute_network.inside_vpc.name
}

output "outside_vpc_name" {
  value = google_compute_network.outside_vpc.name
}

output "diag_vpc_name" {
  value = var.with_diagnostic ? google_compute_network.diag_vpc[0].name : null
}

output "mgmt_subnet_name" {
  value = google_compute_subnetwork.mgmt_subnet.name
}

output "inside_subnet_name" {
  value = google_compute_subnetwork.inside_subnet.name
}

output "outside_subnet_name" {
  value = google_compute_subnetwork.outside_subnet.name
}

output "diag_subnet_name" {
  value = var.with_diagnostic ? google_compute_subnetwork.diag_subnet[0].name : null
}

##VPC Connector and NAT GW, Router Outputs
output "vpc_connector_name" {
  value = google_vpc_access_connector.connector.name
}

output "mgmt_nat_ip" {
  value = var.ftd_reg_via_public_ip && length(google_compute_address.mgmt_gw_public_ip) > 0 ? google_compute_address.mgmt_gw_public_ip[0].address : null
}

output "mgmt_nat_router" {
  value = var.ftd_reg_via_public_ip && length(google_compute_router.mgmt_nat_router) > 0 ? google_compute_router.mgmt_nat_router[0].name : null
}

##Firewall Rule Outputs
output "mgmt_firewall_rule_name" {
  description = "Name of the management firewall rule"
  value       = google_compute_firewall.mgmt_firewall.name
}

output "inside_firewall_rule_name" {
  description = "Name of the inside firewall rule"
  value       = google_compute_firewall.inside_firewall.name
}

output "outside_firewall_rule_name" {
  description = "Name of the outside firewall rule"
  value       = google_compute_firewall.outside_firewall.name
}

output "diag_firewall_rule_name" {
  description = "Name of the diagnostic firewall rule"
  value       = var.with_diagnostic ? google_compute_firewall.diag_firewall[0].name : null
}

output "inside_hc_firewall_rule_name" {
  description = "Name of the inside health check firewall rule"
  value       = google_compute_firewall.hc_firewall_inside.name
}

output "outside_hc_firewall_rule_name" {
  description = "Name of the outside health check firewall rule"
  value       = google_compute_firewall.hc_firewall_outside.name
}





