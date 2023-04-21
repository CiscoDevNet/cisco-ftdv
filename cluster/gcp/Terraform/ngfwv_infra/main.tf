terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
      version = "4.37.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

provider "google-beta" {
  project     = var.project_id
  region      = var.region
}


module "vpc_networks" {
    for_each = local.networks_list
    source  = "terraform-google-modules/network/google//modules/vpc"
    version = "~> 4.0"

    project_id   = var.project_id
    network_name = each.value.name

    shared_vpc_host = false
}

module "vpc_subnets" {
    for_each = local.networks_list
    source  = "terraform-google-modules/network/google//modules/subnets"
    version = "~> 4.0"

    project_id   = var.project_id
    network_name = each.value.name
    
    subnets = each.value.subnet

    depends_on = [
      module.vpc_networks
    ]

}


module "firewall_rules" {
  for_each = local.networks_list
  source       = "terraform-google-modules/network/google//modules/firewall-rules"
  project_id   = var.project_id
  network_name = each.value.name

  rules = [{
    name                    = "${each.value.name}-allowaccess"
    description             = null
    direction               = "INGRESS"
    priority                = null
    ranges                  = ["0.0.0.0/0"]
    source_tags             = null
    source_service_accounts = null
    target_tags             = null
    target_service_accounts = null
    allow = [{
      protocol = each.value.protocol
      ports    = each.value.ports
    }]
    deny = []
    log_config = {
      metadata = "INCLUDE_ALL_METADATA"
    }
  }]

  depends_on = [
      module.vpc_networks
    ]
}

module "healthcheck_firewall_rules" {
  source       = "terraform-google-modules/network/google//modules/firewall-rules"
  project_id   = var.project_id
  network_name = "${var.resourceNamePrefix}-ftdv-inside-vpc"

  rules = [{
    name                    = "${var.resourceNamePrefix}-ftdv-inside-health-allow-ssh-ingress"
    description             = null
    direction               = "INGRESS"
    priority                = null
    ranges                  = ["130.211.0.0/22", "35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22"]
    source_tags             = null
    source_service_accounts = null
    target_tags             = null
    target_service_accounts = null
    allow = [{
      protocol = "all"
      ports = []
    }]
    deny = []
    log_config = {
      metadata = "INCLUDE_ALL_METADATA"
    }
  }]

  depends_on = [
      module.vpc_networks
    ]
}



