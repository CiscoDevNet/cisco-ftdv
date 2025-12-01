variable "type_of_deployment" {
  validation {
    condition     = var.type_of_deployment == "east_west" || var.type_of_deployment == "north_south"
    error_message = "Invalid deployment type. Must be either 'east_west' or 'north_south'."
  }
  description = "This variable determines the type of deployment for the cluster."
}

variable "project_id" {
  validation {
    condition     = length(var.project_id) > 0
    error_message = "Project ID cannot be empty."
  }
}

variable "resource_name_prefix" {
  validation {
    condition = (
      can(regex("^[a-z][0-9a-z]*$", var.resource_name_prefix)) &&
      length(var.resource_name_prefix) > 1
    )
    error_message = "Prefix must start with a lowercase letter and contain only lowercase letters and numbers."
  }
}

variable "zone" {
  validation {
    condition     = length(var.zone) > 0
    error_message = "Zone cannot be empty."
  }
}

variable "region" {
  validation {
    condition     = length(var.region) > 0
    error_message = "Region cannot be empty."
  }
}

variable "deploy_with_external_ip" {
  validation {
    condition     = var.deploy_with_external_ip == "True" || var.deploy_with_external_ip == "False"
    error_message = "Deploy with external IP must be either 'True' or 'False'."
  }
}

variable "retry_count" {
  validation {
    condition     = var.retry_count >= 0
    error_message = "Retry count must be a non-negative integer."
  }
}

variable "reg_id" {
  validation {
    condition     = length(var.reg_id) > 0
    error_message = "Reg ID cannot be empty."
  }
}

variable "nat_id" {
  validation {
    condition     = length(var.nat_id) > 0
    error_message = "NAT ID cannot be empty."
  }
}

variable "cls_grp_name" {
  validation {
    condition     = length(var.cls_grp_name) > 0
    error_message = "Cluster group name cannot be empty."
  }
}

variable "policy_id" {
  validation {
    condition     = length(var.policy_id) > 0
    error_message = "Policy ID cannot be empty."
  }
}

variable "fmc_ip" {
  validation {
    condition     = can(regex("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", var.fmc_ip))
    error_message = "Invalid FMC IP address."
  }
}

variable "fmc_password" {
  validation {
    condition     = length(var.fmc_password) >= 8
    error_message = "FMC password cannot be empty and must be more than or equal to 8 characters."
  }
}

variable "fmc_username" {
  validation {
    condition     = length(var.fmc_username) > 0
    error_message = "FMC username cannot be empty."
  }
}

variable "ftdv_password" {
  validation {
    condition     = length(var.ftdv_password) >= 8
    error_message = "FTDV password cannot be empty and must be more than or equal to 8 characters"
  }
}

variable "license_caps" {
  validation {
    condition     = length(var.license_caps) > 0
    error_message = "License caps cannot be empty."
  }
}

variable "performance_tier" {
  validation {
    condition     = length(var.performance_tier) > 0
    error_message = "Performance tier cannot be empty."
  }
}

variable "vpc_connector_name" {
  validation {
    condition     = length(var.vpc_connector_name) > 0 && length(var.vpc_connector_name) <= 25
    error_message = "VPC connector name cannot be empty and must be 25 characters or less."
  }
}
variable "machine_type" {
  validation {
    condition = contains(
      ["c2-standard-4", "c2-standard-8", "c2-standard-16",
      "n1-standard-4", "n1-standard-8", "n1-standard-16",
      "n2-standard-4", "n2-standard-8", "n2-standard-16",
      "n2-highmem-4", "n2-highmem-8", "n1-highmem-4",
      "n1-highmem-8", "n1-highmem-16",
      "n2d-standard-4", "n2d-standard-8", "n2d-standard-16",
      "c2d-standard-4", "c2d-standard-8", "c2d-standard-16"]
    , var.machine_type)
    error_message = "Invalid machine type. Must be one of the predefined types: c2-standard-4, c2-standard-8, c2-standard-16, n1-standard-4, n1-standard-8, n1-standard-16, n2-standard-4, n2-standard-8, n2-standard-16, n2-highmem-4, n2-highmem-8, n1-highmem-4, n1-highmem-8, n1-highmem-16, n2d-standard-4, n2d-standard-8, n2d-standard-16, c2d-standard-4, c2d-standard-8, c2d-standard-16."
  }
}

variable "source_image_url" {
  validation {
    condition     = length(var.source_image_url) > 0
    error_message = "Source image URL cannot be empty."
  }
}

variable "service_account_email" {
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.service_account_email))
    error_message = "Invalid service account email format."
  }
}

variable "cpu_utilization_target" {
  validation {
    condition     = var.cpu_utilization_target > 0.0 && var.cpu_utilization_target <= 1.0
    error_message = "CPU utilization target must be between 0.0 and 1.0."
  }
}

variable "ftdv_replicas" {
  validation {
    condition     = var.ftdv_replicas > 0
    error_message = "FTDV replicas must be a positive integer."
  }
}

variable "admin_password" {
  validation {
    condition     = length(var.admin_password) >= 8
    error_message = "Admin password cannot be empty and must be more than or equal to 8 characters"
  }
}

variable "hostname" {
  validation {
    condition     = length(var.hostname) > 0
    error_message = "Hostname cannot be empty."
  }
}

variable "ccl_subnet_range" {
  validation {
    condition     = length(var.ccl_subnet_range) > 0
    error_message = "CCL subnet range cannot be empty."
  }
}

variable "cluster_grp_name" {
  validation {
    condition     = length(var.cluster_grp_name) > 0
    error_message = "Cluster group name cannot be empty."
  }
}

variable "with_diagnostic" {
  validation {
    condition     = var.with_diagnostic == true || var.with_diagnostic == false
    error_message = "With diagnostic must be a boolean."
  }
}

variable "mgmt_vpc_name" {
  validation {
    condition     = length(var.mgmt_vpc_name) > 0
    error_message = "Management VPC name cannot be empty."
  }
}

variable "mgmt_subnet_name" {
  validation {
    condition     = length(var.mgmt_subnet_name) > 0
    error_message = "Management subnet name cannot be empty."
  }
}

variable "inside_vpc_name" {
  validation {
    condition     = length(var.inside_vpc_name) > 0
    error_message = "Inside VPC name cannot be empty."
  }
}

variable "inside_subnet_name" {
  validation {
    condition     = length(var.inside_subnet_name) > 0
    error_message = "Inside subnet name cannot be empty."
  }
}

variable "outside_vpc_name" {
  validation {
    condition     = length(var.outside_vpc_name) > 0
    error_message = "Outside VPC name cannot be empty."
  }
}

variable "outside_subnet_name" {
  validation {
    condition     = length(var.outside_subnet_name) > 0
    error_message = "Outside subnet name cannot be empty."
  }
}

variable "diag_vpc_name" {
  default  = null
  nullable = true
}

variable "diag_subnet_name" {
  default  = null
  nullable = true
}

variable "ccl_vpc_name" {
  validation {
    condition     = length(var.ccl_vpc_name) > 0
    error_message = "CCL VPC name cannot be empty."
  }
}

variable "ccl_subnet_name" {
  validation {
    condition     = length(var.ccl_subnet_name) > 0
    error_message = "CCL subnet name cannot be empty."
  }
}

variable "mgmt_firewall_rule" {
  validation {
    condition     = length(var.mgmt_firewall_rule) > 0
    error_message = "Management firewall rule cannot be empty."
  }
}

variable "diag_firewall_rule" {
  default  = null
  nullable = true
}

variable "outside_firewall_rule" {
  validation {
    condition     = length(var.outside_firewall_rule) > 0
    error_message = "Outside firewall rule cannot be empty."
  }
}

variable "inside_firewall_rule" {
  validation {
    condition     = length(var.inside_firewall_rule) > 0
    error_message = "Inside firewall rule cannot be empty."
  }
}

variable "ccl_firewall_rule" {
  validation {
    condition     = length(var.ccl_firewall_rule) > 0
    error_message = "CCL firewall rule cannot be empty."
  }
}

variable "health_check_firewall_rule" {
  validation {
    condition     = length(var.health_check_firewall_rule) > 0
    error_message = "Health check firewall rule cannot be empty."
  }
}
variable "ilb_protocol" {
  default = "TCP"
  validation {
    condition     = length(var.ilb_protocol) > 0
    error_message = "ILB protocol cannot be empty."
  }
}

variable "ilb_draining_timeout_sec" {
  default = 60
  validation {
    condition     = var.ilb_draining_timeout_sec > 0
    error_message = "ILB draining timeout seconds must be a positive integer."
  }
}

variable "ilb_port" {
  default = 80
  validation {
    condition     = var.ilb_port > 0
    error_message = "ILB port must be a positive integer."
  }
}

variable "ilb_check_interval_sec" {
  default = 10
  validation {
    condition     = var.ilb_check_interval_sec > 0
    error_message = "ILB check interval seconds must be a positive integer."
  }
}

variable "ilb_timeout_sec" {
  default = 5
  validation {
    condition     = var.ilb_timeout_sec > 0
    error_message = "ILB timeout seconds must be a positive integer."
  }
}

variable "ilb_unhealthy_threshold" {
  default = 1
  validation {
    condition     = var.ilb_unhealthy_threshold > 0
    error_message = "ILB unhealthy threshold must be a positive integer."
  }
}

variable "elb_port" {
  nullable = true
  default  = 80
  validation {
    condition     = var.elb_port == null || var.elb_port > 0
    error_message = "ELB port must be null or a positive integer."
  }
}

variable "elb_port_name" {
  nullable = true
  default  = "tcp"
  validation {
    condition     = var.elb_port_name == null || length(var.elb_port_name) > 0
    error_message = "ELB port name must be null or non-empty."
  }
}

variable "elb_protocol" {
  nullable = true
  default  = "TCP"
  validation {
    condition     = var.elb_protocol == null || length(var.elb_protocol) > 0
    error_message = "ELB protocol must be null or non-empty."
  }
}

variable "elb_timeout_sec" {
  nullable = true
  default  = 5
  validation {
    condition     = var.elb_timeout_sec == null || var.elb_timeout_sec > 0
    error_message = "ELB timeout seconds must be null or a positive integer."
  }
}

variable "elb_protocol_name" {
  nullable = true
  default  = "tcp"
  validation {
    condition     = var.elb_protocol_name == null || length(var.elb_protocol_name) > 0
    error_message = "ELB protocol name must be null or non-empty."
  }
}

variable "elb_unhealthy_threshold" {
  nullable = true
  default  = 1
  validation {
    condition     = var.elb_unhealthy_threshold == null || var.elb_unhealthy_threshold > 0
    error_message = "ELB unhealthy threshold must be null or a positive integer."
  }
}

variable "elb_ip_protocol" {
  nullable = true
  default  = "TCP"
  validation {
    condition     = var.elb_ip_protocol == null || length(var.elb_ip_protocol) > 0
    error_message = "ELB IP protocol must be null or non-empty."
  }
}

variable "elb_front_end_ports" {
  nullable = true
  default  = [80, 443, 22]
  validation {
    condition     = var.elb_front_end_ports == null || length(var.elb_front_end_ports) > 0
    error_message = "ELB frontend ports must be null or non-empty."
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}


module "ftdv_cluster_function" {
  source = "./modules/cluster_function"

  project_id              = var.project_id
  resource_name_prefix    = var.resource_name_prefix
  region                  = var.region
  service_account_email   = var.service_account_email
  deploy_with_external_ip = var.deploy_with_external_ip
  retry_count             = var.retry_count
  reg_id                  = var.reg_id
  nat_id                  = var.nat_id
  cls_grp_name            = var.cls_grp_name
  policy_id               = var.policy_id
  fmc_ip                  = var.fmc_ip
  fmc_password            = var.fmc_password
  fmc_username            = var.fmc_username
  ftdv_password           = var.ftdv_password
  license_caps            = var.license_caps
  performance_tier        = var.performance_tier
  vpc_connector_name      = var.vpc_connector_name
}

resource "time_sleep" "wait_for_function" {
  depends_on      = [module.ftdv_cluster_function]
  create_duration = "60s" # Wait for 60 seconds
}

module "east_west" {
  source = "./modules/east_west"

  count = var.type_of_deployment == "east_west" ? 1 : 0

  project_id                 = var.project_id
  region                     = var.region
  zone                       = var.zone
  resource_name_prefix       = var.resource_name_prefix
  machine_type               = var.machine_type
  source_image_url           = var.source_image_url
  service_account_email      = var.service_account_email
  cpu_utilization_target     = var.cpu_utilization_target
  ftdv_replicas              = var.ftdv_replicas
  admin_password             = var.admin_password
  hostname                   = var.hostname
  ccl_subnet_range           = var.ccl_subnet_range
  cluster_grp_name           = var.cluster_grp_name
  with_diagnostic            = var.with_diagnostic
  mgmt_vpc_name              = var.mgmt_vpc_name
  mgmt_subnet_name           = var.mgmt_subnet_name
  inside_vpc_name            = var.inside_vpc_name
  inside_subnet_name         = var.inside_subnet_name
  outside_vpc_name           = var.outside_vpc_name
  outside_subnet_name        = var.outside_subnet_name
  diag_vpc_name              = var.diag_vpc_name
  diag_subnet_name           = var.diag_subnet_name
  ccl_vpc_name               = var.ccl_vpc_name
  ccl_subnet_name            = var.ccl_subnet_name
  mgmt_firewall_rule         = var.mgmt_firewall_rule
  diag_firewall_rule         = var.diag_firewall_rule
  outside_firewall_rule      = var.outside_firewall_rule
  inside_firewall_rule       = var.inside_firewall_rule
  ccl_firewall_rule          = var.ccl_firewall_rule
  health_check_firewall_rule = var.health_check_firewall_rule
  ilb_protocol               = var.ilb_protocol
  ilb_draining_timeout_sec   = var.ilb_draining_timeout_sec
  ilb_port                   = var.ilb_port
  ilb_check_interval_sec     = var.ilb_check_interval_sec
  ilb_timeout_sec            = var.ilb_timeout_sec
  ilb_unhealthy_threshold    = var.ilb_unhealthy_threshold

  depends_on = [resource.time_sleep.wait_for_function]
}

module "north_south" {
  source = "./modules/north_south"

  count = var.type_of_deployment == "north_south" ? 1 : 0

  project_id                 = var.project_id
  region                     = var.region
  zone                       = var.zone
  resource_name_prefix       = var.resource_name_prefix
  machine_type               = var.machine_type
  source_image_url           = var.source_image_url
  service_account_email      = var.service_account_email
  cpu_utilization_target     = var.cpu_utilization_target
  ftdv_replicas              = var.ftdv_replicas
  admin_password             = var.admin_password
  hostname                   = var.hostname
  ccl_subnet_range           = var.ccl_subnet_range
  cluster_grp_name           = var.cluster_grp_name
  with_diagnostic            = var.with_diagnostic
  mgmt_vpc_name              = var.mgmt_vpc_name
  mgmt_subnet_name           = var.mgmt_subnet_name
  inside_vpc_name            = var.inside_vpc_name
  inside_subnet_name         = var.inside_subnet_name
  outside_vpc_name           = var.outside_vpc_name
  outside_subnet_name        = var.outside_subnet_name
  diag_vpc_name              = var.diag_vpc_name
  diag_subnet_name           = var.diag_subnet_name
  ccl_vpc_name               = var.ccl_vpc_name
  ccl_subnet_name            = var.ccl_subnet_name
  mgmt_firewall_rule         = var.mgmt_firewall_rule
  diag_firewall_rule         = var.diag_firewall_rule
  outside_firewall_rule      = var.outside_firewall_rule
  inside_firewall_rule       = var.inside_firewall_rule
  ccl_firewall_rule          = var.ccl_firewall_rule
  health_check_firewall_rule = var.health_check_firewall_rule
  ilb_protocol               = var.ilb_protocol
  ilb_draining_timeout_sec   = var.ilb_draining_timeout_sec
  ilb_port                   = var.ilb_port
  ilb_check_interval_sec     = var.ilb_check_interval_sec
  ilb_timeout_sec            = var.ilb_timeout_sec
  ilb_unhealthy_threshold    = var.ilb_unhealthy_threshold
  elb_ip_protocol            = var.elb_ip_protocol
  elb_front_end_ports        = var.elb_front_end_ports
  elb_port                   = var.elb_port
  elb_port_name              = var.elb_port_name
  elb_protocol               = var.elb_protocol
  elb_timeout_sec            = var.elb_timeout_sec
  elb_protocol_name          = var.elb_protocol_name
  elb_unhealthy_threshold    = var.elb_unhealthy_threshold

  depends_on = [resource.time_sleep.wait_for_function]
}
