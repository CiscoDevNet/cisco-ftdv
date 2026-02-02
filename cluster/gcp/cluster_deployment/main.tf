variable "type_of_deployment" {
  description = "This variable determines the type of deployment for the cluster."
  validation {
    condition     = lower(var.type_of_deployment) == "east_west" || lower(var.type_of_deployment) == "north_south"
    error_message = "Invalid deployment type. Must be either 'east_west' or 'north_south'."
  }
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
      length(var.resource_name_prefix) > 1 &&
      length(var.resource_name_prefix) <= 15
    )
    error_message = "Prefix must start with a lowercase letter and contain only lowercase letters and numbers."
  }
}

variable "zone1" {
  description = "The zone where the resources will be deployed."
  type        = string
  validation {
    condition     = can(regex("^[a-f]$", var.zone1))
    error_message = "Zone must be a single character between 'a' and 'f'."
  }
}

variable "zone2" {
  description = "The zone where the resources will be deployed."
  type        = string
  validation {
    condition     = can(regex("^[a-f]$", var.zone2))
    error_message = "Zone must be a single character between 'a' and 'f'."
  }
}

variable "zone3" {
  description = "The zone where the resources will be deployed."
  type        = string
  validation {
    condition     = can(regex("^[a-f]$", var.zone3))
    error_message = "Zone must be a single character between 'a' and 'f'."
  }
}

variable "region" {
  validation {
    condition     = length(var.region) > 0
    error_message = "Region cannot be empty."
  }
}

variable "public_key" {
  description = "SSH public key for instance access."
  validation {
    condition     = can(regex("^(ssh-(rsa|dss|ed25519|ecdsa)\\s.+)$", var.public_key))
    error_message = "Please provide a valid SSH public key."
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

variable "fmc_username" {
  validation {
    condition     = length(var.fmc_username) > 0
    error_message = "FMC username cannot be empty."
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

variable "service_account_mail_id" {
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.service_account_mail_id))
    error_message = "Invalid service account email format."
  }
}

variable "ftd_reg_via_public_ip" {
  description = "Whether to register FTDv using it's public IP or not."
  type        = bool
}

variable "auto_scaling" {
  description = "Enable or disable auto-scaling."
  type        = bool
}

variable "cpu_utilization_target" {
  validation {
    condition     = var.cpu_utilization_target > 0.0 && var.cpu_utilization_target <= 1.0
    error_message = "CPU utilization target must be between 0.0 and 1.0."
  }
}

variable "min_ftd_count" {
  description = "Minimum number of ftdv instances."
  type        = number
  validation {
    condition     = var.min_ftd_count >= 0 && var.min_ftd_count <= 16
    error_message = "Minimum ftdv count cannot be negative."
  }
}

variable "max_ftd_count" {
  description = "The maximum ftd count allowed."
  type        = number
  validation {
    condition     = var.max_ftd_count > 0 && var.max_ftd_count <= 16
    error_message = "The max_ftd_count must be greater than 0."
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

variable "mgmt_firewall_rule_name" {
  validation {
    condition     = length(var.mgmt_firewall_rule_name) > 0
    error_message = "Management firewall rule cannot be empty."
  }
}

variable "diag_firewall_rule_name" {
  default  = null
  nullable = true
}

variable "outside_firewall_rule_name" {
  validation {
    condition     = length(var.outside_firewall_rule_name) > 0
    error_message = "Outside firewall rule cannot be empty."
  }
}

variable "outside_hc_firewall_rule_name" {
  description = "Name of the firewall rule for outside health check."
  validation {
    condition     = length(var.outside_hc_firewall_rule_name) > 0
    error_message = "Outside Health Check firewall rule cannot be empty."
  }
}

variable "inside_firewall_rule_name" {
  validation {
    condition     = length(var.inside_firewall_rule_name) > 0
    error_message = "Inside firewall rule cannot be empty."
  }
}

variable "inside_hc_firewall_rule_name" {
  description = "Name of the firewall rule for inside health check."
  validation {
    condition     = length(var.inside_hc_firewall_rule_name) > 0
    error_message = "Inside Health Check firewall rule cannot be empty."
  }
}

variable "ccl_firewall_rule_name" {
  validation {
    condition     = length(var.ccl_firewall_rule_name) > 0
    error_message = "CCL firewall rule cannot be empty."
  }
}

variable "assign_public_ip_to_mgmt" {
  description = "Assign public IP to management interface."
  type        = bool
  default     = false
}

variable "ilb_frontend_protocol" {
  description = "Frontend protocol for the internal LB (Allowed Values: TCP, UDP)."
  type        = string
  validation {
    condition     = var.ilb_frontend_protocol == "TCP" || var.ilb_frontend_protocol == "UDP"
    error_message = "Frontend protocol for the internal LB must be either 'TCP' or 'UDP'."
  }
}

variable "ilb_backend_protocol" {
  description = "Frontend protocol for the internal LB (Allowed Values: TCP, UDP, UNSPECIFIED)."
  type        = string
  validation {
    condition     = var.ilb_backend_protocol == "TCP" || var.ilb_backend_protocol == "UDP" || var.ilb_backend_protocol == "UNSPECIFIED"
    error_message = "Please provide a valid LB protocol."
  }
}

variable "ilb_draining_timeout_sec" {
  default = 60
  validation {
    condition     = var.ilb_draining_timeout_sec > 0
    error_message = "ILB draining timeout seconds must be a positive integer."
  }
}

variable "ilb_health_check_port" {
  default = 80
  validation {
    condition     = var.ilb_health_check_port > 0
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

variable "elb_health_check_port" {
  default = 80
  validation {
    condition     = var.elb_health_check_port == null || var.elb_health_check_port > 0
    error_message = "ELB port must be null or a positive integer."
  }
}

variable "elb_frontend_protocol" {
  description = "Frontend protocol for the external LB (Allowed Values: TCP, UDP)."
  type        = string
  validation {
    condition     = var.elb_frontend_protocol == "TCP" || var.elb_frontend_protocol == "UDP"
    error_message = "Please provide a valid LB protocol."
  }
}

variable "elb_backend_protocol" {
  description = "Frontend protocol for the external LB (Allowed Values: TCP, UDP, UNSPECIFIED)."
  type        = string
  validation {
    condition     = var.elb_backend_protocol == "TCP" || var.elb_backend_protocol == "UDP" || var.elb_backend_protocol == "UNSPECIFIED"
    error_message = "Please provide a valid LB protocol."
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

variable "elb_unhealthy_threshold" {
  nullable = true
  default  = 1
  validation {
    condition     = var.elb_unhealthy_threshold == null || var.elb_unhealthy_threshold > 0
    error_message = "ELB unhealthy threshold must be null or a positive integer."
  }
}

variable "elb_front_end_ports" {
  default = [80, 443, 22]
  validation {
    condition     = length(var.elb_front_end_ports) > 0 || var.elb_front_end_ports == "all"
    error_message = "ELB frontend ports must be null or non-empty."
  }
}

variable "elb_check_interval_sec" {
  description = "Health check interval for the ELB."
  type        = number
  validation {
    condition     = var.elb_check_interval_sec > 0
    error_message = "Please provide a positive check interval."
  }
}

variable "elb_draining_timeout_sec" {
  description = "Timeout for draining connections on the ELB."
  type        = number
  validation {
    condition     = var.elb_draining_timeout_sec > 0
    error_message = "Please provide a positive draining timeout."
  }
}

variable "ftd_password_secret_name" {
  description = "Name of the Secret for the FTDv password, created in GCP Secret Manager."
  validation {
    condition     = length(var.ftd_password_secret_name) > 0
    error_message = "FTD password secret cannot be empty."
  }
}

variable "fmc_password_secret_name" {
  description = "Name of the Secret for the FMC password."
  validation {
    condition     = length(var.fmc_password_secret_name) > 0
    error_message = "FMC password secret cannot be empty."
  }
}

variable "enable_secure_boot" {
  description = "Enable Secure Boot for the instance."
  type        = bool
  default     = false
}

provider "google" {
  project = var.project_id
  region  = var.region
}

module "ftdv_cluster_function" {
  source = "./modules/cluster_function"

  project_id               = var.project_id
  resource_name_prefix     = var.resource_name_prefix
  region                   = var.region
  ftd_reg_via_public_ip    = var.ftd_reg_via_public_ip
  reg_id                   = var.reg_id
  nat_id                   = var.nat_id
  cluster_grp_name         = var.cluster_grp_name
  policy_id                = var.policy_id
  fmc_ip                   = var.fmc_ip
  fmc_password_secret_name = var.fmc_password_secret_name
  fmc_username             = var.fmc_username
  license_caps             = var.license_caps
  vpc_connector_name       = var.vpc_connector_name
  ftd_password_secret_name = var.ftd_password_secret_name
  perf_tier                = var.performance_tier
}

resource "time_sleep" "wait_for_function" {
  depends_on      = [module.ftdv_cluster_function]
  create_duration = "60s" # Wait for 60 seconds
}

module "east_west" {
  source = "./modules/east_west"

  count = var.type_of_deployment == "east_west" ? 1 : 0

  project_id                    = var.project_id
  region                        = var.region
  zone1                         = var.zone1
  zone2                         = var.zone2
  zone3                         = var.zone3
  resource_name_prefix          = var.resource_name_prefix
  machine_type                  = var.machine_type
  source_image_url              = var.source_image_url
  public_key                    = var.public_key
  service_account_mail_id       = var.service_account_mail_id
  outside_vpc_name              = var.outside_vpc_name
  outside_subnet_name           = var.outside_subnet_name
  inside_vpc_name               = var.inside_vpc_name
  inside_subnet_name            = var.inside_subnet_name
  mgmt_vpc_name                 = var.mgmt_vpc_name
  mgmt_subnet_name              = var.mgmt_subnet_name
  ccl_vpc_name                  = var.ccl_vpc_name
  ccl_subnet_name               = var.ccl_subnet_name
  diag_vpc_name                 = var.diag_vpc_name
  diag_subnet_name              = var.diag_subnet_name
  mgmt_firewall_rule_name       = var.mgmt_firewall_rule_name
  diag_firewall_rule_name       = var.diag_firewall_rule_name
  outside_firewall_rule_name    = var.outside_firewall_rule_name
  inside_firewall_rule_name     = var.inside_firewall_rule_name
  inside_hc_firewall_rule_name  = var.inside_hc_firewall_rule_name
  outside_hc_firewall_rule_name = var.outside_hc_firewall_rule_name
  ccl_firewall_rule_name        = var.ccl_firewall_rule_name
  hostname                      = var.hostname
  with_diagnostic               = var.with_diagnostic
  assign_public_ip_to_mgmt      = var.assign_public_ip_to_mgmt
  auto_scaling                  = var.auto_scaling
  cpu_utilization_target        = var.cpu_utilization_target
  min_ftd_count                 = var.min_ftd_count
  max_ftd_count                 = var.max_ftd_count
  ccl_subnet_range              = var.ccl_subnet_range
  cluster_grp_name              = var.cluster_grp_name
  ilb_frontend_protocol         = var.ilb_frontend_protocol
  ilb_backend_protocol          = var.ilb_backend_protocol
  ilb_health_check_port         = var.ilb_health_check_port
  ilb_check_interval_sec        = var.ilb_check_interval_sec
  ilb_timeout_sec               = var.ilb_timeout_sec
  ilb_unhealthy_threshold       = var.ilb_unhealthy_threshold
  ilb_draining_timeout_sec      = var.ilb_draining_timeout_sec
  enable_secure_boot            = var.enable_secure_boot

  depends_on = [resource.time_sleep.wait_for_function]
}

module "north_south" {
  source = "./modules/north_south"

  count = var.type_of_deployment == "north_south" ? 1 : 0

  project_id                    = var.project_id
  region                        = var.region
  zone1                         = var.zone1
  zone2                         = var.zone2
  zone3                         = var.zone3
  resource_name_prefix          = var.resource_name_prefix
  machine_type                  = var.machine_type
  source_image_url              = var.source_image_url
  public_key                    = var.public_key
  service_account_mail_id       = var.service_account_mail_id
  outside_vpc_name              = var.outside_vpc_name
  outside_subnet_name           = var.outside_subnet_name
  inside_vpc_name               = var.inside_vpc_name
  inside_subnet_name            = var.inside_subnet_name
  mgmt_vpc_name                 = var.mgmt_vpc_name
  mgmt_subnet_name              = var.mgmt_subnet_name
  ccl_vpc_name                  = var.ccl_vpc_name
  ccl_subnet_name               = var.ccl_subnet_name
  diag_vpc_name                 = var.diag_vpc_name
  diag_subnet_name              = var.diag_subnet_name
  inside_firewall_rule_name     = var.inside_firewall_rule_name
  outside_firewall_rule_name    = var.outside_firewall_rule_name
  mgmt_firewall_rule_name       = var.mgmt_firewall_rule_name
  ccl_firewall_rule_name        = var.ccl_firewall_rule_name
  inside_hc_firewall_rule_name  = var.inside_hc_firewall_rule_name
  outside_hc_firewall_rule_name = var.outside_hc_firewall_rule_name
  diag_firewall_rule_name       = var.diag_firewall_rule_name
  hostname                      = var.hostname
  with_diagnostic               = var.with_diagnostic
  assign_public_ip_to_mgmt      = var.assign_public_ip_to_mgmt
  auto_scaling                  = var.auto_scaling
  cpu_utilization_target        = var.cpu_utilization_target
  min_ftd_count                 = var.min_ftd_count
  max_ftd_count                 = var.max_ftd_count
  ccl_subnet_range              = var.ccl_subnet_range
  cluster_grp_name              = var.cluster_grp_name
  elb_health_check_port         = var.elb_health_check_port
  elb_front_end_ports           = var.elb_front_end_ports
  elb_frontend_protocol         = var.elb_frontend_protocol
  elb_backend_protocol          = var.elb_backend_protocol
  elb_timeout_sec               = var.elb_timeout_sec
  elb_check_interval_sec        = var.elb_check_interval_sec
  elb_unhealthy_threshold       = var.elb_unhealthy_threshold
  elb_draining_timeout_sec      = var.elb_draining_timeout_sec
  ilb_frontend_protocol         = var.ilb_frontend_protocol
  ilb_backend_protocol          = var.ilb_backend_protocol
  ilb_health_check_port         = var.ilb_health_check_port
  ilb_check_interval_sec        = var.ilb_check_interval_sec
  ilb_timeout_sec               = var.ilb_timeout_sec
  ilb_unhealthy_threshold       = var.ilb_unhealthy_threshold
  ilb_draining_timeout_sec      = var.ilb_draining_timeout_sec
  enable_secure_boot            = var.enable_secure_boot

  depends_on = [resource.time_sleep.wait_for_function]

}
