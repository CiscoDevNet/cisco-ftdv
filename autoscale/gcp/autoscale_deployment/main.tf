provider "google" {
  project     = var.project_id
  region      = var.region
}

variable "project_id" {
  description = "The ID of the GCP project to use."
  validation {
    condition = (
      length(var.project_id) > 2 &&
      can(regex("^[0-9A-Za-z-]+$", var.project_id))
    )
    error_message = "Please provide a valid project ID."
  }
}

variable "region" {
  description = "The GCP region to create resources in."
  validation {
    condition = (
      length(var.region) > 2 &&
      can(regex("^[0-9A-Za-z-]+$", var.region))
    )
    error_message = "Please provide a valid region."
  }
}

variable "resource_name_prefix" {
  description = "Prefix for naming resources in the deployment."
  validation {
    condition = (
      can(regex("^[a-zA-Z][0-9A-Za-z-_]*$", var.resource_name_prefix)) &&
      length(var.resource_name_prefix) > 1 && length(var.resource_name_prefix) < 12
    )
    error_message = "Prefix must start with a letter and contain only letters, numbers, dashes, or underscores."
  }
}

variable "machine_type" {
  description = "Machine type for the instances."
  validation {
    condition     = can(regex("^[A-Za-z0-9-]+$", var.machine_type))
    error_message = "Please provide a valid machine type."
  }
}

variable "source_image_url" {
  description = "URL to the source image used by instances."
  validation {
    condition     = can(regex("^(https?://|projects/).+", var.source_image_url))
    error_message = "Please provide a valid URL starting with http or https, or a valid GCP image reference beginning with projects/."
  }
}

variable "enable_secure_boot" {
  description = "Enable Secure Boot for FTDv instances (supported from version 10.0 onwards)."
  type        = bool
  default     = false
}

variable "cpu_utilization_target" {
  description = "Target CPU utilization for autoscale."
  type        = number
  validation {
    condition     = var.cpu_utilization_target > 0 && var.cpu_utilization_target < 1
    error_message = "Please provide a valid CPU utilization percentage between 1 and 1."
  }
}

variable "cool_down_period_sec" {
  description = "Scale-in/out cooldown period in seconds."
  type        = number
  validation {
    condition     = var.cool_down_period_sec > 0
    error_message = "Please provide a positive cooldown period."
  }
}

variable "min_ftd_replicas" {
  description = "Minimum number of FTD replicas to maintain."
  type        = number
  validation {
    condition     = var.min_ftd_replicas >= 0
    error_message = "Minimum FTD replicas must be a non-negative integer."
  }
}

variable "max_ftd_replicas" {
  description = "Maximum number of FTD replicas to maintain."
  type        = number
  validation {
    condition     = var.max_ftd_replicas >= 0
    error_message = "Max FTD replicas must be a non-negative integer."
  }
}

variable "elb_port_name" {
  description = "Port name for the external LB."
  validation {
    condition     = can(regex("^[A-Za-z0-9-]+$", var.elb_port_name))
    error_message = "Port name can only include letters, numbers, or dashes."
  }
}

variable "elb_protocol" {
  description = "Protocol for the external LB (e.g., TCP)."
  validation {
    condition     = length(var.elb_protocol) > 2
    error_message = "Please provide a valid LB protocol."
  }
}

variable "elb_protocol_name" {
  description = "Protocol name for the external LB."
  validation {
    condition     = can(regex("^[A-Za-z0-9-]+$", var.elb_protocol_name))
    error_message = "Protocol name can only include letters, numbers, or dashes."
  }
}

variable "elb_timeout_sec" {
  description = "Timeout for the external LB in seconds."
  type        = number
  validation {
    condition     = var.elb_timeout_sec > 0
    error_message = "Please provide a valid LB timeout in seconds."
  }
}

variable "elb_unhealthy_threshold" {
  description = "Unhealthy threshold for the external LB."
  type        = number
  validation {
    condition     = var.elb_unhealthy_threshold > 0
    error_message = "Please provide a valid unhealthy threshold."
  }
}

variable "elb_ip_protocol" {
  description = "IP protocol used by the external LB."
  validation {
    condition     = length(var.elb_ip_protocol) > 2
    error_message = "Please provide a valid IP protocol name."
  }
}

variable "elb_fe_ports" {
  description = "Frontend ports for the external load balancer."
  type        = list(string)
}

variable "ilb_protocol" {
  description = "Protocol for the internal LB."
  validation {
    condition     = length(var.ilb_protocol) > 2
    error_message = "Please provide a valid LB protocol."
  }
}

variable "ilb_protocol_name" {
  description = "Protocol name for the internal LB."
  validation {
    condition     = can(regex("^[A-Za-z0-9-]+$", var.ilb_protocol_name))
    error_message = "Protocol name can only include letters, numbers, or dashes."
  }
}

variable "ilb_check_interval_sec" {
  description = "Health check interval for the ILB in seconds."
  type        = number
  validation {
    condition     = var.ilb_check_interval_sec > 0
    error_message = "Please provide a positive check interval."
  }
}

variable "ilb_timeout_sec" {
  description = "Timeout for the internal LB in seconds."
  type        = number
  validation {
    condition     = var.ilb_timeout_sec > 0
    error_message = "Please provide a valid LB timeout in seconds."
  }
}

variable "ilb_unhealthy_threshold" {
  description = "Unhealthy threshold for the internal LB."
  type        = number
  validation {
    condition     = var.ilb_unhealthy_threshold > 0
    error_message = "Please provide a valid unhealthy threshold."
  }
}

variable "ilb_draining_timeout_sec" {
  description = "Draining timeout for the internal LB in seconds."
  type        = number
  validation {
    condition     = var.ilb_draining_timeout_sec >= 0
    error_message = "Draining timeout cannot be negative."
  }
}

variable "service_account_mail_id" {
  description = "Service account email used by the instances."
  validation {
    condition     = can(regex(".+@.+\\..+", var.service_account_mail_id))
    error_message = "Please provide a valid email address."
  }
}

variable "public_key" {
  description = "SSH public key for instance access."
  validation {
    condition     = can(regex("^(ssh-(rsa|dss|ed25519|ecdsa)\\s.+)$", var.public_key))
    error_message = "Please provide a valid SSH public key."
  }
}

variable "outside_vpc_name" {
  description = "The name of the outside VPC."
  validation {
    condition     = length(var.outside_vpc_name) > 0
    error_message = "Outside VPC name cannot be empty."
  }
}

variable "outside_subnet_name" {
  description = "Subnet name for the outside VPC."
  validation {
    condition     = length(var.outside_subnet_name) > 0
    error_message = "Please provide a valid outside VPC subnet name."
  }
}

variable "inside_vpc_name" {
  description = "The name of the inside VPC."
  validation {
    condition     = length(var.inside_vpc_name) > 0
    error_message = "Inside VPC name cannot be empty."
  }
}

variable "inside_subnet_name" {
  description = "Subnet name for the inside VPC."
  validation {
    condition     = length(var.inside_subnet_name) > 0
    error_message = "Please provide a valid inside VPC subnet name."
  }
}

variable "mgmt_vpc_name" {
  description = "The name of the management VPC."
  validation {
    condition     = length(var.mgmt_vpc_name) > 0
    error_message = "Management VPC name cannot be empty."
  }
}

variable "mgmt_subnet_name" {
  description = "Subnet name for the management VPC."
  validation {
    condition     = length(var.mgmt_subnet_name) > 0
    error_message = "Please provide a valid management VPC subnet name."
  }
}

variable "diag_vpc_name" {
  description = "Name of the diagnostic VPC."
  default      = null
  nullable     = true
}

variable "diag_subnet_name" {
  description = "Subnet name for the diagnostic VPC."
  default      = null
  nullable     = true
}

variable "assign_public_ip_to_mgmt" {
  description = "Indicates whether to deploy using an external IP."
  type        = bool
}

variable "with_diagnostic" {
  description = "Flag to include diagnostic information."
  type        = bool
}

variable "mgmt_firewall_rule_name" {
  description = "Firewall rule for management traffic."
  validation {
    condition     = can(regex("^[A-Za-z0-9-_]+$", var.mgmt_firewall_rule_name))
    error_message = "Firewall rule name can only include letters, numbers, dashes, or underscores."
  }
}

variable "outside_firewall_rule_name" {
  description = "Firewall rule for external traffic."
  validation {
    condition     = can(regex("^[A-Za-z0-9-_]+$", var.outside_firewall_rule_name))
    error_message = "Firewall rule name can only include letters, numbers, dashes, or underscores."
  }
}

variable "inside_firewall_rule_name" {
  description = "Firewall rule for internal traffic."
  validation {
    condition     = can(regex("^[A-Za-z0-9-_]+$", var.inside_firewall_rule_name))
    error_message = "Firewall rule name can only include letters, numbers, dashes, or underscores."
  }
}

variable "health_check_firewall_rule_name" {
  description = "Firewall rule for health checks."
  validation {
    condition     = can(regex("^[A-Za-z0-9-_]+$", var.health_check_firewall_rule_name))
    error_message = "Firewall rule name can only include letters, numbers, dashes, or underscores."
  }
}

variable "diag_firewall_rule_name" {
  description = "Firewall rule for diagnostic traffic."
  default      = null
  nullable     = true
}

variable "fmc_ip" {
  description = "IP address of the FMC."
  validation {
    condition     = can(regex("^((25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d?\\d)$", var.fmc_ip))
    error_message = "Please provide a valid IPv4 address."
  }
}

variable "fmc_username" {
  description = "Username for the FMC."
  validation {
    condition     = length(var.fmc_username) > 0
    error_message = "FMC username cannot be empty."
  }
}

variable "reg_id" {
  description = "Registration ID."
  validation {
    condition     = length(var.reg_id) > 0
    error_message = "Registration ID cannot be empty."
  }
}

variable "nat_id" {
  description = "NAT ID."
  validation {
    condition     = length(var.nat_id) > 0
    error_message = "NAT ID cannot be empty."
  }
}

variable "grp_id" {
  description = "Group ID."
  validation {
    condition     = length(var.grp_id) > 0
    error_message = "Group ID cannot be empty."
  }
}

variable "policy_id" {
  description = "Policy ID."
  validation {
    condition     = length(var.policy_id) > 0
    error_message = "Policy ID cannot be empty."
  }
}

variable "ftd_reg_via_public_ip" {
  description = "Whether FTDv registers to FMC using its public IP (also drives Cloud Function egress via public/NAT path)."
  type        = bool
  default     = false
}

variable "license_caps" {
  description = "License capabilities."
  validation {
    condition     = length(var.license_caps) > 0
    error_message = "License capabilities cannot be empty."
  }
}

variable "instance_prefix_in_fmc" {
  description = "Instance prefix in FMC."
  validation {
    condition     = length(var.instance_prefix_in_fmc) > 0
    error_message = "Instance prefix cannot be empty."
  }
}

variable "outside_gw_name" {
  description = "Name of the outside gateway."
  validation {
    condition     = length(var.outside_gw_name) > 0
    error_message = "Outside gateway name cannot be empty."
  }
}

variable "inside_gw_name" {
  description = "Name of the inside gateway."
  validation {
    condition     = length(var.inside_gw_name) > 0
    error_message = "Inside gateway name cannot be empty."
  }
}

variable "outside_sec_zone" {
  description = "Security zone for outside traffic."
  validation {
    condition     = length(var.outside_sec_zone) > 0
    error_message = "Outside security zone cannot be empty."
  }
}

variable "inside_sec_zone" {
  description = "Security zone for inside traffic."
  validation {
    condition     = length(var.inside_sec_zone) > 0
    error_message = "Inside security zone cannot be empty."
  }
}

variable "fmc_password_secret" {
  description = "Secret for the FMC password."
  validation {
    condition     = length(var.fmc_password_secret) > 0
    error_message = "FMC password secret cannot be empty."
  }
}

variable "new_ftd_password_secret" {
  description = "Secret for the new FTD password."
  validation {
    condition     = length(var.new_ftd_password_secret) > 0
    error_message = "New FTD password secret cannot be empty."
  }
}

variable "vpc_connector_name" {
  description = "Name for the VPC connector resource for cloud functions to access VPC resources."
  validation {
    condition     = can(regex("^[A-Za-z0-9-_]+$", var.vpc_connector_name)) && length(var.vpc_connector_name) <= 25
    error_message = "Please provide a valid VPC connector name."

  }
}

variable "health_check_port" {
  description = "Port for health checks."
  validation {
    condition     = can(regex("^[0-9]+$", var.health_check_port))
    error_message = "Please provide a valid port number."
  }
}

variable "zone" {
  # Zone is string "a,b,c,d" or "a"
  description = "The zone where the resources will be deployed."
  type        = string
  validation {
    condition     = can(regex("^[a-z](,[a-z]){0,2}$", var.zone))
    error_message = "Please provide a valid zone or comma-separated list of up to 3 zones."
  }
}

module "ftdv_functions" {
  source                  = "./modules/functions"
  project_id              = var.project_id
  region                  = var.region
  resource_name_prefix    = var.resource_name_prefix
  service_account_mail_id = var.service_account_mail_id
  vpc_connector_name      = var.vpc_connector_name
  inside_gw_name          = var.inside_gw_name
  outside_gw_name         = var.outside_gw_name
  inside_sec_zone         = var.inside_sec_zone
  outside_sec_zone        = var.outside_sec_zone
  fmc_ip                  = var.fmc_ip
  fmc_username            = var.fmc_username
  reg_id                  = var.reg_id
  nat_id                  = var.nat_id
  grp_id                  = var.grp_id
  policy_id               = var.policy_id
  ftd_reg_via_public_ip   = var.ftd_reg_via_public_ip
  license_caps            = var.license_caps
  instance_prefix_in_fmc  = var.instance_prefix_in_fmc
  fmc_password_secret     = var.fmc_password_secret
  new_ftd_password_secret = var.new_ftd_password_secret
  health_check_port       = var.health_check_port
}

resource "time_sleep" "wait_after_functions" {
  create_duration = "60s"
  depends_on      = [module.ftdv_functions]
}

module "ftdv_autoscale" {
  source                     = "./modules/north_south"
  project_id                 = var.project_id
  region                     = var.region
  resource_name_prefix       = var.resource_name_prefix
  machine_type               = var.machine_type
  source_image_url           = var.source_image_url
  enable_secure_boot         = var.enable_secure_boot
  cpu_utilization_target     = var.cpu_utilization_target
  cool_down_period_sec       = var.cool_down_period_sec
  min_ftd_replicas           = var.min_ftd_replicas
  max_ftd_replicas           = var.max_ftd_replicas
  elb_port_name              = var.elb_port_name
  elb_protocol               = var.elb_protocol
  elb_protocol_name          = var.elb_protocol_name
  elb_timeout_sec            = var.elb_timeout_sec
  elb_unhealthy_threshold    = var.elb_unhealthy_threshold
  elb_ip_protocol            = var.elb_ip_protocol
  elb_fe_ports               = var.elb_fe_ports
  ilb_protocol               = var.ilb_protocol
  ilb_protocol_name          = var.ilb_protocol_name
  ilb_draining_timeout_sec   = var.ilb_draining_timeout_sec
  health_check_port          = var.health_check_port
  ilb_check_interval_sec     = var.ilb_check_interval_sec
  ilb_timeout_sec            = var.ilb_timeout_sec
  ilb_unhealthy_threshold    = var.ilb_unhealthy_threshold
  service_account_email      = var.service_account_mail_id
  public_key                 = var.public_key
  outside_vpc_name           = var.outside_vpc_name
  outside_subnet_name       = var.outside_subnet_name
  inside_vpc_name            = var.inside_vpc_name
  inside_subnet_name        = var.inside_subnet_name
  mgmt_vpc_name              = var.mgmt_vpc_name
  mgmt_subnet_name          = var.mgmt_subnet_name
  diag_vpc_name              = var.diag_vpc_name
  diag_subnet_name          = var.diag_subnet_name
  assign_public_ip_to_mgmt   = var.assign_public_ip_to_mgmt
  with_diagnostic            = var.with_diagnostic
  mgmt_firewall_rule         = var.mgmt_firewall_rule_name
  outside_firewall_rule      = var.outside_firewall_rule_name
  inside_firewall_rule       = var.inside_firewall_rule_name
  health_check_firewall_rule = var.health_check_firewall_rule_name
  diag_firewall_rule         = var.diag_firewall_rule_name
  zone                       = var.zone

  depends_on = [time_sleep.wait_after_functions]
}

# Outputs

output "elb_name" {
  value = module.ftdv_autoscale.elb_name
}

output "ilb_name" {
  value = module.ftdv_autoscale.ilb_name
}

output "instance_group_name" {
  value = module.ftdv_autoscale.instance_group_name
}

output "elb_ip" {
  value = module.ftdv_autoscale.elb_ip
}

output "ilb_ip" {
  value = module.ftdv_autoscale.ilb_ip
}

output "outside_nat_router" {
  value = module.ftdv_autoscale.outside_nat_router
}

output "outside_nat" {
  value = module.ftdv_autoscale.outside_nat
}

output "scale_out_function_name" {
  value = module.ftdv_functions.scale_out_function_name
}

output "scale_in_function_name" {
  value = module.ftdv_functions.scale_in_function_name
}
