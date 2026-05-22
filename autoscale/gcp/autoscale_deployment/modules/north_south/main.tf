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

variable "cpu_utilization_target" {
  description = "Target CPU utilization for autoscale."
  type        = number
  validation {
    condition     = var.cpu_utilization_target > 0 && var.cpu_utilization_target < 1
    error_message = "Please provide a valid CPU utilization percentage between 0 and 1."
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
    condition     = var.max_ftd_replicas > 0
    error_message = "Max FTD replicas must be greater than 0."
  }
}

variable "elb_port" {
  description = "External Load Balancer port."
  type        = number
  validation {
    condition     = var.elb_port > 0 && var.elb_port < 65536
    error_message = "Please provide a valid port number (1-65535)."
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

variable "ilb_draining_timeout_sec" {
  description = "Draining timeout for the internal LB in seconds."
  type        = number
  validation {
    condition     = var.ilb_draining_timeout_sec >= 0
    error_message = "Draining timeout cannot be negative."
  }
}

variable "ilb_port" {
  description = "Internal load balancer port."
  type        = number
  validation {
    condition     = var.ilb_port > 0 && var.ilb_port < 65536
    error_message = "Please provide a valid port number (1-65535)."
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

variable "service_account_email" {
  description = "Service account email used by the instances."
  validation {
    condition     = can(regex(".+@.+\\..+", var.service_account_email))
    error_message = "Please provide a valid email address."
  }
}

variable "admin_password" {
  description = "Password for admin access."
  validation {
    condition     = length(var.admin_password) >= 8
    error_message = "Admin password must be at least 8 characters long."
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

variable "outside_subnetwork_name" {
  description = "Subnet name for the outside VPC."
  validation {
    condition     = length(var.outside_subnetwork_name) > 0
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

variable "inside_subnetwork_name" {
  description = "Subnet name for the inside VPC."
  validation {
    condition     = length(var.inside_subnetwork_name) > 0
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

variable "mgmt_subnetwork_name" {
  description = "Subnet name for the management VPC."
  validation {
    condition     = length(var.mgmt_subnetwork_name) > 0
    error_message = "Please provide a valid management VPC subnet name."
  }
}

variable "diag_vpc_name" {
  description = "Name of the diagnostic VPC."
  validation {
    condition     = length(var.diag_vpc_name) > 0
    error_message = "Diagnostic VPC name cannot be empty."
  }
}

variable "diag_subnetwork_name" {
  description = "Subnet name for the diagnostic VPC."
  validation {
    condition     = length(var.diag_subnetwork_name) > 0
    error_message = "Please provide a valid diagnostic VPC subnet name."
  }
}

variable "deploy_using_external_ip" {
  description = "Indicates whether to deploy using an external IP."
  type        = bool
}

variable "with_diagnostic" {
  description = "Flag to include diagnostic information."
  type        = bool
}

variable "mgmt_firewall_rule" {
  description = "Firewall rule for management traffic."
  validation {
    condition     = can(regex("^[A-Za-z0-9-_]+$", var.mgmt_firewall_rule))
    error_message = "Firewall rule name can only include letters, numbers, dashes, or underscores."
  }
}

variable "outside_firewall_rule" {
  description = "Firewall rule for external traffic."
  validation {
    condition     = can(regex("^[A-Za-z0-9-_]+$", var.outside_firewall_rule))
    error_message = "Firewall rule name can only include letters, numbers, dashes, or underscores."
  }
}

variable "inside_firewall_rule" {
  description = "Firewall rule for internal traffic."
  validation {
    condition     = can(regex("^[A-Za-z0-9-_]+$", var.inside_firewall_rule))
    error_message = "Firewall rule name can only include letters, numbers, dashes, or underscores."
  }
}

variable "health_check_firewall_rule" {
  description = "Firewall rule for health checks."
  validation {
    condition     = can(regex("^[A-Za-z0-9-_]+$", var.health_check_firewall_rule))
    error_message = "Firewall rule name can only include letters, numbers, dashes, or underscores."
  }
}

variable "diag_firewall_rule" {
  description = "Firewall rule for diagnostic traffic."
  validation {
    condition     = can(regex("^[A-Za-z0-9-_]+$", var.diag_firewall_rule))
    error_message = "Firewall rule name can only include letters, numbers, dashes, or underscores."
  }
}

variable "zone" {
  # Zone is string "a,b,c,d" or "a"
  description = "The zone where the resources will be deployed."
  type        = string
  validation {
    condition     = can(regex("^[a-z](,[a-z])*$", var.zone))
    error_message = "Please provide a valid zone or comma-separated list of zones."
  }
}

resource "google_compute_instance_template" "ftdv_instance_template" {
  name           = "${var.resource_name_prefix}-ftdv-instance-template"
  machine_type   = var.machine_type
  can_ip_forward = true

  tags = concat(
    [var.mgmt_firewall_rule],
    var.with_diagnostic ? [var.diag_firewall_rule] : [],
    [
      var.outside_firewall_rule,
      var.inside_firewall_rule,
      var.health_check_firewall_rule
    ]
  )

  reservation_affinity {
    type = "ANY_RESERVATION"

  }
  disk {
    device_name  = "boot"
    source_image = var.source_image_url
    auto_delete  = true
    boot         = true
    type         = "PERSISTENT"
    disk_type    = "pd-standard"
  }

  network_interface {
    network    = "projects/${var.project_id}/global/networks/${var.outside_vpc_name}"
    subnetwork = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.outside_subnetwork_name}"
  }

  network_interface {
    network    = "projects/${var.project_id}/global/networks/${var.inside_vpc_name}"
    subnetwork = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.inside_subnetwork_name}"
  }

  network_interface {
    network    = "projects/${var.project_id}/global/networks/${var.mgmt_vpc_name}"
    subnetwork = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.mgmt_subnetwork_name}"

    dynamic "access_config" {
      for_each = var.deploy_using_external_ip ? [1] : []
      content {
        network_tier = "PREMIUM"
      }

    }
  }

  dynamic "network_interface" {
    for_each = var.with_diagnostic ? [1] : []
    content {
      network    = "projects/${var.project_id}/global/networks/${var.diag_vpc_name}"
      subnetwork = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.diag_subnetwork_name}"
    }
  }

  metadata = {
    startup-script = format(
      <<EOF
          #!/bin/bash
          {
            "AdminPassword": "%s",
            "Hostname": "ftdv-gcp",
            "DNS1": "8.8.8.8",
            "FirewallMode": "routed",
            "IPv4Mode": "dhcp",
            "ManageLocally": "No"%s
          }
    EOF
      ,
      var.admin_password,
      var.with_diagnostic ? "" : ",\n        \"Diagnostic\": \"OFF\""
    )
    ssh-keys = var.public_key
  }

  service_account {
    email = var.service_account_email
    scopes = [
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write",
      "https://www.googleapis.com/auth/service.management.readonly",
      "https://www.googleapis.com/auth/servicecontrol",
      "https://www.googleapis.com/auth/trace.append",
    ]
  }

  scheduling {
    on_host_maintenance = "MIGRATE"
    automatic_restart   = true
  }

  labels = {
    autostop = "false"
  }
}

resource "google_compute_region_instance_group_manager" "ftdv_instance_group" {
  name               = "${var.resource_name_prefix}-ftdv-instance-group"
  region             = var.region
  base_instance_name = "${var.resource_name_prefix}-ftdv-instance"
  target_size        = 1

  version {
    name              = "v1"
    instance_template = google_compute_instance_template.ftdv_instance_template.id
  }

  distribution_policy_zones = [for zone in split(",", var.zone) : "${var.region}-${zone}"]
}

resource "google_compute_region_autoscaler" "ftdv_autoscaler" {
  name   = "${var.resource_name_prefix}-ftdv-autoscaler"
  region = var.region
  target = google_compute_region_instance_group_manager.ftdv_instance_group.id


  autoscaling_policy {
    mode            = "ON"
    max_replicas    = var.max_ftd_replicas
    min_replicas    = var.min_ftd_replicas
    cooldown_period = var.cool_down_period_sec

    cpu_utilization {
      target = var.cpu_utilization_target
    }
  }
}

resource "google_compute_region_backend_service" "ftdv_backend_service_elb" {
  name                  = "${var.resource_name_prefix}-ftdv-backend-service-elb"
  region                = var.region
  protocol              = var.elb_protocol
  load_balancing_scheme = "EXTERNAL"
  port_name             = var.elb_port_name

  backend {
    balancing_mode = "CONNECTION"
    group          = google_compute_region_instance_group_manager.ftdv_instance_group.instance_group

  }

  health_checks = [google_compute_region_health_check.ftdv_hc_elb.id]
}

resource "google_compute_region_health_check" "ftdv_hc_elb" {
  name   = "${var.resource_name_prefix}-ftdv-hc-elb"
  region = var.region
  tcp_health_check {
    port         = var.elb_port
    proxy_header = "NONE"
  }
  timeout_sec         = var.elb_timeout_sec
  unhealthy_threshold = var.elb_unhealthy_threshold
}

resource "google_compute_forwarding_rule" "ftdv_fr_elb" {
  name                  = "${var.resource_name_prefix}-ftdv-fr-elb"
  region                = var.region
  load_balancing_scheme = "EXTERNAL"
  ip_protocol           = var.elb_ip_protocol
  ports                 = var.elb_fe_ports
  backend_service       = google_compute_region_backend_service.ftdv_backend_service_elb.id
  ip_address            = google_compute_address.ftdv_elb_ip.address
}

resource "google_compute_address" "ftdv_elb_ip" {
  name         = "${var.resource_name_prefix}-ftdv-elb-ip"
  region       = var.region
  address_type = "EXTERNAL"
}

resource "google_compute_region_backend_service" "ftdv_backend_service_ilb" {
  name                  = "${var.resource_name_prefix}-ftdv-backend-service-ilb"
  region                = var.region
  protocol              = var.ilb_protocol
  load_balancing_scheme = "INTERNAL"
  backend {
    group          = google_compute_region_instance_group_manager.ftdv_instance_group.instance_group
    balancing_mode = "CONNECTION"
  }

  health_checks = [google_compute_health_check.ftdv_hc_ilb.id]

  connection_draining_timeout_sec = var.ilb_draining_timeout_sec

  network = "projects/${var.project_id}/global/networks/${var.inside_vpc_name}"
}

resource "google_compute_health_check" "ftdv_hc_ilb" {
  name = "${var.resource_name_prefix}-ftdv-hc-ilb"
  tcp_health_check {
    port = var.ilb_port
  }
  check_interval_sec  = var.ilb_check_interval_sec
  timeout_sec         = var.ilb_timeout_sec
  unhealthy_threshold = var.ilb_unhealthy_threshold
}

resource "google_compute_forwarding_rule" "ftdv_fr_ilb" {
  name                  = "${var.resource_name_prefix}-ftdv-fr-ilb"
  region                = var.region
  load_balancing_scheme = "INTERNAL"
  all_ports             = true
  backend_service       = google_compute_region_backend_service.ftdv_backend_service_ilb.id
  network               = "projects/${var.project_id}/global/networks/${var.inside_vpc_name}"
  subnetwork            = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.inside_subnetwork_name}"
}

resource "google_compute_address" "ftdv_ilb_ip" {
  name         = "${var.resource_name_prefix}-ftdv-ilb-ip"
  region       = var.region
  address_type = "INTERNAL"
  subnetwork   = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.inside_subnetwork_name}"
}

resource "google_compute_router" "nat_router" {
  name    = "${var.resource_name_prefix}-nat-router"
  region  = var.region
  network = "projects/${var.project_id}/global/networks/${var.outside_vpc_name}"

}

resource "google_compute_router_nat" "nat" {
  name                               = "${var.resource_name_prefix}-nat"
  router                             = google_compute_router.nat_router.name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}