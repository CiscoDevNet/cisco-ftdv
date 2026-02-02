# Variables
variable "project_id" {}
variable "service_account_mail_id" {}
variable "region" {}
variable "zone1" {}
variable "zone2" {}
variable "zone3" {}

variable "resource_name_prefix" {}

variable "machine_type" {}
variable "source_image_url" {}
variable "public_key" {}

variable "mgmt_vpc_name" {}
variable "mgmt_subnet_name" {}
variable "inside_vpc_name" {}
variable "inside_subnet_name" {}
variable "outside_vpc_name" {}
variable "outside_subnet_name" {}
variable "diag_vpc_name" {
  default  = null
  nullable = true
}
variable "diag_subnet_name" {
  default  = null
  nullable = true
}
variable "ccl_vpc_name" {}
variable "ccl_subnet_name" {}

variable "mgmt_firewall_rule_name" {}
variable "diag_firewall_rule_name" {
  default  = null
  nullable = true
}
variable "outside_firewall_rule_name" {}
variable "inside_firewall_rule_name" {}
variable "ccl_firewall_rule_name" {}
variable "inside_hc_firewall_rule_name" {}  
variable "outside_hc_firewall_rule_name" {}

variable "hostname" {}
variable "with_diagnostic" {}
variable "assign_public_ip_to_mgmt" {}

variable "ccl_subnet_range" {}
variable "cluster_grp_name" {}

variable "auto_scaling" {}
variable "max_ftd_count" {}
variable "min_ftd_count" {}
variable "cpu_utilization_target" {}

variable "ilb_backend_protocol" {}
variable "ilb_frontend_protocol" {}

variable "ilb_health_check_port" {}
variable "ilb_draining_timeout_sec" {}
variable "ilb_check_interval_sec" {}
variable "ilb_timeout_sec" {}
variable "ilb_unhealthy_threshold" {}
variable "enable_secure_boot" {}

# Resources
resource "google_compute_instance_template" "ftdv_instance_template" {
  name           = "${var.resource_name_prefix}-ftdv-instance-template"
  machine_type   = var.machine_type
  can_ip_forward = true

  tags = concat([
    var.mgmt_firewall_rule_name,
    var.outside_firewall_rule_name,
    var.inside_firewall_rule_name,
    var.ccl_firewall_rule_name,
    var.inside_hc_firewall_rule_name,
    var.outside_hc_firewall_rule_name
  ], var.with_diagnostic ? [var.diag_firewall_rule_name] : [])

  disk {
    device_name  = "boot"
    type         = "PERSISTENT"
    auto_delete  = true
    boot         = true
    source_image = var.source_image_url

  }

  shielded_instance_config{
    enable_secure_boot = var.enable_secure_boot
    enable_vtpm        = true
    enable_integrity_monitoring = true
  }

  network_interface {
    network    = "projects/${var.project_id}/global/networks/${var.outside_vpc_name}"
    subnetwork = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.outside_subnet_name}"
  }

  network_interface {
    network    = "projects/${var.project_id}/global/networks/${var.inside_vpc_name}"
    subnetwork = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.inside_subnet_name}"
  }

  network_interface {
    network    = "projects/${var.project_id}/global/networks/${var.mgmt_vpc_name}"
    subnetwork = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.mgmt_subnet_name}"

    dynamic "access_config" {
      for_each = var.assign_public_ip_to_mgmt ? [1] : []
      content {
        network_tier = "PREMIUM"
      }

    }
  }

  dynamic "network_interface" {
    for_each = var.with_diagnostic ? [1] : []
    content {
      network    = "projects/${var.project_id}/global/networks/${var.diag_vpc_name}"
      subnetwork = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.diag_subnet_name}"
    }
  }

  network_interface {
    network    = "projects/${var.project_id}/global/networks/${var.ccl_vpc_name}"
    subnetwork = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.ccl_subnet_name}"
  }

  reservation_affinity {
    type = "ANY_RESERVATION"

  }

  metadata = {
    ssh-keys = var.public_key
  }

  metadata_startup_script = <<EOT
  {
    "AdminPassword": "th1S_w!ll_Be_C#@nged",
    "Hostname": "${var.hostname}",
    "FirewallMode": "routed",
    %{if var.with_diagnostic == false} "Diagnostic": "OFF",%{endif} 
    "ManageLocally": "No",
    "Cluster": {
      "CclSubnetRange": "${var.ccl_subnet_range}",
      "ClusterGroupName": "${var.cluster_grp_name}"
    }
  }
  EOT

  labels = {
    autostop = "false"
  }

  scheduling {
    on_host_maintenance = "MIGRATE"
    automatic_restart   = true
  }

  service_account {
    email = var.service_account_mail_id
    scopes = [
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write",
      "https://www.googleapis.com/auth/service.management.readonly",
      "https://www.googleapis.com/auth/servicecontrol",
      "https://www.googleapis.com/auth/trace.append"
    ]
  }
}

resource "google_compute_region_instance_group_manager" "ftdv_igm" {
  name                      = "${var.resource_name_prefix}-ftdv-instance-group"
  region                    = var.region
  base_instance_name        = "${var.resource_name_prefix}-ftdv-automation-instance"
  distribution_policy_zones = concat(var.zone1 != "" ? ["${var.region}-${var.zone1}"] : [], var.zone2 != "" ? ["${var.region}-${var.zone2}"] : [], var.zone3 != "" ? ["${var.region}-${var.zone3}"] : [])
  version {
    instance_template = google_compute_instance_template.ftdv_instance_template.id
  }
}

resource "google_compute_region_autoscaler" "ftdv_autoscaler" {
  name   = "${var.resource_name_prefix}-ftdv-cluster"
  region = var.region
  target = google_compute_region_instance_group_manager.ftdv_igm.id

  autoscaling_policy {
    cpu_utilization {
      target = var.cpu_utilization_target
    }
    mode         = "ON"
    max_replicas = var.auto_scaling == true ? var.max_ftd_count : var.min_ftd_count
    min_replicas = var.min_ftd_count
  }
}

resource "google_compute_region_backend_service" "ftdv_ilb_inside" {
  name                  = "${var.resource_name_prefix}-ftdv-backend-service-ilb-inside"
  region                = var.region
  protocol              = var.ilb_backend_protocol
  load_balancing_scheme = "INTERNAL"
  session_affinity      = "CLIENT_IP_PROTO"
  health_checks         = [google_compute_health_check.ftdv_hc_ilb_inside.id]

  connection_draining_timeout_sec = var.ilb_draining_timeout_sec
  network                         = "projects/${var.project_id}/global/networks/${var.inside_vpc_name}"

  backend {
    balancing_mode = "CONNECTION"
    group          = google_compute_region_instance_group_manager.ftdv_igm.instance_group
  }
}

resource "google_compute_health_check" "ftdv_hc_ilb_inside" {
  name = "${var.resource_name_prefix}-ftdv-hc-ilb-inside"
  tcp_health_check {
    port = var.ilb_health_check_port
  }
  check_interval_sec  = var.ilb_check_interval_sec
  timeout_sec         = var.ilb_timeout_sec
  unhealthy_threshold = var.ilb_unhealthy_threshold
}

resource "google_compute_forwarding_rule" "ftdv_fr_ilb_inside" {
  name                  = "${var.resource_name_prefix}-ftdv-fr-ilb-inside"
  region                = var.region
  load_balancing_scheme = "INTERNAL"
  ip_protocol           = contains(["TCP", "UDP"], var.ilb_backend_protocol) ? var.ilb_backend_protocol : var.ilb_frontend_protocol
  all_ports             = true
  ip_address            = google_compute_address.ftdv_ilb_ip_inside.address
  backend_service       = google_compute_region_backend_service.ftdv_ilb_inside.id
  network               = "projects/${var.project_id}/global/networks/${var.inside_vpc_name}"
  subnetwork            = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.inside_subnet_name}"
}

resource "google_compute_address" "ftdv_ilb_ip_inside" {
  name         = "${var.resource_name_prefix}-ilb-ip-inside"
  region       = var.region
  address_type = "INTERNAL"
  subnetwork   = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.inside_subnet_name}"
}

resource "google_compute_region_backend_service" "ftdv_ilb_outside" {
  name                  = "${var.resource_name_prefix}-ftdv-backend-service-ilb-outside"
  region                = var.region
  protocol              = var.ilb_backend_protocol
  load_balancing_scheme = "INTERNAL"
  session_affinity      = "CLIENT_IP_PROTO"
  health_checks         = [google_compute_health_check.ftdv_hc_ilb_outside.id]

  connection_draining_timeout_sec = var.ilb_draining_timeout_sec
  network                         = "projects/${var.project_id}/global/networks/${var.outside_vpc_name}"

  backend {
    balancing_mode = "CONNECTION"
    group          = google_compute_region_instance_group_manager.ftdv_igm.instance_group
  }
}

resource "google_compute_health_check" "ftdv_hc_ilb_outside" {
  name = "${var.resource_name_prefix}-ftdv-hc-ilb-outside"
  tcp_health_check {
    port = var.ilb_health_check_port
  }
  check_interval_sec  = var.ilb_check_interval_sec
  timeout_sec         = var.ilb_timeout_sec
  unhealthy_threshold = var.ilb_unhealthy_threshold
}

resource "google_compute_forwarding_rule" "ftdv_fr_ilb_outside" {
  name                  = "${var.resource_name_prefix}-ftdv-fr-ilb-outside"
  region                = var.region
  load_balancing_scheme = "INTERNAL"
  ip_protocol           = contains(["TCP", "UDP"], var.ilb_backend_protocol) ? var.ilb_backend_protocol : var.ilb_frontend_protocol
  all_ports             = true
  ip_address            = google_compute_address.ftdv_ilb_ip_outside.address
  backend_service       = google_compute_region_backend_service.ftdv_ilb_outside.id
  network               = "projects/${var.project_id}/global/networks/${var.outside_vpc_name}"
  subnetwork            = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.outside_subnet_name}"
}

resource "google_compute_address" "ftdv_ilb_ip_outside" {
  name         = "${var.resource_name_prefix}-ilb-ip-outside"
  region       = var.region
  address_type = "INTERNAL"
  subnetwork   = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.outside_subnet_name}"
}
