##############################################
# Variables
variable "project_id" {}
variable "region" {}
variable "zone" {}
variable "resource_name_prefix" {}
variable "machine_type" {}
variable "source_image_url" {}
variable "service_account_email" {}
variable "cpu_utilization_target" {}
variable "ftdv_replicas" {}

variable "admin_password" {}
variable "hostname" {}
variable "ccl_subnet_range" {}
variable "cluster_grp_name" {}
variable "with_diagnostic" {}

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

# Internal Load Balancer variables from Jinja template
variable "ilb_protocol" {}
variable "ilb_draining_timeout_sec" {}
variable "ilb_port" {}
variable "ilb_check_interval_sec" {}
variable "ilb_timeout_sec" {}
variable "ilb_unhealthy_threshold" {}

variable "mgmt_firewall_rule" {}
variable "diag_firewall_rule" {
  default  = null
  nullable = true
}
variable "outside_firewall_rule" {}
variable "inside_firewall_rule" {}
variable "ccl_firewall_rule" {}
variable "health_check_firewall_rule" {}

resource "google_compute_instance_template" "ftdv_instance_template" {
  name           = "${var.resource_name_prefix}-ftdv-instance-template"
  machine_type   = var.machine_type
  can_ip_forward = true

  tags = concat([
    var.mgmt_firewall_rule,
    var.outside_firewall_rule,
    var.inside_firewall_rule,
    var.ccl_firewall_rule,
    var.health_check_firewall_rule
  ], var.with_diagnostic ? [var.diag_firewall_rule] : [])

  disk {
    device_name  = "boot"
    type         = "PERSISTENT"
    auto_delete  = true
    boot         = true
    source_image = var.source_image_url

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
      for_each = var.with_diagnostic ? [1] : []
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

  dynamic "network_interface" {
    for_each = var.with_diagnostic ? [1] : []
    content {
      network    = "projects/${var.project_id}/global/networks/${var.ccl_vpc_name}"
      subnetwork = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.ccl_subnet_name}"
    }
  }

  reservation_affinity {
    type = "ANY_RESERVATION"

  }

  metadata_startup_script = <<EOT
  {
    "AdminPassword": "${var.admin_password}",
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
    email = var.service_account_email
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
  distribution_policy_zones = ["${var.region}-${var.zone}"]
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
    min_replicas = var.ftdv_replicas
    max_replicas = var.ftdv_replicas
  }
}

resource "google_compute_region_backend_service" "ftdv_ilb_east" {
  name                  = "${var.resource_name_prefix}-ftdv-backend-service-ilb-east"
  region                = var.region
  protocol              = var.ilb_protocol
  load_balancing_scheme = "INTERNAL"
  session_affinity      = "CLIENT_IP_PROTO"
  health_checks         = [google_compute_health_check.ftdv_hc_ilb_east.id]

  connection_draining_timeout_sec = var.ilb_draining_timeout_sec
  network                         = "projects/${var.project_id}/global/networks/${var.inside_vpc_name}"

  backend {
    balancing_mode = "CONNECTION"
    group          = google_compute_region_instance_group_manager.ftdv_igm.instance_group
  }
}

resource "google_compute_health_check" "ftdv_hc_ilb_east" {
  name = "${var.resource_name_prefix}-ftdv-hc-ilb-east"
  tcp_health_check {
    port = var.ilb_port
  }
  check_interval_sec  = var.ilb_check_interval_sec
  timeout_sec         = var.ilb_timeout_sec
  unhealthy_threshold = var.ilb_unhealthy_threshold
}

resource "google_compute_forwarding_rule" "ftdv_fr_ilb_east" {
  name                  = "${var.resource_name_prefix}-ftdv-fr-ilb-east"
  region                = var.region
  load_balancing_scheme = "INTERNAL"
  all_ports             = true
  ip_address            = google_compute_address.ftdv_ilb_ip_east.address
  backend_service       = google_compute_region_backend_service.ftdv_ilb_east.id
  network               = "projects/${var.project_id}/global/networks/${var.inside_vpc_name}"
  subnetwork            = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.inside_subnet_name}"
}

resource "google_compute_address" "ftdv_ilb_ip_east" {
  name         = "${var.resource_name_prefix}-ilb-ip-east"
  region       = var.region
  address_type = "INTERNAL"
  subnetwork   = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.inside_subnet_name}"
}

resource "google_compute_region_backend_service" "ftdv_ilb_west" {
  name                  = "${var.resource_name_prefix}-ftdv-backend-service-ilb-west"
  region                = var.region
  protocol              = var.ilb_protocol
  load_balancing_scheme = "INTERNAL"
  session_affinity      = "CLIENT_IP_PROTO"
  health_checks         = [google_compute_health_check.ftdv_hc_ilb_west.id]

  connection_draining_timeout_sec = var.ilb_draining_timeout_sec
  network                         = "projects/${var.project_id}/global/networks/${var.outside_vpc_name}"

  backend {
    balancing_mode = "CONNECTION"
    group          = google_compute_region_instance_group_manager.ftdv_igm.instance_group
  }
}

resource "google_compute_health_check" "ftdv_hc_ilb_west" {
  name = "${var.resource_name_prefix}-ftdv-hc-ilb-west"
  tcp_health_check {
    port = var.ilb_port
  }
  check_interval_sec  = var.ilb_check_interval_sec
  timeout_sec         = var.ilb_timeout_sec
  unhealthy_threshold = var.ilb_unhealthy_threshold
}

resource "google_compute_forwarding_rule" "ftdv_fr_ilb_west" {
  name                  = "${var.resource_name_prefix}-ftdv-fr-ilb-west"
  region                = var.region
  load_balancing_scheme = "INTERNAL"
  all_ports             = true
  ip_address            = google_compute_address.ftdv_ilb_ip_west.address
  backend_service       = google_compute_region_backend_service.ftdv_ilb_west.id
  network               = "projects/${var.project_id}/global/networks/${var.outside_vpc_name}"
  subnetwork            = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.outside_subnet_name}"
}

resource "google_compute_address" "ftdv_ilb_ip_west" {
  name         = "${var.resource_name_prefix}-ilb-ip-west"
  region       = var.region
  address_type = "INTERNAL"
  subnetwork   = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.outside_subnet_name}"
}
