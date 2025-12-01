variable "service_account_email" {}
variable "project_id" {}
variable "region" {}
variable "zone" {}
variable "resource_name_prefix" {}

variable "machine_type" {}
variable "source_image_url" {}

variable "outside_vpc_name" {}
variable "inside_vpc_name" {}
variable "mgmt_vpc_name" {}
variable "diag_vpc_name" {
  default  = null
  nullable = true
}
variable "ccl_vpc_name" {}

variable "outside_subnet_name" {}
variable "inside_subnet_name" {}
variable "mgmt_subnet_name" {}
variable "diag_subnet_name" {
  default  = null
  nullable = true
}
variable "ccl_subnet_name" {}

variable "mgmt_firewall_rule" {}
variable "diag_firewall_rule" {
  default  = null
  nullable = true
}
variable "outside_firewall_rule" {}
variable "inside_firewall_rule" {}
variable "ccl_firewall_rule" {}
variable "health_check_firewall_rule" {}

variable "with_diagnostic" {}
variable "admin_password" {}
variable "hostname" {}
variable "ccl_subnet_range" {}
variable "cluster_grp_name" {}

variable "cpu_utilization_target" {}
variable "ftdv_replicas" {}

variable "ilb_protocol" {}
variable "ilb_draining_timeout_sec" {}
variable "ilb_port" {}
variable "ilb_check_interval_sec" {}
variable "ilb_timeout_sec" {}
variable "ilb_unhealthy_threshold" {}

variable "elb_port" {}
variable "elb_port_name" {}
variable "elb_protocol" {}
variable "elb_timeout_sec" {}
variable "elb_protocol_name" {}
variable "elb_unhealthy_threshold" {}
variable "elb_ip_protocol" {}
variable "elb_front_end_ports" {}

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
    subnetwork = "projects/${var.project_id}/regions/${var.region}/subnets/${var.outside_subnet_name}"
  }

  network_interface {
    network    = "projects/${var.project_id}/global/networks/${var.inside_vpc_name}"
    subnetwork = "projects/${var.project_id}/regions/${var.region}/subnets/${var.inside_subnet_name}"
  }

  network_interface {
    network    = "projects/${var.project_id}/global/networks/${var.mgmt_vpc_name}"
    subnetwork = "projects/${var.project_id}/regions/${var.region}/subnets/${var.mgmt_subnet_name}"

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
      subnetwork = "projects/${var.project_id}/regions/${var.region}/subnets/${var.diag_subnet_name}"
    }
  }

  dynamic "network_interface" {
    for_each = var.with_diagnostic ? [1] : []
    content {
      network    = "projects/${var.project_id}/global/networks/${var.ccl_vpc_name}"
      subnetwork = "projects/${var.project_id}/regions/${var.region}/subnets/${var.ccl_subnet_name}"
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

resource "google_compute_region_backend_service" "ftdv_backend_service_ilb_south" {
  name                  = "${var.resource_name_prefix}-ftdv-backend-service-ilb-south"
  region                = var.region
  protocol              = var.ilb_protocol
  load_balancing_scheme = "INTERNAL"

  backend {
    balancing_mode = "CONNECTION"
    group          = google_compute_region_instance_group_manager.ftdv_igm.instance_group
  }

  health_checks = [google_compute_health_check.ftdv_hc_ilb_south.self_link]

  connection_draining_timeout_sec = var.ilb_draining_timeout_sec
  network                         = "projects/${var.project_id}/global/networks/${var.inside_vpc_name}"
  session_affinity                = "CLIENT_IP_PROTO"
}

resource "google_compute_health_check" "ftdv_hc_ilb_south" {
  name                = "${var.resource_name_prefix}-ftdv-hc-ilb-south"
  check_interval_sec  = var.ilb_check_interval_sec
  timeout_sec         = var.ilb_timeout_sec
  unhealthy_threshold = var.ilb_unhealthy_threshold

  tcp_health_check {
    port = var.ilb_port
  }
}

resource "google_compute_forwarding_rule" "ftdv_fr_ilb_south" {
  name                  = "${var.resource_name_prefix}-ftdv-fr-ilb-south"
  region                = var.region
  all_ports             = true
  load_balancing_scheme = "INTERNAL"
  ip_address            = google_compute_address.ilb_ip_south.self_link
  backend_service       = google_compute_region_backend_service.ftdv_backend_service_ilb_south.self_link
  network               = "projects/${var.project_id}/global/networks/${var.inside_vpc_name}"
  subnetwork            = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.inside_subnet_name}"
}

resource "google_compute_address" "ilb_ip_south" {
  name         = "${var.resource_name_prefix}-ilb-ip-south"
  address_type = "INTERNAL"
  region       = var.region
  subnetwork   = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.inside_subnet_name}"
}

resource "google_compute_region_health_check" "ftdv_hc_elb_north" {
  name                = "${var.resource_name_prefix}-ftdv-hc-elb-north"
  region              = var.region
  check_interval_sec  = 10 # Default value if not provided
  timeout_sec         = var.elb_timeout_sec
  unhealthy_threshold = var.elb_unhealthy_threshold


  tcp_health_check {
    port         = var.elb_port
    proxy_header = "NONE"
  }
}

resource "google_compute_region_backend_service" "ftdv_backend_service_elb_north" {
  name                  = "${var.resource_name_prefix}-ftdv-backend-service-elb-north"
  region                = var.region
  protocol              = var.elb_protocol
  load_balancing_scheme = "EXTERNAL"

  backend {
    balancing_mode = "CONNECTION"
    group          = google_compute_region_instance_group_manager.ftdv_igm.instance_group
  }

  health_checks    = [google_compute_region_health_check.ftdv_hc_elb_north.self_link]
  session_affinity = "CLIENT_IP_PROTO"
}

resource "google_compute_forwarding_rule" "ftdv_fr_elb_north_list_of_ports" {
  count = var.elb_front_end_ports == "all" ? 0 : 1
  name                  = "${var.resource_name_prefix}-ftdv-fr-elb-north"
  region                = var.region
  ip_protocol           = var.elb_ip_protocol
  load_balancing_scheme = "EXTERNAL"
  ip_address            = google_compute_address.elb_ip_north.self_link
  backend_service       = google_compute_region_backend_service.ftdv_backend_service_elb_north.self_link

  ports = var.elb_front_end_ports
}
resource "google_compute_forwarding_rule" "ftdv_fr_elb_north_all_ports" {
  count = var.elb_front_end_ports == "all" ? 1 : 0

  name                  = "${var.resource_name_prefix}-ftdv-fr-elb-north"
  region                = var.region
  ip_protocol           = var.elb_ip_protocol
  load_balancing_scheme = "EXTERNAL"
  ip_address            = google_compute_address.elb_ip_north.self_link
  backend_service       = google_compute_region_backend_service.ftdv_backend_service_elb_north.self_link

  all_ports = true
}

resource "google_compute_address" "elb_ip_north" {
  name         = "${var.resource_name_prefix}-elb-ip-north"
  address_type = "EXTERNAL"
  region       = var.region
}

resource "google_compute_router" "cloud_nat_router" {
  name    = "${var.resource_name_prefix}-cloud-nat-router"
  region  = var.region
  network = "projects/${var.project_id}/global/networks/${var.outside_vpc_name}"
}

resource "google_compute_router_nat" "cloud_nat" {
  name   = "${var.resource_name_prefix}-cloud-nat"
  router = google_compute_router.cloud_nat_router.name
  region = var.region

  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}
