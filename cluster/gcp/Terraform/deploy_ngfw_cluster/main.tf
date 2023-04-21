terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
      version = "4.37.0"
    }
  }
}

provider "google" {
  project = "asavgcp-poc-4krn"
  region  = var.region
  zone    = var.zone
}

provider "google-beta" {
  project     = "asavgcp-poc-4krn"
  region      = var.region
}

resource "google_compute_instance_template" "ftdv_template" {
  name = local.instance_template_name
  
  labels = {
    autostop = "false"
  }

  machine_type         = var.machineType
  can_ip_forward       = true

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  disk {
    source_image      = var.sourceImageURL
    auto_delete       = true
    boot              = true
    device_name = "boot"
    type = "PERSISTENT"
    disk_type = "pd-standard"
    disk_size_gb = 49
  }

  network_interface {
    network = "${var.resourceNamePrefix}-ftdv-outside-vpc"
    subnetwork = "${var.resourceNamePrefix}-ftdv-outside-subnet"
  }

  network_interface {
    network = "${var.resourceNamePrefix}-ftdv-inside-vpc"
    subnetwork = "${var.resourceNamePrefix}-ftdv-inside-subnet"
  }

  network_interface {
    network = "${var.resourceNamePrefix}-ftdv-mgmt-vpc"
    subnetwork = "${var.resourceNamePrefix}-ftdv-mgmt-subnet"
    
    # access_config {
    #   network_tier = "PREMIUM"
    # }
    
  }

  network_interface {
    network = "${var.resourceNamePrefix}-ftdv-diag-vpc"
    subnetwork = "${var.resourceNamePrefix}-ftdv-diag-subnet"
  }

  network_interface {
    network = "${var.resourceNamePrefix}-ftdv-ccl-vpc"
    subnetwork = "${var.resourceNamePrefix}-ftdv-ccl-subnet"
  }

  reservation_affinity {
    type = "ANY_RESERVATION"
  }


  metadata = {
    startup-script = "{ \"AdminPassword\": \"${var.adminPassword}\", \"Hostname\": \"${var.hostname}\", \"FirewallMode\": \"routed\", \"ManageLocally\": \"No\", \"Cluster\": { \"CclSubnetRange\": \"${var.cclSubnetRange}\", \"ClusterGroupName\": \"${local.cluster_name}\" } }"
  }

  service_account {
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    email  = var.serviceAccountMailId
    scopes = ["https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring.write", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/trace.append"]
  }
}

resource "google_compute_region_instance_group_manager" "ftdv_instance_group" {
  name = "${var.resourceNamePrefix}-ftdv-instance-group"
  region = var.region
  base_instance_name = "${var.resourceNamePrefix}-ftdv-automation-instance"
  target_size = var.targetSize
  distribution_policy_zones = [var.zone]
  version {
    instance_template  = google_compute_instance_template.ftdv_template.id
  }


}

resource "google_compute_health_check" "tcp-health-check" {
  name        = "${var.resourceNamePrefix}-ftdv-health-check"

  timeout_sec         = var.ftdvTimeoutSec
  check_interval_sec  = var.ftdvCheckIntervalSec
  unhealthy_threshold = var.ftdvUnhealthyThreshold

  tcp_health_check {
    port = var.ftdvHealthCheckPort
  }
}

resource "google_compute_region_autoscaler" "ftdv_autoscaler" {

  name   = "${var.resourceNamePrefix}-ftdv-cluster"
  region = var.region
  target = google_compute_region_instance_group_manager.ftdv_instance_group.id

  autoscaling_policy {
    max_replicas    = var.ftdvReplicas
    min_replicas    = var.ftdvReplicas
    mode = "ON"
    cpu_utilization {
      target = var.cpuUtilizationTarget
    }
  }
  
}

resource "google_compute_region_health_check" "ftdv-hc-ilb-south" {
  name        = "${var.resourceNamePrefix}-ftdv-hc-ilb-south"

  timeout_sec         = var.ilbTimeoutSec
  check_interval_sec  = var.ilbCheckIntervalSec
  unhealthy_threshold = var.ilbUnhealthyThreshold
  region      = var.region
  tcp_health_check {
    port = var.ilbPort
  }
}

resource "google_compute_region_backend_service" "ftdv-backend-service-ilb-south" {
  load_balancing_scheme = "INTERNAL"

  backend {
    group = google_compute_region_instance_group_manager.ftdv_instance_group.instance_group
  }

  region      = var.region
  name        = "${var.resourceNamePrefix}-ftdv-backend-service-ilb-south"
  protocol    = var.ilbProtocol
  

  health_checks = [google_compute_region_health_check.ftdv-hc-ilb-south.id]
   
  connection_draining_timeout_sec = var.ilbDrainingTimeoutSec
  session_affinity  = "CLIENT_IP_PROTO"
  network = "projects/${var.project_name}/global/networks/${local.inside_vpc_name}"

  depends_on = [
    google_compute_region_health_check.ftdv-hc-ilb-south
  ]
}

resource "google_compute_forwarding_rule" "ftdv-fr-ilb-south" {
  name                  = "${var.resourceNamePrefix}-ftdv-fr-ilb-south"
  provider              = google-beta
  region                = var.region
  load_balancing_scheme = "INTERNAL"
  all_ports = true
  ip_address = google_compute_address.ilb-ip-south.id
  backend_service = google_compute_region_backend_service.ftdv-backend-service-ilb-south.id
  network               = "projects/${var.project_name}/global/networks/${local.inside_vpc_name}"
  subnetwork            = "projects/${var.project_name}/regions/${var.region}/subnetworks/${local.inside_subnet_name}"
}

resource "google_compute_address" "ilb-ip-south" {
  name = "${var.resourceNamePrefix}-ilb-ip-south"
  address_type = "INTERNAL"
  region = var.region
  subnetwork = "projects/${var.project_name}/regions/${var.region}/subnetworks/${local.inside_subnet_name}"
}

resource "google_compute_region_backend_service" "ftdv-backend-service-elb-north" {
  load_balancing_scheme = "EXTERNAL"

  backend {
    group = google_compute_region_instance_group_manager.ftdv_instance_group.instance_group
  }

  region      = var.region
  name        = "${var.resourceNamePrefix}-ftdv-backend-service-elb-north"
  #port = var.elbPort
  port_name = var.portName
  protocol    = var.elbProtocol
  health_checks = [google_compute_region_health_check.ftdv-hc-elb-north.id]
  session_affinity  = "CLIENT_IP_PROTO"

  depends_on = [
    google_compute_region_health_check.ftdv-hc-elb-north
  ]
}

resource "google_compute_region_health_check" "ftdv-hc-elb-north" {
  name = "${var.resourceNamePrefix}-ftdv-hc-elb-north"
  
  timeout_sec = var.elbTimeoutSec
  unhealthy_threshold = var.elbUnhealthyThreshold
  region      = var.region
  
  tcp_health_check {
    port = var.elbPort
  }
}

resource "google_compute_forwarding_rule" "ftdv-fr-elb-north" {
  name                  = "${var.resourceNamePrefix}-ftdv-fr-elb-north"
  provider              = google-beta
  region                = var.region
  load_balancing_scheme = "EXTERNAL"
  ip_protocol = var.elbIpProtocol
  ports = var.elbFePorts
  ip_address = google_compute_address.elb-ip-north.id
  backend_service = google_compute_region_backend_service.ftdv-backend-service-elb-north.id
}

resource "google_compute_address" "elb-ip-north" {
  name = "${var.resourceNamePrefix}-elb-ip-north"
  address_type = "EXTERNAL"
  region = var.region
}

resource "google_compute_router" "cloud-nat-router" {
  name    = "${var.resourceNamePrefix}-cloud-nat-router"
  region  = var.region
  network = "projects/${var.project_name}/global/networks/${local.outside_vpc_name}"
}



