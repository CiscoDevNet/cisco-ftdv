
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

module "log_export" {
  source                 = "terraform-google-modules/log-export/google"
  destination_uri        = "${module.destination.destination_uri}"
  filter = local.filter_rule
  log_sink_name          = "${var.resourceNamePrefix}-ftdv-insert-sink"
  parent_resource_id   = "asavgcp-poc-4krn"
  unique_writer_identity = true
}

module "destination" {
  source                   = "terraform-google-modules/log-export/google//modules/pubsub"
  project_id               = "asavgcp-poc-4krn"
  topic_name               = "${var.resourceNamePrefix}-ftdv-pubsub-topic-insert"
  log_sink_writer_identity = "${module.log_export.writer_identity}"
  create_subscriber        = false
}

resource "google_cloudfunctions_function" "function" {
  name        = "${var.resourceNamePrefix}-ftdv-cluster-action"
  runtime     = "python39"
  timeout = 540
  source_archive_bucket = var.bucket_name
  source_archive_object = var.function_archieve_object
  entry_point           = "cluster_handler"
  environment_variables = {
    EXTERNAL_IP_ENABLE: var.deployWithExternalIP
    RETRY_COUNT: var.retryCount
    REG_ID: var.regID
    NAT_ID: var.natID
    CLS_GRP_NAME: local.cluster_name
    POLICY_ID: var.policyID
    FMC_IP: var.fmcIP
    FMC_PASSWORD: var.fmcPassword
    FMC_USERNAME: var.fmcUsername
    FTDV_PASSWORD: var.ftdvPassword
    LICENSE_CAPS: var.licenseCAPS
    PERF_TIER: var.performanceTier
  }
  max_instances = 1
  vpc_connector = var.vpcConnectorName
  vpc_connector_egress_settings = "PRIVATE_RANGES_ONLY"
  ingress_settings = "ALLOW_ALL"
  event_trigger {
    resource = "${var.resourceNamePrefix}-ftdv-pubsub-topic-insert"
    event_type = "google.pubsub.topic.publish"
  }

}




