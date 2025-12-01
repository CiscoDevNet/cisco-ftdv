variable "project_id" {}
variable "resource_name_prefix" {}
variable "region" {}
variable "service_account_email" {}
variable "deploy_with_external_ip" {}
variable "retry_count" {}
variable "reg_id" {}
variable "nat_id" {}
variable "cls_grp_name" {}
variable "policy_id" {}
variable "fmc_ip" {}
variable "fmc_password" {}
variable "fmc_username" {}
variable "ftdv_password" {}
variable "license_caps" {}
variable "performance_tier" {}
variable "vpc_connector_name" {}

# Create a GCS bucket to store the Cloud Function ZIP archive
resource "google_storage_bucket" "ftdv_bucket" {
  name          = "${var.resource_name_prefix}-ftdv-cluster-bucket"
  location      = var.region
  storage_class = "STANDARD"

  force_destroy               = true
  uniform_bucket_level_access = true
}

# Create a ZIP archive of all files in ./src directory
data "archive_file" "ftdv_cluster_zip" {
  type        = "zip"
  source_dir  = "${path.module}/src"
  output_path = "${path.module}/src/ftdv_cluster_function.zip"
}

# Upload the ZIP archive to the created bucket
resource "google_storage_bucket_object" "ftdv_cluster_function" {
  name   = "ftdv_cluster_function.zip"
  bucket = google_storage_bucket.ftdv_bucket.name
  source = data.archive_file.ftdv_cluster_zip.output_path
}

resource "google_logging_project_sink" "ftdv_insert_sink" {
  name        = "${var.resource_name_prefix}-ftdv-insert-sink"
  destination = "pubsub.googleapis.com/${google_pubsub_topic.ftdv_pubsub_topic_insert.id}"

  filter                 = "(resource.type = \"gce_instance_group_manager\" AND resource.labels.instance_group_manager_name = \"${var.resource_name_prefix}-ftdv-instance-group\" AND protoPayload.methodName = \"v1.compute.regionInstanceGroupManagers.insert\" AND operation.last = true) OR (resource.type = \"cloud_function\" AND resource.labels.function_name = \"${var.resource_name_prefix}-ftdv-cluster-action\" AND textPayload:\"Reattempt\")"
  unique_writer_identity = false
}


# Pub/Sub Topic for Cluster Deployment
resource "google_pubsub_topic" "ftdv_pubsub_topic_insert" {
  name = "${var.resource_name_prefix}-ftdv-pubsub-topic-insert"

}

# IAM Binding for Pub/Sub
resource "google_pubsub_topic_iam_binding" "ftdv_pubsub_binding" {
  topic = google_pubsub_topic.ftdv_pubsub_topic_insert.name
  role  = "roles/pubsub.publisher"
  members = [
    # google_logging_project_sink.ftdv_insert_sink.writer_identity,
    "serviceAccount:cloud-logs@system.gserviceaccount.com"
    
  ]
}

# Cloud Function to Handle Cluster Actions
resource "google_cloudfunctions_function" "ftdv_cluster_action" {
  name                  = "${var.resource_name_prefix}-ftdv-cluster-action"
  region                = var.region
  runtime               = "python39"
  timeout               = 540
  entry_point           = "cluster_handler"
  available_memory_mb   = 256
  source_archive_bucket = google_storage_bucket.ftdv_bucket.name
  source_archive_object = google_storage_bucket_object.ftdv_cluster_function.name
  max_instances         = 1

  environment_variables = {
    EXTERNAL_IP_ENABLE = var.deploy_with_external_ip
    RETRY_COUNT        = var.retry_count
    REG_ID             = var.reg_id
    NAT_ID             = var.nat_id
    CLS_GRP_NAME       = var.cls_grp_name
    POLICY_ID          = var.policy_id
    FMC_IP             = var.fmc_ip
    FMC_PASSWORD       = var.fmc_password
    FMC_USERNAME       = var.fmc_username
    FTDV_PASSWORD      = var.ftdv_password
    LICENSE_CAPS       = var.license_caps
    PERF_TIER          = var.performance_tier
    RESOURCE_PREFIX    = var.resource_name_prefix
  }

  vpc_connector                 = var.vpc_connector_name
  vpc_connector_egress_settings = "PRIVATE_RANGES_ONLY"
  ingress_settings              = "ALLOW_ALL"

  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.ftdv_pubsub_topic_insert.name
  }
}
