# Input variables for the FTDv cluster function module
variable "project_id" {}
variable "region" {}
variable "resource_name_prefix" {}
variable "vpc_connector_name" {}

variable "fmc_ip" {}
variable "fmc_password_secret_name" {}
variable "fmc_username" {}
variable "reg_id" {}
variable "nat_id" {}
variable "policy_id" {}
variable "perf_tier" {}

variable "cluster_grp_name" {}
variable "ftd_reg_via_public_ip" {}
variable "license_caps" {}
variable "ftd_password_secret_name" {}

# Create storage bucket for storing Cloud Functions code
resource "google_storage_bucket" "ftdv_bucket" {
  name          = "${var.resource_name_prefix}-ftdv-cluster-bucket"
  location      = var.region
  storage_class = "STANDARD"

  force_destroy               = true
  uniform_bucket_level_access = true
}

# Create zip archive of scale-in function code
data "archive_file" "ftdv_cluster_scalein_action_zip" {
  type        = "zip"
  source_dir  = "${path.module}/scalein-action"
  output_path = "${path.module}/scalein-action/ftdv_scalein.zip"
}

# Create zip archive of scale-out function code
data "archive_file" "ftdv_cluster_scaleout_action_zip" {
  type        = "zip"
  source_dir  = "${path.module}/scaleout-action"
  output_path = "${path.module}/scaleout-action/ftdv_scaleout.zip"
}

# Upload scale-in function zip to storage bucket
resource "google_storage_bucket_object" "ftdv_cluster_scalein_action_object" {
  name   = "ftdv_scalein.zip"
  bucket = google_storage_bucket.ftdv_bucket.id
  source = data.archive_file.ftdv_cluster_scalein_action_zip.output_path

  depends_on = [ google_storage_bucket.ftdv_bucket ]
}

# Upload scale-out function zip to storage bucket
resource "google_storage_bucket_object" "ftdv_cluster_scaleout_action_object" {
  name   = "ftdv_scaleout.zip"
  bucket = google_storage_bucket.ftdv_bucket.id
  source = data.archive_file.ftdv_cluster_scaleout_action_zip.output_path

  depends_on = [ google_storage_bucket.ftdv_bucket ]
}

# Delete local zip files after uploading to bucket
resource "null_resource" "delete_zip_files" {
  depends_on = [
    google_storage_bucket_object.ftdv_cluster_scalein_action_object,
    google_storage_bucket_object.ftdv_cluster_scaleout_action_object
  ]
  provisioner "local-exec" {
    command = "rm -f ${data.archive_file.ftdv_cluster_scalein_action_zip.output_path} ${data.archive_file.ftdv_cluster_scaleout_action_zip.output_path}"
  }
}

# Create Pub/Sub topic for instance insertion events
resource "google_pubsub_topic" "insert" {
  name = "${var.resource_name_prefix}-ftdv-pubsub-topic-insert"
}

# Create Pub/Sub topic for instance deletion events
resource "google_pubsub_topic" "delete" {
  name = "${var.resource_name_prefix}-ftdv-pubsub-topic-delete"
}

# Create log sink to capture instance creation events
resource "google_logging_project_sink" "insert_sink" {
  name                   = "${var.resource_name_prefix}-ftdv-insert-sink"
  destination            = "pubsub.googleapis.com/projects/${var.project_id}/topics/${google_pubsub_topic.insert.name}"
  filter                 = "(resource.type = \"gce_instance\" AND protoPayload.methodName = \"v1.compute.instances.insert\" AND operation.last = true AND protoPayload.resourceName:\"${var.resource_name_prefix}\")"
  unique_writer_identity = false
}

# Create log sink to capture instance deletion events
resource "google_logging_project_sink" "delete_sink" {
  name                   = "${var.resource_name_prefix}-ftdv-delete-sink"
  destination            = "pubsub.googleapis.com/projects/${var.project_id}/topics/${google_pubsub_topic.delete.name}"
  filter                 = "resource.type = \"gce_instance\" AND protoPayload.methodName = \"v1.compute.instances.delete\" AND protoPayload.resourceName:\"${var.resource_name_prefix}\" AND operation.first=true"
  unique_writer_identity = false
}

# Grant publisher permissions for the insert topic
resource "google_pubsub_topic_iam_binding" "insert" {
  topic = google_pubsub_topic.insert.id

  role = "roles/pubsub.publisher"

  members = [
    "serviceAccount:cloud-logs@system.gserviceaccount.com"
  ]
}

# Grant publisher permissions for the delete topic
resource "google_pubsub_topic_iam_binding" "delete" {
  topic = google_pubsub_topic.delete.id

  role = "roles/pubsub.publisher"

  members = [
    "serviceAccount:cloud-logs@system.gserviceaccount.com"
  ]
}

# Create Cloud Function for handling scale-out operations
resource "google_cloudfunctions_function" "scaleout_action" {
  name                  = "${var.resource_name_prefix}-ftdv-scaleout-action"
  runtime               = "python312"
  entry_point           = "scale_out"
  source_archive_bucket = google_storage_bucket.ftdv_bucket.id
  source_archive_object = google_storage_bucket_object.ftdv_cluster_scaleout_action_object.name
  timeout               = 540
  max_instances         = 16
  ingress_settings      = "ALLOW_ALL"

  environment_variables = {
    RESOURCE_NAME_PREFIX   = var.resource_name_prefix
    FTD_REG_VIA_PUBLIC_IP  = var.ftd_reg_via_public_ip
    CLS_GRP_NAME           = var.cluster_grp_name
    FMC_IP                 = var.fmc_ip
    FMC_USERNAME           = var.fmc_username
    REG_ID                 = var.reg_id
    NAT_ID                 = var.nat_id
    POLICY_ID              = var.policy_id
    LICENSE_CAPS           = var.license_caps
    PERF_TIER              = var.perf_tier
    FORCE_STOP             = "false"
  }

  secret_environment_variables {
    key     = "FMCV_PASSWORD"
    secret  = var.fmc_password_secret_name
    version = "latest"
  }

  secret_environment_variables {
    key     = "FTDV_PASSWORD"
    secret  = var.ftd_password_secret_name
    version = "latest"
  }

  vpc_connector                 = var.vpc_connector_name
  vpc_connector_egress_settings = var.ftd_reg_via_public_ip ?  "ALL_TRAFFIC" : "PRIVATE_RANGES_ONLY"
  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.insert.id
  }
}

# Create Cloud Function for handling scale-in operations
resource "google_cloudfunctions_function" "scalein_action" {
  name                  = "${var.resource_name_prefix}-ftdv-scalein-action"
  runtime               = "python312"
  entry_point           = "scale_in"
  source_archive_bucket = google_storage_bucket.ftdv_bucket.id
  source_archive_object = google_storage_bucket_object.ftdv_cluster_scalein_action_object.name
  timeout               = 540
  max_instances         = 1
  ingress_settings      = "ALLOW_ALL"

  environment_variables = {
    FMC_IP              = var.fmc_ip
    FMC_USERNAME        = var.fmc_username
    CLS_GRP_NAME        = var.cluster_grp_name
  }

  secret_environment_variables {
    key     = "FMCV_PASSWORD"
    secret  = var.fmc_password_secret_name
    version = "latest"
  }

  vpc_connector                 = var.vpc_connector_name
  vpc_connector_egress_settings = var.ftd_reg_via_public_ip ?  "ALL_TRAFFIC" : "PRIVATE_RANGES_ONLY"
  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.delete.id
  }
}