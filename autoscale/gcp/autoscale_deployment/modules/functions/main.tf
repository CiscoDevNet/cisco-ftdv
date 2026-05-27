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

variable "service_account_mail_id" {
  description = "Service account email used by the instances."
  validation {
    condition     = can(regex(".+@.+\\..+", var.service_account_mail_id))
    error_message = "Please provide a valid email address."
  }
}

variable "vpc_connector_name" {
  description = "Name for the VPC connector resource for cloud functions to access VPC resources."
  validation {
    condition     = can(regex("^[A-Za-z0-9-_]+$", var.vpc_connector_name)) && length(var.vpc_connector_name) <= 25
    error_message = "Please provide a valid VPC connector name."

  }
}

variable "inside_gw_name" {
  description = "Name of the inside gateway."
  validation {
    condition     = length(var.inside_gw_name) > 0
    error_message = "Inside gateway name cannot be empty."
  }
}

variable "outside_gw_name" {
  description = "Name of the outside gateway."
  validation {
    condition     = length(var.outside_gw_name) > 0
    error_message = "Outside gateway name cannot be empty."
  }
}

variable "inside_sec_zone" {
  description = "Security zone for inside traffic."
  validation {
    condition     = length(var.inside_sec_zone) > 0
    error_message = "Inside security zone cannot be empty."
  }
}

variable "outside_sec_zone" {
  description = "Security zone for outside traffic."
  validation {
    condition     = length(var.outside_sec_zone) > 0
    error_message = "Outside security zone cannot be empty."
  }
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
  description = "Device Group Name."
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
  description = "Whether FTDv should register to FMC using its public IP (also routes Cloud Function egress via the public/NAT path)."
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

variable "health_check_port" {
  description = "Port for health checks."
  validation {
    condition     = can(regex("^[0-9]+$", var.health_check_port))
    error_message = "Please provide a valid port number."
  }
}

locals {
  default_ftdv_password = "th1S_w!ll_Be_C#@nged"
}

resource "google_storage_bucket" "ftdv_bucket" {
  name          = "${var.resource_name_prefix}-ftdv-autoscale-bucket"
  location      = var.region
  storage_class = "STANDARD"

  force_destroy               = true
  uniform_bucket_level_access = true
}

data "archive_file" "ftdv_autoscale_scalein_action_zip" {
  type        = "zip"
  source_dir  = "${path.module}/scalein_functions"
  output_path = "${path.module}/scalein_functions/ftdv_scalein.zip"
}

data "archive_file" "ftdv_autoscale_scaleout_action_zip" {
  type        = "zip"
  source_dir  = "${path.module}/scaleout_functions"
  output_path = "${path.module}/scaleout_functions/ftdv_scaleout.zip"

}

resource "google_storage_bucket_object" "ftdv_autoscale_scalein_action_object" {
  name   = "ftdv_scalein.zip"
  bucket = google_storage_bucket.ftdv_bucket.id
  source = data.archive_file.ftdv_autoscale_scalein_action_zip.output_path
}

resource "google_storage_bucket_object" "ftdv_autoscale_scaleout_action_object" {
  name   = "ftdv_scaleout.zip"
  bucket = google_storage_bucket.ftdv_bucket.id
  source = data.archive_file.ftdv_autoscale_scaleout_action_zip.output_path
}

resource "google_pubsub_topic" "insert" {
  name = "${var.resource_name_prefix}-ftdv-pubsub-topic-insert"

}

resource "google_logging_project_sink" "insert_sink" {
  name                   = "${var.resource_name_prefix}-ftdv-insert-sink"
  destination            = "pubsub.googleapis.com/projects/${var.project_id}/topics/${google_pubsub_topic.insert.name}"
  filter                 = "(resource.type = \"gce_instance\" AND protoPayload.methodName = \"v1.compute.instances.insert\" AND protoPayload.resourceName:\"${var.resource_name_prefix}\" AND operation.last = true) OR (resource.type = \"cloud_function\" AND resource.labels.function_name = \"${var.resource_name_prefix}-ftdv-scaleout-action\" AND textPayload:\"Second Attempt\")"
  unique_writer_identity = false
  depends_on             = [google_pubsub_topic.insert]
}

resource "google_pubsub_topic_iam_binding" "insert" {
  topic = google_pubsub_topic.insert.id

  role = "roles/pubsub.publisher"

  members = [
    "serviceAccount:cloud-logs@system.gserviceaccount.com"
  ]
}

resource "google_pubsub_topic" "delete" {
  name = "${var.resource_name_prefix}-ftdv-pubsub-topic-delete"
}


resource "google_logging_project_sink" "delete_sink" {
  name                   = "${var.resource_name_prefix}-ftdv-delete-sink"
  destination            = "pubsub.googleapis.com/projects/${var.project_id}/topics/${google_pubsub_topic.delete.name}"
  filter                 = "resource.type = \"gce_instance\" AND protoPayload.methodName = \"v1.compute.instances.delete\" AND protoPayload.resourceName:\"${var.resource_name_prefix}\" AND operation.first=true"
  unique_writer_identity = false
  depends_on             = [google_pubsub_topic.delete]
}

resource "google_pubsub_topic_iam_binding" "delete" {
  topic = google_pubsub_topic.delete.id

  role = "roles/pubsub.publisher"

  members = [
    "serviceAccount:cloud-logs@system.gserviceaccount.com"
  ]

}


# PART 3: Create Cloud Functions
resource "google_cloudfunctions_function" "scaleout_action" {
  name                  = "${var.resource_name_prefix}-ftdv-scaleout-action"
  runtime               = "python312"
  entry_point           = "scale_out"
  source_archive_bucket = google_storage_bucket.ftdv_bucket.id
  source_archive_object = google_storage_bucket_object.ftdv_autoscale_scaleout_action_object.name
  timeout               = 540
  max_instances         = 1
  ingress_settings      = "ALLOW_ALL"

  environment_variables = {
    FMC_IP                 = var.fmc_ip
    FMC_USERNAME           = var.fmc_username
    REG_ID                 = var.reg_id
    NAT_ID                 = var.nat_id
    GRP_ID                 = var.grp_id
    POLICY_ID              = var.policy_id
    FTDV_PASSWORD          = local.default_ftdv_password
    FTD_REG_VIA_PUBLIC_IP  = var.ftd_reg_via_public_ip
    LICENSE_CAPS           = var.license_caps
    INSTANCE_PREFIX_IN_FMC = var.instance_prefix_in_fmc
    OUTSIDE_GW_NAME        = var.outside_gw_name
    INSIDE_GW_NAME         = var.inside_gw_name
    OUTSIDE_SEC_ZONE       = var.outside_sec_zone
    INSIDE_SEC_ZONE        = var.inside_sec_zone
    HEALTH_CHECK_PORT      = var.health_check_port
  }

  secret_environment_variables {
    key     = "FMC_PASSWORD"
    secret  = var.fmc_password_secret
    version = "latest"
  }

  secret_environment_variables {
    key     = "NEW_FTD_PASSWORD"
    secret  = var.new_ftd_password_secret
    version = "latest"
  }

  vpc_connector                 = var.vpc_connector_name
  vpc_connector_egress_settings = var.ftd_reg_via_public_ip ? "ALL_TRAFFIC" : "PRIVATE_RANGES_ONLY"
  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.insert.id
  }
}

resource "google_cloudfunctions_function" "scalein_action" {
  name                  = "${var.resource_name_prefix}-ftdv-scalein-action"
  runtime               = "python312"
  entry_point           = "scale_in"
  source_archive_bucket = google_storage_bucket.ftdv_bucket.id
  source_archive_object = google_storage_bucket_object.ftdv_autoscale_scalein_action_object.name
  timeout               = 540
  max_instances         = 1
  ingress_settings      = "ALLOW_ALL"

  environment_variables = {
    FMC_IP                 = var.fmc_ip
    FMC_USERNAME           = var.fmc_username
    INSTANCE_PREFIX_IN_FMC = var.instance_prefix_in_fmc
  }

  secret_environment_variables {
    key     = "FMC_PASSWORD"
    secret  = var.fmc_password_secret
    version = "latest"
  }

  vpc_connector                 = var.vpc_connector_name
  vpc_connector_egress_settings = var.ftd_reg_via_public_ip ? "ALL_TRAFFIC" : "PRIVATE_RANGES_ONLY"
  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.delete.id
  }
}

# Outputs
output "scale_out_function_name" {
  value = google_cloudfunctions_function.scaleout_action.name
}

output "scale_in_function_name" {
  value = google_cloudfunctions_function.scalein_action.name
}
