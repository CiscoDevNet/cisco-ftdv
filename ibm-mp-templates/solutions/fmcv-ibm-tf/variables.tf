variable "TF_VERSION" {
  description = "Legacy compatibility metadata only. Select the Catalog Terraform runtime series 1.13 separately; version.tf enforces the actual executable."
  type        = string
  default     = "1.13"
  nullable    = false
  validation {
    condition     = var.TF_VERSION == "1.13" || can(regex("^1\\.13\\.[0-9]+$", var.TF_VERSION))
    error_message = "TF_VERSION must identify the 1.13 series or a 1.13 patch label; it does not select the executable."
  }
}

variable "ibmcloud_api_key" {
  description = "Optional explicit API-key override. Omit to use IBM provider environment/runtime credentials, including Schematics IAM. Never commit credentials."
  type        = string
  default     = null
  nullable    = true
  sensitive   = true
}

variable "region" {
  description = "IBM Cloud region containing the existing VPC and management subnet. The selected image and profile must support the subnet location."
  type        = string
  default     = "us-east"
  nullable    = false
  validation {
    condition     = contains(flatten([for release in values(local.fmcv_image_releases) : release.supported_regions]), var.region)
    error_message = "region must be listed by a configured image release."
  }
}

variable "resource_group_name" {
  description = "Name of the existing resource group for the FMCv VSI, management VNI, boot volume, and optional floating IP."
  type        = string
  nullable    = false
  validation {
    condition     = length(trimspace(var.resource_group_name)) > 0
    error_message = "resource_group_name must not be empty."
  }
}

variable "resource_name_prefix" {
  description = "Unique resource name prefix for this deployment in the target region and resource group. Terraform uses the supplied prefix before suffixes such as -vsi and -mgmt-vni."
  type        = string
  default     = null

  validation {
    condition     = var.resource_name_prefix == null ? true : length(var.resource_name_prefix) <= 35 && can(regex(local.resource_name_prefix_pattern, var.resource_name_prefix))
    error_message = "resource_name_prefix must contain 1–35 lowercase letters, digits or hyphens. Start with a letter and avoid consecutive or trailing hyphens."
  }

  validation {
    condition     = var.resource_name_prefix == null || var.prefix == null || var.resource_name_prefix == var.prefix
    error_message = "Set only resource_name_prefix or prefix, or provide the same value for both."
  }
}

variable "prefix" {
  description = "Deprecated alias for resource_name_prefix. Existing callers can continue to supply their original prefix. If both inputs are omitted, Terraform uses cisco-fmcv."
  type        = string
  default     = null

  validation {
    condition     = var.prefix == null ? true : length(var.prefix) <= 35 && can(regex(local.resource_name_prefix_pattern, var.prefix))
    error_message = "prefix must contain 1–35 lowercase letters, digits or hyphens. Start with a letter and avoid consecutive or trailing hyphens."
  }
}

variable "vpc_id" {
  description = "ID of the existing VPC. This module does not create or modify the VPC."
  type        = string
  nullable    = false
  validation {
    condition     = length(trimspace(var.vpc_id)) > 0
    error_message = "vpc_id must not be empty."
  }
}

variable "management_subnet_id" {
  description = "Existing subnet ID for IBM eth0, management."
  type        = string
  nullable    = false
  validation {
    condition     = length(trimspace(var.management_subnet_id)) > 0
    error_message = "management_subnet_id must not be empty."
  }
}

variable "management_security_group_id" {
  description = "Existing security group ID in the selected VPC for eth0 / management."
  type        = string
  nullable    = false
  validation {
    condition     = length(trimspace(var.management_security_group_id)) > 0
    error_message = "management_security_group_id must not be empty."
  }
}

variable "ssh_key_id" {
  description = "ID of one existing regional IBM VPC SSH-key registration. Provider keys receives a one-element list. Guest login/bootstrap behavior is image-specific and separate."
  type        = string
  nullable    = false
  validation {
    condition     = length(trimspace(var.ssh_key_id)) > 0
    error_message = "ssh_key_id must be one non-empty ID string."
  }
}

variable "instance_profile" {
  description = "Product-qualified profile from fmcv-images.json, available in the selected subnet zone and supporting at least one network attachment."
  type        = string
  default     = "bx3d-8x40"
  nullable    = false
  validation {
    condition     = contains(flatten([for release in values(local.fmcv_image_releases) : release.supported_profiles]), var.instance_profile)
    error_message = "instance_profile must be listed by a configured image release; selected-image and live-zone checks also apply."
  }
}

variable "enable_secure_boot" {
  description = "Requested mode must be supported by the selected image in fmcv-images.json and by the live IBM Cloud profile."
  type        = bool
  default     = false
  nullable    = false
}

variable "fmcv_image_version" {
  description = "Image label from fmcv-images.json. Null uses default_version. Review Catalog form choices/default separately; changes in JSON do not synchronize the UI."
  type        = string
  default     = null
  nullable    = true
  validation {
    condition     = contains(keys(local.fmcv_image_releases), var.fmcv_image_version == null ? local.fmcv_image_catalog.default_version : var.fmcv_image_version)
    error_message = "Image version must be null for the packaged default or a configured release label."
  }

}

variable "create_management_floating_ip" {
  description = "Create a public floating IP on the management VNI only. Keep false for private management; use an existing restricted management SG."
  type        = bool
  default     = false
  nullable    = false
}

variable "user_data" {
  description = "Optional raw FMCv Day-0 JSON object; do not base64-encode. Null/blank omits user_data. Image-supported fields such as AdminPassword and Hostname are passed through unchanged. Arrange an image-supported initial-access path when omitted. Sensitive values can remain in Terraform state."
  type        = string
  default     = null
  nullable    = true
  sensitive   = true
  validation {
    condition     = try(trimspace(var.user_data), "") == "" ? true : can(keys(jsondecode(var.user_data)))
    error_message = "When supplied, user_data must be a JSON object, not base64, a JSON string, an array or command text."
  }
}

variable "enable_metadata_service" {
  description = "Image compatibility setting: metadata must remain enabled for initial bootstrap."
  type        = bool
  default     = true
  nullable    = false
  validation {
    condition     = var.enable_metadata_service
    error_message = "enable_metadata_service must be true for these image bootstrap contracts."
  }
}

variable "metadata_service_protocol" {
  description = "Image compatibility setting for initial bootstrap. The configured images use HTTP metadata."
  type        = string
  default     = "http"
  nullable    = false
  validation {
    condition     = var.metadata_service_protocol == "http"
    error_message = "metadata_service_protocol must be http for these image bootstrap contracts."
  }
}

variable "tags" {
  description = "User tags applied to the VSI and optional floating IP."
  type        = list(string)
  default     = ["cisco", "fmcv", "network-security"]
  nullable    = false
  validation {
    condition     = alltrue([for tag in var.tags : length(trimspace(tag)) > 0])
    error_message = "tags must not contain empty values."
  }
}

