# Compatibility metadata for callers that supply TF_VERSION. Configure the
# Software version's runtime separately; version.tf enforces the actual binary.
# tflint-ignore: terraform_unused_declarations
variable "TF_VERSION" {
  description = "Publisher runtime metadata for this release. Configure the Software Terraform runtime to 1.13.4; version.tf enforces the actual Terraform version. This variable does not select the Terraform executable."
  type        = string
  default     = "1.13.4"

  validation {
    condition     = var.TF_VERSION == "1.13.4"
    error_message = "TF_VERSION is publisher-pinned to 1.13.4 for this release."
  }
}

variable "ibmcloud_api_key" {
  description = "Optional explicit IBM Cloud API-key override. When omitted, the IBM provider uses its environment or runtime authentication, including Schematics-supplied IAM credentials. Local callers can use IC_API_KEY or IBMCLOUD_API_KEY. The authenticated identity must have access to the selected account and resources; do not commit credentials."
  type        = string
  default     = null
  nullable    = true
  sensitive   = true
}

variable "region" {
  description = "IBM Cloud region containing the existing VPC and all three subnets. It must support the selected ASAv image version."
  type        = string
  default     = "us-east"

  validation {
    condition     = contains(flatten([for release in values(local.asav_image_releases) : release.supported_regions]), var.region)
    error_message = "region must be supported by an ASAv image version configured for this Terraform release."
  }
}

variable "resource_group_name" {
  description = "Name of the resource group for the ASAv VSI, VNIs, boot volume, and optional floating IP."
  type        = string

  validation {
    condition     = length(trimspace(var.resource_group_name)) > 0
    error_message = "resource_group_name must not be empty."
  }
}

variable "prefix" {
  description = "Complete customer-supplied resource-name prefix, unique for each deployment in the target region and resource group. Use 1-35 lowercase letters, numbers, or hyphens. Terraform uses this value unchanged before resource suffixes such as -vsi and -mgmt-vni; no random suffix is appended."
  type        = string
  default     = "cisco-asav"

  validation {
    condition = (
      length(var.prefix) >= 1 &&
      length(var.prefix) <= 35 &&
      can(regex("^[a-z][a-z0-9-]*$", var.prefix)) &&
      !strcontains(var.prefix, "--") &&
      !endswith(var.prefix, "-")
    )
    error_message = "prefix must be 1-35 lowercase letters, numbers, or hyphens; it must start with a letter, contain no consecutive hyphens, and not end with a hyphen. Supply a unique prefix for each deployment; no random suffix is added."
  }
}

variable "vpc_id" {
  description = "ID of the existing VPC in which ASAv is deployed. The template does not create or modify the VPC."
  type        = string

  validation {
    condition     = length(trimspace(var.vpc_id)) > 0
    error_message = "vpc_id must not be empty."
  }
}

variable "management_subnet_id" {
  description = "ID of the existing subnet for eth0 / ASAv Management0/0."
  type        = string

  validation {
    condition     = length(trimspace(var.management_subnet_id)) > 0
    error_message = "management_subnet_id must not be empty."
  }
}

variable "data_subnet_1_id" {
  description = "ID of the existing subnet for data-1: IBM eth1 / ASAv GigabitEthernet0/0. This interface is commonly used as inside/trusted, but its role is customer-defined."
  type        = string

  validation {
    condition     = length(trimspace(var.data_subnet_1_id)) > 0
    error_message = "data_subnet_1_id must not be empty."
  }
}

variable "data_subnet_2_id" {
  description = "ID of the existing subnet for data-2: IBM eth2 / ASAv GigabitEthernet0/1. This interface is commonly used as outside/untrusted, but its role is customer-defined."
  type        = string

  validation {
    condition     = length(trimspace(var.data_subnet_2_id)) > 0
    error_message = "data_subnet_2_id must not be empty."
  }
}

variable "management_security_group_id" {
  description = "ID of an existing least-privilege security group for the management VNI."
  type        = string

  validation {
    condition     = length(trimspace(var.management_security_group_id)) > 0
    error_message = "management_security_group_id must not be empty."
  }
}

variable "data_security_group_1_id" {
  description = "ID of an existing security group for the data-1 VNI."
  type        = string

  validation {
    condition     = length(trimspace(var.data_security_group_1_id)) > 0
    error_message = "data_security_group_1_id must not be empty."
  }
}

variable "data_security_group_2_id" {
  description = "ID of an existing security group for the data-2 VNI."
  type        = string

  validation {
    condition     = length(trimspace(var.data_security_group_2_id)) > 0
    error_message = "data_security_group_2_id must not be empty."
  }
}

variable "ssh_key_ids" {
  description = "IDs of existing VPC SSH keys in the deployment region, passed to IBM when creating the VSI. Guest user, SSH and key configuration are still required; see the README for the inline-key example and the separate image-managed injection path."
  type        = list(string)

  validation {
    condition = (
      length(var.ssh_key_ids) > 0 &&
      length(var.ssh_key_ids) == length(toset(var.ssh_key_ids)) &&
      alltrue([for ssh_key_id in var.ssh_key_ids : length(trimspace(ssh_key_id)) > 0])
    )
    error_message = "ssh_key_ids must contain at least one non-empty, unique SSH key ID."
  }
}

variable "instance_profile" {
  description = "Publisher-supported IBM Cloud VSI profile. The profile must support at least three network attachments and be available in the selected subnet zone. Fourth-generation cx4d profiles are region- and zone-limited; Terraform validates live profile metadata during planning."
  type        = string
  default     = "cx3d-2x5"

  validation {
    condition     = contains(flatten([for release in values(local.asav_image_releases) : release.supported_profiles]), var.instance_profile)
    error_message = "instance_profile must be supported by an image release in asav-images.json; the selected image must also support it."
  }
}

variable "enable_secure_boot" {
  description = "Enable Secure Boot for the ASAv instance. Defaults to true."
  type        = bool
  default     = true
}

variable "asav_image_version" {
  description = "ASAv image label from asav-images.json. Omit or set null to use that file's default_version; set an explicit label to pin a deployment. Catalog form choices/defaults must be reviewed separately during import."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      contains(keys(local.asav_image_releases), local.asav_image_catalog.default_version) &&
      contains(keys(local.asav_image_releases), var.asav_image_version == null ? local.asav_image_catalog.default_version : var.asav_image_version)
    )
    error_message = "asav_image_version must be null (use the packaged default) or one of: ${join(", ", sort(keys(local.asav_image_releases)))}. The file's default_version must also identify an entry in releases."
  }
}

variable "create_management_floating_ip" {
  description = "Create a floating IP on the management VNI. Keep false for private management; enable only with a restricted management security group."
  type        = bool
  default     = false
}

variable "user_data" {
  description = "Optional raw ASAv Day-0 configuration; do not base64-encode it. Configure the guest management interface, local user and SSH access for the chosen image. If omitted, arrange another initial configuration path such as the console. Sensitive values can remain in Terraform state even though this input is masked."
  type        = string
  default     = null
  nullable    = true
  sensitive   = true
}

variable "all_interface_allow_ip_spoofing" {
  description = "Advanced setting applied to management and both data VNIs. Defaults to true for the intended firewall forwarding configuration and requires VNI IP-spoofing management permission. Changing this setting requires separate compatibility and forwarding validation."
  type        = bool
  default     = true
}

variable "all_interface_protocol_state_filtering_mode" {
  description = "Advanced setting applied to management and both data VNIs. Defaults to disabled for the intended firewall configuration. Changing this setting requires separate compatibility and forwarding validation."
  type        = string
  default     = "disabled"

  validation {
    condition     = contains(["auto", "enabled", "disabled"], var.all_interface_protocol_state_filtering_mode)
    error_message = "all_interface_protocol_state_filtering_mode must be auto, enabled, or disabled."
  }
}

variable "enable_metadata_service" {
  description = "Publisher-managed ASAv compatibility setting. Must remain enabled for Day-0 delivery."
  type        = bool
  default     = true

  validation {
    condition     = var.enable_metadata_service
    error_message = "enable_metadata_service must be true for the configured ASAv images so raw Day 0 configuration can be consumed."
  }
}

variable "metadata_service_protocol" {
  description = "Publisher-managed ASAv compatibility setting. Must remain HTTP for Day-0 delivery with the configured images."
  type        = string
  default     = "http"

  validation {
    condition     = var.metadata_service_protocol == "http"
    error_message = "metadata_service_protocol must be http for the configured ASAv images."
  }
}

variable "tags" {
  description = "User tags applied to the VSI and optional floating IP."
  type        = list(string)
  default     = ["cisco", "asav", "network-security"]

  validation {
    condition     = alltrue([for tag in var.tags : length(trimspace(tag)) > 0])
    error_message = "tags cannot contain empty values."
  }
}
