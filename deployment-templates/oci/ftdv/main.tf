variable "tenancy_ocid" {
  default = "ocid1.tenancy.oc1..aaaaaaaa2fzl22x3tf2erwqpllaqcbk2xcx4rrap2b45gcclrl4x3agi32sq"
  description = "OCID of the tenancy to which your account belongs. To know more about where to find your tenancy OCID, refer to this link - https://docs.oracle.com/en-us/iaas/Content/General/Concepts/identifiers.htm#tenancy_ocid."
  validation {
        condition = (
          length(var.tenancy_ocid) > 14 &&
          can(regex("^ocid1.tenancy.", var.tenancy_ocid ))
        )
        error_message = "The tenancy OCID must start with <ocid1.tenancy....> and must be valid. Please check the value provided."
      }
}

variable "region" {
    default = "us-phoenix-1"
  description = "The unique identifier of the region in which you want the resources to be created. To get a list of all the regions and their unique identifiers in the OCI commercial realm refer to this link - https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm#About"
  validation {
        condition = (
          length(var.region) > 2 &&
          can(regex("^[0-9A-Za-z-]+$", var.region))
        )
        error_message = "Please provide a valid region."
      }
}

variable "compartment_id" {
    default = "ocid1.compartment.oc1..aaaaaaaaa6yubbqnwm32i3th564zm3ndenui7xv4rkcx4urcxb5pypoj52eq"
  description = "The OCID of the compartment in which to create the resources. The compartment OCID looks something like this - ocid1.compartment.oc1..<unique_ID>"
  validation {
        condition = (
          length(var.compartment_id) > 16 &&
          can(regex("^ocid1.compartment.", var.compartment_id ))
        )
        error_message = "The compartment OCID must start with <oocid1.compartment.....> and must be valid. Please check the value provided."
      }
}

variable "availability_domain" {
    default = "Tpeb:PHX-AD-1"
  description = "The availability domain to place instances. To get the specific names of your tenancy's availability domains, use the ListAvailabilityDomains (https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/AvailabilityDomain/ListAvailabilityDomains) operation, which is available in the IAM API. Example - Example - Tpeb:PHX-AD-1, Tpeb:PHX-AD-2"
  validation {
        condition = (
          can(regex("^[0-9A-Za-z:-]+$", var.availability_domain))
        )
        error_message = "Please provide a valid availability domain."
      }
}

variable "mgmt_subnet_ocid" {
    default = "ocid1.subnet.oc1.phx.aaaaaaaap3sdmd64v7bknhl7zqq6i6tqoardhrfh5xlzf2kz5it5smcagsfq"
  description = "OCID of the Management subnet that is to be used."
  validation {
        condition = (
          length(var.mgmt_subnet_ocid) > 13 &&
          can(regex("^ocid1.subnet.", var.mgmt_subnet_ocid ))
        )
        error_message = "The subnet OCID must start with <ocid1.subnet....> and must be valid. Please check the value provided."
      }
}

variable "mgmt_nsg_ocid" {
    default = "ocid1.networksecuritygroup.oc1.phx.aaaaaaaa4larsbybwy7mlt56nq2l7nygdvcup4g7x2bbgitcpkxjtc7ad5xq"
  description = "OCID of the Management subnet network security group that is to be used."
  validation {
        condition = (
          length(var.mgmt_nsg_ocid) > 27 &&
          can(regex("^ocid1.networksecuritygroup.", var.mgmt_nsg_ocid ))
        )
        error_message = "The NSG OCID must start with <ocid1.networksecuritygroup.....> and must be valid. Please check the value provided."
      }
}

variable "diag_subnet_ocid" {
    default = "ocid1.subnet.oc1.phx.aaaaaaaap3sdmd64v7bknhl7zqq6i6tqoardhrfh5xlzf2kz5it5smcagsfq"
  description = "OCID of the Diag subnet that is to be used."
  validation {
        condition = (
          length(var.diag_subnet_ocid) > 13 &&
          can(regex("^ocid1.subnet.", var.diag_subnet_ocid ))
        )
        error_message = "The subnet OCID must start with <ocid1.subnet....> and must be valid. Please check the value provided."
      }
}

variable "diag_nsg_ocid" {
    default = "ocid1.networksecuritygroup.oc1.phx.aaaaaaaa4larsbybwy7mlt56nq2l7nygdvcup4g7x2bbgitcpkxjtc7ad5xq"
  description = "OCID of the Diag subnet network security group that is to be used."
  validation {
        condition = (
          length(var.diag_nsg_ocid) > 27 &&
          can(regex("^ocid1.networksecuritygroup.", var.diag_nsg_ocid ))
        )
        error_message = "The NSG OCID must start with <ocid1.networksecuritygroup.....> and must be valid. Please check the value provided."
      }
}

variable "inside_subnet_ocid" {
    default = "ocid1.subnet.oc1.phx.aaaaaaaasnllvesxmh74lelxklcl5ejfqlsqgriwnc4ghd44pcftdrea4mea"
  description = "OCID of the Inside subnet that is to be used."
  validation {
        condition = (
          length(var.inside_subnet_ocid) > 13 &&
          can(regex("^ocid1.subnet.", var.inside_subnet_ocid ))
        )
        error_message = "The subnet OCID must start with <ocid1.subnet....> and must be valid. Please check the value provided."
      }
}

variable "inside_nsg_ocid" {
    default = "ocid1.networksecuritygroup.oc1.phx.aaaaaaaasb6hpq5vng2i6awnhz5ifqkzggw2ai2jsxdsoqoxyoviq3gvy3yq"
  description = "OCID of the Inside subnet network security group that is to be used."
  validation {
        condition = (
          length(var.inside_nsg_ocid) > 27 &&
          can(regex("^ocid1.networksecuritygroup.", var.inside_nsg_ocid ))
        )
        error_message = "The NSG OCID must start with <ocid1.networksecuritygroup.....> and must be valid. Please check the value provided."
      }
}

variable "outside_subnet_ocid" {
    default = "ocid1.subnet.oc1.phx.aaaaaaaazu5isd7d44e6lompesumud2jljncmuezzvthgxdbwlu2nd7tuovq"
  description = "OCID of the Outside subnet that is to be used."
  validation {
        condition = (
          length(var.outside_subnet_ocid) > 13 &&
          can(regex("^ocid1.subnet.", var.outside_subnet_ocid ))
        )
        error_message = "The subnet OCID must start with <ocid1.subnet....> and must be valid. Please check the value provided."
      }
}

variable "outside_nsg_ocid" {
    default = "ocid1.networksecuritygroup.oc1.phx.aaaaaaaacuciei2qextx6eucobc52ntx5bzofsz63m2xbbz3qe32ucb2vvzq"
  description = "OCID of the Outside subnet network security group that is to be used."
  validation {
        condition = (
          length(var.outside_nsg_ocid) > 27 &&
          can(regex("^ocid1.networksecuritygroup.", var.outside_nsg_ocid ))
        )
        error_message = "The NSG OCID must start with <ocid1.networksecuritygroup.....> and must be valid. Please check the value provided."
      }
}

variable "instance_shape" {
  description = "The shape of the instance to be created."
  type        = string
  default     = "VM.Standard2.4"

  validation {
    condition     = can(regex("^(VM|BM)\\.[A-Za-z0-9]+(\\.[A-Za-z0-9]+)*$", var.instance_shape))
    error_message = "Instance shape must start with 'VM.' or 'BM.' and follow OCI naming conventions."
  }
}

variable "custom_image_ocid" {
  default = "ocid1.image.oc1.phx.aaaaaaaasyeodapxohxbvnth5apeggyxbkzl7ifwrszlermged4gmzhphfza"
  description = "OCID of the custom image to be used to create instance configuration if the marketplace image is not to be used."
}

variable "network_type" {
    default = "PARAVIRTUALIZED"
    description = "Network type for the instance. Supported values are 'VFIO' and 'PARAVIRTUALIZED'. Default is 'PARAVIRTUALIZED'."
    validation {
        condition = (
          contains(["VFIO", "PARAVIRTUALIZED"], var.network_type)
        )
        error_message = "Please provide a valid network type. Supported values are 'VFIO' and 'PARAVIRTUALIZED'."
      }
}

variable "instance_name" {
    description = "Display name of the instance"
}

variable "user_data" {
    description = "Raw JSON string for instance initialization (will be base64 encoded automatically)"
    type = string
}

# Flex shape parameters
variable "ocpus" {
  type        = number
  default     = null
  description = "OCPUs for Flex shapes. Leave null for fixed shapes."
}

variable "memory_in_gbs" {
  type        = number
  default     = null
  description = "Memory (in GB) for Flex shapes. Leave null for fixed shapes."
}

provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  region           = var.region
}

locals {
  is_flex_shape = can(regex("\\.Flex$", var.instance_shape))
}

resource "oci_core_instance" "test_instance" {
    #Required
    availability_domain = var.availability_domain
    compartment_id = var.compartment_id
    shape = var.instance_shape

    # Only render shape_config when a Flex shape is chosen
    dynamic "shape_config" {
      for_each = local.is_flex_shape ? [1] : []
      content {
        ocpus                       = var.ocpus
        memory_in_gbs               = var.memory_in_gbs
      }
    }

    create_vnic_details {
        assign_public_ip = "true"
        display_name = "mgmt"
        nsg_ids = [var.mgmt_nsg_ocid]
        subnet_id = var.mgmt_subnet_ocid
    }

    display_name = var.instance_name
    metadata = {"user_data" : base64encode(var.user_data)}

    source_details {
        #Required
        source_id = var.custom_image_ocid
        source_type = "image"
    }

    launch_options {
        network_type = var.network_type
    }

    freeform_tags = {
      autostop    = "false"
      autodelete  = "false"
    }
}

resource "oci_core_vnic_attachment" "test_vnic_attachment_diag" {
    #Required
    create_vnic_details {
        #Optional
        assign_public_ip = "false"
        display_name = "diag"
        nsg_ids = [var.diag_nsg_ocid]
        skip_source_dest_check = "true"
        subnet_id = var.diag_subnet_ocid
    }
    instance_id = oci_core_instance.test_instance.id
    #Optional
    display_name = "diag"
}

resource "oci_core_vnic_attachment" "test_vnic_attachment_in" {
    #Required
    create_vnic_details {
        #Optional
        assign_public_ip = "false"
        display_name = "inside"
        nsg_ids = [var.inside_nsg_ocid]
        skip_source_dest_check = "true"
        subnet_id = var.inside_subnet_ocid
    }
    instance_id = oci_core_instance.test_instance.id
    #Optional
    display_name = "inside"
    depends_on = [oci_core_vnic_attachment.test_vnic_attachment_diag]
}

resource "oci_core_vnic_attachment" "test_vnic_attachment_out" {
    #Required
    create_vnic_details {
        #Optional
        assign_public_ip = "false"
        display_name = "outside"
        nsg_ids = [var.outside_nsg_ocid]
        skip_source_dest_check = "true"
        subnet_id = var.outside_subnet_ocid
    }
    instance_id = oci_core_instance.test_instance.id
    #Optional
    display_name = "outside"
    depends_on = [oci_core_vnic_attachment.test_vnic_attachment_diag, oci_core_vnic_attachment.test_vnic_attachment_in]
}

data "oci_core_vnic_attachments" "test_vnic_attachments" {
    #Required
    compartment_id = var.compartment_id
    #Optional
    instance_id = oci_core_instance.test_instance.id
}

data "oci_core_vnic" "test_vnic_mgmt" {
    vnic_id = local.mgmt_vnic_id[0]
}

data "oci_core_vnic" "test_vnic_diag" {
    vnic_id = oci_core_vnic_attachment.test_vnic_attachment_diag.vnic_id
}

data "oci_core_vnic" "test_vnic_in" {
    vnic_id = oci_core_vnic_attachment.test_vnic_attachment_in.vnic_id
}

data "oci_core_vnic" "test_vnic_out" {
    vnic_id = oci_core_vnic_attachment.test_vnic_attachment_out.vnic_id
}

locals{
    mgmt_vnic_id = [ for x, y in data.oci_core_vnic_attachments.test_vnic_attachments.vnic_attachments : y.vnic_id if y.subnet_id == var.mgmt_subnet_ocid ]
}

resource "oci_core_ipv6" "test_ipv6_mgmt" {
    #Required
    vnic_id = local.mgmt_vnic_id[0] 
}
resource "oci_core_ipv6" "test_ipv6_diag" {
    #Required
    vnic_id = oci_core_vnic_attachment.test_vnic_attachment_diag.vnic_id
}
resource "oci_core_ipv6" "test_ipv6_in" {
    #Required
    vnic_id = oci_core_vnic_attachment.test_vnic_attachment_in.vnic_id
}
resource "oci_core_ipv6" "test_ipv6_out" {
    #Required
    vnic_id = oci_core_vnic_attachment.test_vnic_attachment_out.vnic_id
}

# Outputs
output "instance_id" {
  description = "OCID of the FTD instance"
  value       = oci_core_instance.test_instance.id
}

output "instance_name" {
  description = "Name of the FTD instance"
  value       = var.instance_name
}

output "public_ipv4_address" {
  description = "Public IPv4 address of the FTD (management interface)"
  value       = data.oci_core_vnic.test_vnic_mgmt.public_ip_address
}

output "private_ipv4_address_mgmt" {
  description = "Private IPv4 address of the management interface"
  value       = data.oci_core_vnic.test_vnic_mgmt.private_ip_address
}

output "private_ipv4_address_diag" {
  description = "Private IPv4 address of the diagnostic interface"
  value       = data.oci_core_vnic.test_vnic_diag.private_ip_address
}

output "private_ipv4_address_inside" {
  description = "Private IPv4 address of the inside interface"
  value       = data.oci_core_vnic.test_vnic_in.private_ip_address
}

output "private_ipv4_address_outside" {
  description = "Private IPv4 address of the outside interface"
  value       = data.oci_core_vnic.test_vnic_out.private_ip_address
}

output "ipv6_address_mgmt" {
  description = "IPv6 address of the management interface"
  value       = oci_core_ipv6.test_ipv6_mgmt.ip_address
}

output "ipv6_address_diag" {
  description = "IPv6 address of the diagnostic interface"
  value       = oci_core_ipv6.test_ipv6_diag.ip_address
}

output "ipv6_address_inside" {
  description = "IPv6 address of the inside interface"
  value       = oci_core_ipv6.test_ipv6_in.ip_address
}

output "ipv6_address_outside" {
  description = "IPv6 address of the outside interface"
  value       = oci_core_ipv6.test_ipv6_out.ip_address
}

output "state" {
    description = "Current state of the manager instance"
    value       = oci_core_instance.test_instance.state
}
