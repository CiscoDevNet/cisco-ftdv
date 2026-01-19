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
    default = "ocid1.compartment.oc1..aaaaaaaaq3r56dkkwmuudxtz6gfpsdbhbbjmtoi6xc5skoaxxp274udrd4qq"
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
  description = "OCID of the Management subnet network security group that is to be used."
  validation {
        condition = (
          length(var.mgmt_nsg_ocid) > 27 &&
          can(regex("^ocid1.networksecuritygroup.", var.mgmt_nsg_ocid ))
        )
        error_message = "The NSG OCID must start with <ocid1.networksecuritygroup.....> and must be valid. Please check the value provided."
      }
}
variable "instance_shape" {
    default = "VM.Standard2.4"
  description = "The shape of the instance to be created. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance. Supported shapes for FTDv are - 'VM.Standard2.4' and 'VM.Standard2.8'"
  validation {
        condition = (
          contains(["VM.Standard2.4", "VM.Standard2.8"], var.instance_shape)
        )
        error_message = "Please provide a valid instance shape."
      }
}
variable "custom_image_ocid" {
  description = "OCID of the custom image to be used to create instance configuration if the marketplace image is not to be used."
}

variable "instance_name" {
    description = " Display name of the instance"
}

variable "user_data" {
    description = "Raw JSON string for instance initialization (will be base64 encoded automatically)"
    type = string
}

provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  region           = var.region
}

resource "oci_core_instance" "test_instance" {
    #Required
    availability_domain = var.availability_domain
    compartment_id = var.compartment_id
    shape = var.instance_shape

    create_vnic_details {
        #Optional
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
    freeform_tags = {
      autostop    = "false"
      autodelete  = "false"
    }
}

data "oci_core_vnic_attachments" "test_vnic_attachments" {
    #Required
    compartment_id = var.compartment_id
    #Optional
    instance_id = oci_core_instance.test_instance.id
}

locals{
    mgmt_vnic_id = [ for x, y in data.oci_core_vnic_attachments.test_vnic_attachments.vnic_attachments : y.vnic_id if y.subnet_id == var.mgmt_subnet_ocid ]
}

resource "oci_core_ipv6" "test_ipv6_mgmt" {
    #Required
    vnic_id = local.mgmt_vnic_id[0] 
}

# Get VNIC details to access IP addresses
data "oci_core_vnic" "instance_vnic" {
    vnic_id = local.mgmt_vnic_id[0]
}

# Outputs for instance details
output "instance_id" {
    description = "OCID of the FMC instance"
    value       = oci_core_instance.test_instance.id
}

output "instance_name" {
    description = "Name of the manager instance"
    value       = var.instance_name
}

output "public_ipv4_address" {
    description = "Public IPv4 address of the manager instance"
    value       = data.oci_core_vnic.instance_vnic.public_ip_address
}

output "private_ipv4_address" {
    description = "Private IPv4 address of the manager instance"
    value       = data.oci_core_vnic.instance_vnic.private_ip_address
}

output "public_ipv6_address" {
    description = "IPv6 address of the manager instance"
    value       = oci_core_ipv6.test_ipv6_mgmt.ip_address
}

output "state" {
    description = "Current state of the manager instance"
    value       = oci_core_instance.test_instance.state
}
