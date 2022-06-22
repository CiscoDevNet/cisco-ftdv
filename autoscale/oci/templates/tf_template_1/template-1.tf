variable "tenancy_ocid" {
  description = "OCID of the tenancy to which your account belongs. To know more about where to find your tenancy OCID, refer to this link - https://docs.oracle.com/en-us/iaas/Content/General/Concepts/identifiers.htm#tenancy_ocid."
  validation {
        condition = (
          length(var.tenancy_ocid) > 14 &&
          can(regex("^ocid1.tenancy.", var.tenancy_ocid ))
        )
        error_message = "The tenancy OCID must start with <ocid1.tenancy....> and must be valid. Please check the value provided."
      }
}

variable "compartment_id" {
  description = "The OCID of the compartment in which to create the resources. The compartment OCID looks something like this - ocid1.compartment.oc1..<unique_ID>"
  validation {
        condition = (
          length(var.compartment_id) > 16 &&
          can(regex("^ocid1.compartment.", var.compartment_id ))
        )
        error_message = "The compartment OCID must start with <oocid1.compartment.....> and must be valid. Please check the value provided."
      }
}
variable "region" {
  description = "The unique identifier of the region in which you want the resources to be created. To get a list of all the regions and their unique identifiers in the OCI commercial realm refer to this link - https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm#About"
  validation {
        condition = (
          length(var.region) > 2 &&
          can(regex("^[0-9A-Za-z-]+$", var.region))
        )
        error_message = "Please provide a valid region."
      }
}
variable "lb_size" {
  description = "A template that determines the total pre-provisioned bandwidth (ingress plus egress) of the external and internal load balancer. The supported values are - 100Mbps, 10Mbps, 10Mbps-Micro, 400Mbps, 8000Mbps"
  validation {
        condition = (
          contains(["100Mbps", "10Mbps", "10Mbps-Micro", "400Mbps", "8000Mbps"], var.lb_size)
        )
        error_message = "Please provide a valid size."
      }
}
variable "availability_domain" {
  description = "The availability domain to place instances. To get the specific names of your tenancy's availability domains, use the ListAvailabilityDomains (https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/AvailabilityDomain/ListAvailabilityDomains) operation, which is available in the IAM API. Example - Example - Tpeb:PHX-AD-1, Tpeb:PHX-AD-2"
}

variable "min_and_max_instance_count"{
    type = string
    description = "The minimum and maximum number of instances that you would want to retain in the instance pool. Please give the minimum and maximum instance count values as comma separated input. For ex, '1,5' - where 1 is the minimum instance count and 5 is the maximum instance count."

    validation{
      condition = (
          can(regex("^[0-9]+$", split(",", var.min_and_max_instance_count)[0])) &&
          can(regex("^[0-9]+$", split(",", var.min_and_max_instance_count)[1])) &&
          split(",", var.min_and_max_instance_count)[0] < split(",", var.min_and_max_instance_count)[1] &&
          split(",", var.min_and_max_instance_count)[1] < 26
          )
      error_message = "The min_and_max_instance_count is incorrect, Please verify again. Minimum instance count value must be lesser than maximum instance count value. Maximum instance count can not exceed 25 (FMCv Limit)."
    }
}

variable "autoscale_group_prefix" {
  description = "The prefix to be used to name all the resources that are created using the template. For example, if the resource prefix is given as 'autoscale', all the resources are named as follows - autoscale_resource1, autoscale_resource2 etc. Note : Please make sure not give a resource prefic that starts with 'oci_' as these are reserved for services within the cloud and will throw an error."
  validation {
        condition = (
          can(regex("^[a-z][a-z0-9_]*[a-z0-9]$", var.autoscale_group_prefix)) &&
          substr(var.autoscale_group_prefix,0,4) != "oci" &&
          substr(var.autoscale_group_prefix,0,4) != "orcl"
        )
        error_message = "Please provide a valid resource group prefix without any special characters except underscore."
      }
}

locals{
  day_0 = <<EOT
{
	"AdminPassword": "FtDv_AuT0Scale",
	"FirewallMode": "routed",
	"IPv4Mode": "dhcp",
	"IPv6Mode": "disabled",
	"ManageLocally": "No"
}
EOT

  min_instance_count = split(",", var.min_and_max_instance_count)[0]
  max_instance_count = split(",", var.min_and_max_instance_count)[1]
  availability_domains = tolist("${split(",", var.availability_domain)}")
  instance_pool_id = "${length(local.availability_domains) == 1 ? "${oci_core_instance_pool.test_instance_pool_1[0].id}" : "${length(local.availability_domains) == 2 ? "${oci_core_instance_pool.test_instance_pool_2[0].id}" : "${oci_core_instance_pool.test_instance_pool_3[0].id}"}"}"
}

variable "ftdv_configuration_json_url" {
  description = "The URL of the configuration file uploaded to the object storage to be used to configure the FTDv. Example - https://objectstorage.us-phoenix-1.oraclecloud.com/p/<.....>/oci-ftdv-configuration.json"
  validation {
        condition = (
          can(regex("^[0-9A-Za-z-/.:_]+$", var.ftdv_configuration_json_url))
        )
        error_message = "Please provide a valid URL."
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

variable "diag_subnet_ocid" {
  description = "OCID of the Diagnosis subnet that is to be used."
  validation {
        condition = (
          length(var.diag_subnet_ocid) > 13 &&
          can(regex("^ocid1.subnet.", var.diag_subnet_ocid ))
        )
        error_message = "The subnet OCID must start with <ocid1.subnet....> and must be valid. Please check the value provided."
      }

}

variable "diag_nsg_ocid" {
  description = "OCID of the Diagnosis subnet network security group that is to be used."
  validation {
        condition = (
          length(var.diag_nsg_ocid) > 27 &&
          can(regex("^ocid1.networksecuritygroup.", var.diag_nsg_ocid ))
        )
        error_message = "The NSG OCID must start with <ocid1.networksecuritygroup.....> and must be valid. Please check the value provided."
      }
}

variable "inside_subnet_ocid" {
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
  description = "OCID of the Outside subnet network security group that is to be used."
  validation {
        condition = (
          length(var.outside_nsg_ocid) > 27 &&
          can(regex("^ocid1.networksecuritygroup.", var.outside_nsg_ocid ))
        )
        error_message = "The NSG OCID must start with <ocid1.networksecuritygroup.....> and must be valid. Please check the value provided."
      }
}

variable "elb_listener_port" {
  description = "List of comma separated communication ports for the external load balancer listener. Example - 80,8000."

}

variable "ilb_listener_port" {
  description = "List of comma separated communication ports for the internal load balancer listener. Example - 80,8000."
}

variable "health_check_port" {
  description = "The backend server port of external load balancer against which to run the health check."
  validation {
        condition = (
          can(regex("^[0-9]+$", var.health_check_port)) &&
          var.health_check_port > 0 &&
          var.health_check_port < 65536
        )
        error_message = "Please provide a valid port number between 1 and 65535."
      }
}

variable "instance_shape" {
  description = "The shape of the instance to be created. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance. Supported shapes for FTDv are - 'VM.Standard2.4' and 'VM.Standard2.8'"
  validation {
        condition = (
          contains(["VM.Standard2.4", "VM.Standard2.8"], var.instance_shape)
        )
        error_message = "Please provide a valid instance shape."
      }
}
variable "lb_bs_policy" {
  description = "The load balancer policy to be used for the internal and external load balancer backend set. To know more about how load balancer policies work, refer to this link - https://docs.oracle.com/en-us/iaas/Content/Balance/Reference/lbpolicies.htm . Supported values are - 'ROUND_ROBIN', 'LEAST_CONNECTIONS', 'IP_HASH'"
  validation {
        condition = (
          contains(["ROUND_ROBIN", "LEAST_CONNECTIONS", "IP_HASH"], var.lb_bs_policy)
        )
        error_message = "Please provide a valid policy."
      }
}

variable "ftdv_license_type" {
  default = "BYOL"
  type = string
  description = "Type of FTDv license either BYOL or PAYG. Currently BYOL only supported."
}

variable "ftdv_password" {
  description = "The password in the encrypted form, for the admin account to be used to SSH into the FTDv for configuration. Please use configuration guide for the instructions or see the following link https://docs.oracle.com/en/database/other-databases/essbase/19.3/essad/create-vault-and-secrets.html "
  validation {
        condition = (
          length(var.ftdv_password) > 6
        )
        error_message = "Please enter a valid password of length > 6."
      }
}

variable "cryptographic_endpoint" {
  type = string
  description = "Cryptographic endpoint URL will be used for decrypting password. It can be found in the Vault."
  validation {
        condition = (
          can(regex("^((https?:[/][/])?(\\w+[.-])+com)", var.cryptographic_endpoint ))
        )
        error_message = "Cryptographic_endpoint is not a valid URL, Please check the value provided."
      }
}

variable "master_encryption_key_id" {
  type = string
  description = "The OCID of key with which the password was encrypted. It can be found in the Vault."
  validation {
        condition = (
          length(var.master_encryption_key_id) > 10 &&
          can(regex("^ocid1.key.", var.master_encryption_key_id ))
        )
        error_message = "The Encryption Key OCID must start with <ocid1.key....> and must be valid. Please check the value provided."
      }
}

variable "fmc_ip" {
  type = string
  description = "IP Address of FMCv"
  validation {
        condition = (
          can(regex("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", var.fmc_ip ))
        )
        error_message = "FMCv Ip address is incorrect, Please verify again."
      }
}

variable "fmc_username" {
  type = string
  description = "Username of the FMCv, which will control this FTDv device"
}

variable "fmc_password" {
  type = string
  description = "Password of FMCv in encrypted form. Please use configuration guide for the instructions or see the following link https://docs.oracle.com/en/database/other-databases/essbase/19.3/essad/create-vault-and-secrets.html"
  validation {
        condition = (
          length(var.fmc_password) > 6
        )
        error_message = "Please enter a valid password of length > 6."
      }
}

variable "fmc_device_group_name" {
  type = string
  description = "Device group name in FMCv to which this FTDv will be part of"
}

variable "image_name" {
  default = "Cisco Firepower NGFW virtual firewall (NGFWv)"
  description = "The name of the marketplace image to be used for creating the instance configuration."
}

variable "image_version" {
  type = string
  default = "7.0.0-94"
  description = "The Version of the FTDv image available in OCI Marketplace to be used. Currently following versions are available (i) 7.0.0-94   (ii) 6.7.0-65"
  validation {
        condition = (
          contains(["7.0.0-94", "6.7.0-65", ""], var.image_version)
        )
        error_message = "Please provide a available image version."
      }
}

variable "custom_image_ocid" {
  default = ""
  description = "OCID of the custom image to be used to create instance configuration if the marketplace image is not to be used."
}

variable "enable_memory_based_scaling" {
  type = string
  default = "true"
  description = "Publish FTDv Memory usage from the FMCv. By enabling this flag Scaling can happen based on Memory utilization as well."
}

variable "fmc_metrics_username" {
  type = string
  default = ""
  description = "Username of the FMCv, which will be used for publishing the memory usage."
}

variable "fmc_metrics_password" {
  type = string
  default = ""
  description = "Password of FMCv in encrypted form. Please use configuration guide for the instructions or see the following link https://docs.oracle.com/en/database/other-databases/essbase/19.3/essad/create-vault-and-secrets.html"
}

provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  region           = var.region
}

###########   Listing ID     ################
data "oci_marketplace_listings" "test_listings" {
  count = var.custom_image_ocid == "" ? 1 : 0
  name = [var.image_name]
}

data "oci_marketplace_listing" "test_listing" {
  count = var.custom_image_ocid == "" ? 1 : 0
  listing_id = data.oci_marketplace_listings.test_listings[count.index].listings[0].id
}

#################   Image ID    ################################
data "oci_marketplace_listing_package" "test_listing_package" {
  count = var.custom_image_ocid == "" ? 1 : 0
  listing_id      = data.oci_marketplace_listing.test_listing[count.index].id
  package_version = var.image_version
}

data "oci_core_app_catalog_listing_resource_version" "test_catalog_listing" {
  count = var.custom_image_ocid == "" ? 1 : 0
  listing_id       = data.oci_marketplace_listing_package.test_listing_package[count.index].app_catalog_listing_id
  resource_version = data.oci_marketplace_listing_package.test_listing_package[count.index].app_catalog_listing_resource_version
}

#################  marketplace agreements  ####################
resource "oci_marketplace_accepted_agreement" "test_accepted_agreement" {
  count = var.custom_image_ocid == "" ? 1 : 0
  agreement_id    = oci_marketplace_listing_package_agreement.test_listing_package_agreement[count.index].agreement_id
  compartment_id  = var.compartment_id
  listing_id      = data.oci_marketplace_listing.test_listing[count.index].id
  package_version = var.image_version
  signature       = oci_marketplace_listing_package_agreement.test_listing_package_agreement[count.index].signature
}

resource "oci_marketplace_listing_package_agreement" "test_listing_package_agreement" {
  count = var.custom_image_ocid == "" ? 1 : 0
  agreement_id    = data.oci_marketplace_listing_package_agreements.test_listing_package_agreements[count.index].agreements[0].id
  listing_id      = data.oci_marketplace_listing.test_listing[count.index].id
  package_version = var.image_version
}

data "oci_marketplace_listing_package_agreements" "test_listing_package_agreements" {
  count = var.custom_image_ocid == "" ? 1 : 0
  listing_id      = data.oci_marketplace_listing.test_listing[count.index].id
  package_version = var.image_version
}
resource "oci_load_balancer_load_balancer" "test_load_balancer_elb" {
    #Required
    compartment_id = var.compartment_id
    display_name = "${var.autoscale_group_prefix}_external_load_balancer"
    shape = var.lb_size
    subnet_ids = [var.outside_subnet_ocid]

    #Optional
    ip_mode = "IPV4"
    is_private = "false"

}
resource "oci_load_balancer_load_balancer" "test_load_balancer_ilb" {
    #Required
    compartment_id = var.compartment_id
    display_name = "${var.autoscale_group_prefix}_internal_load_balancer"
    shape = var.lb_size
    subnet_ids = [var.inside_subnet_ocid]

    #Optional
    ip_mode = "IPV4"
    is_private = "true"
}
resource "oci_load_balancer_backend_set" "test_backend_set_elb" {
    #Required
    health_checker {
        #Required
        protocol = "TCP"
        port = var.health_check_port
    }
    load_balancer_id = oci_load_balancer_load_balancer.test_load_balancer_elb.id
    name = "${var.autoscale_group_prefix}_elb_bs"
    policy = "${var.lb_bs_policy}"
}
resource "oci_load_balancer_backend_set" "test_backend_set_ilb" {
    #Required
    health_checker {
        #Required
        protocol = "TCP"
        port = var.health_check_port
    }
    load_balancer_id = oci_load_balancer_load_balancer.test_load_balancer_ilb.id
    name = "${var.autoscale_group_prefix}_ilb_bs"
    policy = "${var.lb_bs_policy}"
}
resource "oci_load_balancer_listener" "test_listener_elb" {
    #Required
    default_backend_set_name = oci_load_balancer_backend_set.test_backend_set_elb.name
    load_balancer_id = oci_load_balancer_load_balancer.test_load_balancer_elb.id
    name = "${var.autoscale_group_prefix}_elb_listener_${each.value}"
    port = each.value
    protocol = "TCP"
    for_each = toset("${split(",", var.elb_listener_port)}")
}
resource "oci_load_balancer_listener" "test_listener_ilb" {
    #Required
    default_backend_set_name = oci_load_balancer_backend_set.test_backend_set_ilb.name
    load_balancer_id = oci_load_balancer_load_balancer.test_load_balancer_ilb.id
    name = "${var.autoscale_group_prefix}_ilb_listener_${each.value}"
    port = each.value
    protocol = "TCP"
    for_each = toset("${split(",", var.ilb_listener_port)}")
}
resource "oci_core_instance_configuration" "test_instance_configuration" {
    compartment_id = var.compartment_id
    display_name = "${var.autoscale_group_prefix}_instance_configuration"
    instance_details {
        instance_type = "compute"
        launch_details {
            compartment_id = var.compartment_id
            create_vnic_details {
                assign_public_ip = "true"
                display_name = "management"
                nsg_ids = [var.mgmt_nsg_ocid]
                private_ip = "true"
                skip_source_dest_check = "true"
                subnet_id = var.mgmt_subnet_ocid
            }
            display_name = "${var.autoscale_group_prefix}_instance_configuration"
            launch_mode = "PARAVIRTUALIZED"
            metadata = {"user_data" : base64encode("${local.day_0}")}
            shape = "${var.instance_shape}"
            source_details {
                source_type = "image"
                image_id = var.custom_image_ocid == ""? data.oci_core_app_catalog_listing_resource_version.test_catalog_listing[0].listing_resource_id : var.custom_image_ocid
            }
        }
        secondary_vnics {
          #Optional
          create_vnic_details {
              #Optional
              assign_public_ip = "false"
              display_name = "diag"
              nsg_ids = [var.diag_nsg_ocid]
              private_ip = "true"
              skip_source_dest_check = "true"
              subnet_id = var.diag_subnet_ocid
                }
            display_name = "diag"
            }
        }
    source = "NONE"
}

resource "oci_core_instance_pool" "test_instance_pool_1" {
    count = "${length(local.availability_domains) == 1 ? 1 : 0}"
    #Required
    compartment_id = var.compartment_id
    instance_configuration_id = oci_core_instance_configuration.test_instance_configuration.id
    placement_configurations {
        #Required
        availability_domain = local.availability_domains[0]
        primary_subnet_id = var.mgmt_subnet_ocid
        secondary_vnic_subnets {
            #Required
            subnet_id = var.diag_subnet_ocid
            display_name = "diag"
            }
    }
    size ="0"
    display_name = "${var.autoscale_group_prefix}_instance_pool"
}
resource "oci_core_instance_pool" "test_instance_pool_2" {
    count = "${length(local.availability_domains) == 2 ? 1 : 0}"
    #Required
    compartment_id = var.compartment_id
    instance_configuration_id = oci_core_instance_configuration.test_instance_configuration.id
    placement_configurations {
        #Required
        availability_domain = local.availability_domains[0]
        primary_subnet_id = var.mgmt_subnet_ocid
        secondary_vnic_subnets {
            #Required
            subnet_id = var.diag_subnet_ocid
            display_name = "diag"
            }
    }
    placement_configurations {
        #Required
        availability_domain = local.availability_domains[1]
        primary_subnet_id = var.mgmt_subnet_ocid
        secondary_vnic_subnets {
            #Required
            subnet_id = var.diag_subnet_ocid
            display_name = "diag"
            }
    }
    size ="0"
    display_name = "${var.autoscale_group_prefix}_instance_pool"
}
resource "oci_core_instance_pool" "test_instance_pool_3" {
    count = "${length(local.availability_domains) == 3 ? 1 : 0}"
    #Required
    compartment_id = var.compartment_id
    instance_configuration_id = oci_core_instance_configuration.test_instance_configuration.id
    placement_configurations {
        #Required
        availability_domain = local.availability_domains[0]
        primary_subnet_id = var.mgmt_subnet_ocid
        secondary_vnic_subnets {
            #Required
            subnet_id = var.diag_subnet_ocid
            display_name = "diag"
            }
    }
    placement_configurations {
        #Required
        availability_domain = local.availability_domains[1]
        primary_subnet_id = var.mgmt_subnet_ocid
        secondary_vnic_subnets {
            #Required
            subnet_id = var.diag_subnet_ocid
            display_name = "diag"
            }
    }
    placement_configurations {
        #Required
        availability_domain = local.availability_domains[2]
        primary_subnet_id = var.mgmt_subnet_ocid
        secondary_vnic_subnets {
            #Required
            subnet_id = var.diag_subnet_ocid
            display_name = "diag"
            }
    }
    size ="0"
    display_name = "${var.autoscale_group_prefix}_instance_pool"
}

resource "oci_ons_notification_topic" "test_notification_topic_ftdv_configure" {
    #Required
    compartment_id = var.compartment_id
    name = "${var.autoscale_group_prefix}_ftdv_configure"
}
resource "oci_ons_notification_topic" "test_notification_topic_ftdv_post_launch" {
    #Required
    compartment_id = var.compartment_id
    name = "${var.autoscale_group_prefix}_ftdv_post_launch"
}
locals{
  ftdv_configure_topic_id = oci_ons_notification_topic.test_notification_topic_ftdv_configure.id
  ftdv_post_launch_topic_id = oci_ons_notification_topic.test_notification_topic_ftdv_post_launch.id
}

resource "oci_functions_application" "test_application" {
    #Required
    compartment_id = var.compartment_id
    display_name = "${var.autoscale_group_prefix}_application"
    subnet_ids = [var.mgmt_subnet_ocid]

    #Optional
    config = {
      "elb_id": "${oci_load_balancer_load_balancer.test_load_balancer_elb.id}",
      "elb_backend_set_name": "${oci_load_balancer_backend_set.test_backend_set_elb.name}",
      "elb_listener_port_no": "${var.elb_listener_port}",
      "compartment_id": "${var.compartment_id}",
      "ilb_id": "${oci_load_balancer_load_balancer.test_load_balancer_ilb.id}",
      "ilb_listener_port_no": "${var.ilb_listener_port}",
      "ilb_backend_set_name": "${oci_load_balancer_backend_set.test_backend_set_ilb.name}",
      "instance_pool_id": local.instance_pool_id,
      "region": "${var.region}",
      "metric_namespace_name": "${var.autoscale_group_prefix}_metric_namespace",
      "autoscale_group_prefix": "${var.autoscale_group_prefix}",
      "resource_group_name" : "${var.autoscale_group_prefix}_resource_group",
      "cpu_metric_name": "${var.autoscale_group_prefix}_cpu_usage",
      "healthcheck_metric_name": "${var.autoscale_group_prefix}_health_check",
      "ftdv_username": "admin",
      "cryptographic_endpoint": "${var.cryptographic_endpoint}",
      "master_key_id": "${var.master_encryption_key_id}",
      "ftdv_encrypted_password": "${var.ftdv_password}",
      "min_instance_count": "${local.min_instance_count}",
      "max_instance_count": "${local.max_instance_count}",
      "inside_subnet_id": "${var.inside_subnet_ocid }",
      "inside_nsg_id": "${var.inside_nsg_ocid}",
      "outside_subnet_id": "${var.outside_subnet_ocid}",
      "outside_nsg_id": "${var.outside_nsg_ocid}",
      "ftdv_configuration_json_url": "${var.ftdv_configuration_json_url}",
      "configure_ftdv_topic_id": "${local.ftdv_configure_topic_id}",
      "post_launch_actions_topic_id":"${local.ftdv_post_launch_topic_id}",
      "fmc_ip": "${var.fmc_ip}",
      "fmc_username": "${var.fmc_username}",
      "fmc_encrypted_password": "${var.fmc_password}",
      "fmc_device_group_name": "${var.fmc_device_group_name}",
      "ftdv_license_type": "BYOL",
      "use_public_ip_for_ssh": "true",
      "use_ftdv_public_ip_to_connect_fmc": "true",
      "publish_memory_metrics" : "${var.enable_memory_based_scaling}",
      "fmc_metrics_username" : "${var.fmc_metrics_username}",
      "fmc_metrics_password" : "${var.fmc_metrics_password}",
      "memory_metric_name" : "${var.autoscale_group_prefix}_memory_usage"
  }
}

resource "oci_artifacts_container_repository" "configure_ftdv_container_repository" {
    #Required
    compartment_id = var.compartment_id
    display_name = "${var.autoscale_group_prefix}_ftdv_configure/ftdv_configure"
}

resource "oci_artifacts_container_repository" "post_launch_actions_container_repository" {
    #Required
    compartment_id = var.compartment_id
    display_name = "${var.autoscale_group_prefix}_ftdv_post_launch_actions/ftdv_post_launch_actions"
}

resource "oci_artifacts_container_repository" "publish_metrics_container_repository" {
    #Required
    compartment_id = var.compartment_id
    display_name = "${var.autoscale_group_prefix}_ftdv_publish_metrics/ftdv_publish_metrics"
}

resource "oci_artifacts_container_repository" "remove_unhealthy_backend_container_repository" {
    #Required
    compartment_id = var.compartment_id
    display_name = "${var.autoscale_group_prefix}_ftdv_remove_unhealthy_vm/ftdv_remove_unhealthy_vm"
}

resource "oci_artifacts_container_repository" "scale_in_container_repository" {
    #Required
    compartment_id = var.compartment_id
    display_name = "${var.autoscale_group_prefix}_ftdv_scale_in/ftdv_scale_in"
}

resource "oci_artifacts_container_repository" "scale_out_container_repository" {
    #Required
    compartment_id = var.compartment_id
    display_name = "${var.autoscale_group_prefix}_ftdv_scale_out/ftdv_scale_out"
}

resource "oci_artifacts_container_repository" "token_manager_container_repository" {
    #Required
    compartment_id = var.compartment_id
    display_name = "${var.autoscale_group_prefix}_ftdv_token_manager/ftdv_token_manager"
}

resource "oci_artifacts_container_repository" "ftdv_teardown_operations_container_repository" {
    #Required
    compartment_id = var.compartment_id
    display_name = "${var.autoscale_group_prefix}_ftdv_teardown_operations/ftdv_teardown_operations"
}
