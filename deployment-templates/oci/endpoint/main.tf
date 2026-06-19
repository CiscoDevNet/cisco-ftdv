# OCI Dual Stack Endpoint Terraform Template
# Creates an Ubuntu VM with IPv4 and IPv6 support

terraform {
  required_version = ">= 1.0"
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = "~> 5.0"
    }
  }
}

# Input Variables
variable "tenancy_ocid" {
  description = "OCID of the tenancy"
  type        = string
}

variable "region" {
  description = "OCI region"
  type        = string
  default     = "us-phoenix-1"
}

variable "compartment_id" {
  description = "OCID of the compartment where resources will be created"
  type        = string
}

variable "prefix" {
  description = "Prefix for resource naming"
  type        = string
  default     = "cisco"
}

variable "instance_name" {
  description = "Name of the Virtual Machine"
  type        = string
  default     = "ubuntu-vm"
}

variable "admin_username" {
  description = "Username for the Virtual Machine"
  type        = string
  default     = "ubuntu"
}

variable "image_ocid" {
  description = "OCID of the VM image to use"
  type        = string
  default     = "ocid1.image.oc1.phx.aaaaaaaavhykwhe4bhsoa25kv2sbjixy3a3kqud33wvfjnim7yuhbvwbb4gq"
}

variable "admin_password" {
  description = "Password for the VM admin user"
  type        = string
  sensitive   = true
}

variable "instance_type" {
  description = "The shape of the VM instance"
  type        = string
  default     = "VM.Standard.E2.1"
}

variable "mgmt_vcn_id" {
  description = "ID of the Management VCN for SSH access"
  type        = string
}

variable "mgmt_subnet_id" {
  description = "ID of the management subnet for SSH access (from Management VCN)"
  type        = string
}

variable "mgmt_nsg_id" {
  description = "ID of the management NSG"
  type        = string
}

variable "data_vcn_id" {
  description = "ID of the data VCN (inside or outside)"
  type        = string
}

variable "data_subnet_id" {
  description = "ID of the data subnet for traffic testing (from inside/outside VCN)"
  type        = string
}

variable "data_nsg_id" {
  description = "ID of the data NSG"
  type        = string
}

variable "assign_ipv6_address" {
  description = "Assign an IPv6 address to the VM"
  type        = bool
  default     = true
}

variable "availability_domain" {
  description = "The availability domain to place instances. To get the specific names of your tenancy's availability domains, use the ListAvailabilityDomains operation. Example - Tpeb:PHX-AD-1, Tpeb:PHX-AD-2"
  type        = string
  validation {
    condition = (
      can(regex("^[0-9A-Za-z:-]+$", var.availability_domain))
    )
    error_message = "Please provide a valid availability domain."
  }
}

# Provider Configuration
provider "oci" {
  tenancy_ocid = var.tenancy_ocid
  region       = var.region
}

# Data source to get VCN and subnet details
data "oci_core_vcn" "mgmt_vcn" {
  vcn_id = var.mgmt_vcn_id
}

data "oci_core_subnet" "mgmt_subnet" {
  subnet_id = var.mgmt_subnet_id
}

data "oci_core_vcn" "data_vcn" {
  vcn_id = var.data_vcn_id
}

data "oci_core_subnet" "data_subnet" {
  subnet_id = var.data_subnet_id
}

# VM Instance
resource "oci_core_instance" "vm" {
  availability_domain = var.availability_domain
  compartment_id      = var.compartment_id
  display_name        = "${var.instance_name}"
  shape               = var.instance_type

  source_details {
    source_type = "image"
    source_id   = var.image_ocid
  }

  create_vnic_details {
    subnet_id              = var.mgmt_subnet_id
    display_name           = "${var.instance_name}-mgmt-vnic"
    assign_public_ip       = true
    nsg_ids                = [var.mgmt_nsg_id]
    assign_private_dns_record = true
    hostname_label         = var.instance_name
  }

  metadata = {
    user_data = base64encode(<<-EOF
      #!/bin/bash
      useradd -m -s /bin/bash -G sudo ${var.admin_username}
      echo '${var.admin_username}:${var.admin_password}' | chpasswd

      # SSH Config for password login
      sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication no/g' /etc/ssh/sshd_config
      sed -i 's/PubkeyAuthentication yes/PubkeyAuthentication no/g' /etc/ssh/sshd_config
      sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
      sudo systemctl restart sshd

      # Basic tools
      sudo apt-get update
      sudo apt-get install -y nmap iperf iperf3 firewalld net-tools
      sudo systemctl stop firewalld

      # Network tuning
      sudo ip link set ens3 mtu 1300

      # Shell setup
      sudo cp /etc/skel/.bashrc /home/${var.admin_username}/
      sudo cp /etc/skel/.profile /home/${var.admin_username}/
      sudo chown ${var.admin_username}:${var.admin_username} /home/${var.admin_username}/.bashrc /home/${var.admin_username}/.profile
    EOF
    )
  }

  freeform_tags = {
    autostop    = "false"
    autodelete  = "false"
  }
}

# Secondary VNIC for data interface (private IP only)
resource "oci_core_vnic_attachment" "vm_data_vnic" {
  instance_id  = oci_core_instance.vm.id
  display_name = "${var.instance_name}-data-vnic"
  # Serialize fresh-instance network mutations. OCI was creating the primary-VNIC
  # IPv6 address and the secondary VNIC in parallel, and the attachment could end
  # up reported back as DETACHED instead of ATTACHED.
  depends_on = [oci_core_ipv6.vm_ipv6]

  create_vnic_details {
    subnet_id        = var.data_subnet_id
    display_name     = "${var.instance_name}-data-vnic"
    assign_public_ip = false
    nsg_ids          = [var.data_nsg_id]
    hostname_label   = "${var.instance_name}-data"
  }
}

# Data source to get VNIC attachment for the instance
data "oci_core_vnic_attachments" "vm_vnic_attachments" {
  compartment_id      = var.compartment_id
  instance_id         = oci_core_instance.vm.id
}

# Data source to get management VNIC details for outputs
data "oci_core_vnic" "vm_vnic" {
  vnic_id = data.oci_core_vnic_attachments.vm_vnic_attachments.vnic_attachments[0].vnic_id
}

# Data source to get data VNIC details
data "oci_core_vnic" "vm_data_vnic" {
  vnic_id = oci_core_vnic_attachment.vm_data_vnic.vnic_id
}

# IPv6 Public IP Address (if IPv6 is enabled on the Management VCN)
resource "oci_core_ipv6" "vm_ipv6" {
  count   = var.assign_ipv6_address && length(data.oci_core_vcn.mgmt_vcn.ipv6cidr_blocks) > 0 ? 1 : 0
  vnic_id = data.oci_core_vnic_attachments.vm_vnic_attachments.vnic_attachments[0].vnic_id
  
  freeform_tags = {
    Environment = "test"
    Purpose     = "endpoint"
    Prefix      = var.prefix
  }
}

# Outputs
output "instance_id" {
  description = "OCID of the VM instance"
  value       = oci_core_instance.vm.id
}

output "instance_name" {
  description = "Name of the VM instance"
  value       = var.instance_name
}

output "public_ipv4_address" {
  description = "IPv4 public IP address of the VM"
  value       = data.oci_core_vnic.vm_vnic.public_ip_address
}

output "public_ipv6_address" {
  description = "IPv6 public IP address of the VM (if enabled)"
  value       = var.assign_ipv6_address && length(data.oci_core_vcn.mgmt_vcn.ipv6cidr_blocks) > 0 ? oci_core_ipv6.vm_ipv6[0].ip_address : "IPv6 not enabled"
}

output "private_ipv4_address" {
  description = "Private IPv4 address of the VM"
  value       = data.oci_core_vnic.vm_vnic.private_ip_address
}

output "data_private_ipv4_address" {
  description = "Private IPv4 address of the data interface"
  value       = data.oci_core_vnic.vm_data_vnic.private_ip_address
}

output "hostname" {
  description = "Hostname of the VM"
  value       = var.instance_name
}
