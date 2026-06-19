# OCI Dual Stack Endpoint Configuration
# Fill these values to deploy the endpoint infrastructure

# OCI Provider Configuration
tenancy_ocid    = "__tenancy_ocid__"
region          = "__region__"

# Instance name
instance_name = "__instance_name__"

# Deployment configuration
availability_domain  = "__availability_domain__"

# Compute Configuration
compartment_id  = "__compartment_id__"
prefix          = "__prefix__"
admin_username  = "__admin_username__"
admin_password  = "__admin_password__"
image_ocid      = "__image_ocid__"
instance_type   = "__instance_type__"

# Network Configuration
# Management interface (SSH access) - from Management VCN
mgmt_vcn_id     = "__mgmt_vcn_id__"
mgmt_subnet_id  = "__mgmt_subnet_id__"
mgmt_nsg_id     = "__mgmt_nsg_id__"

# Data interface (traffic testing) - from inside/outside VCN
data_vcn_id     = "__data_vcn_id__"
data_subnet_id  = "__data_subnet_id__"
data_nsg_id     = "__data_nsg_id__"

assign_ipv6_address = true
