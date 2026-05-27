# Project Configuration
project_id           = "project-id"           # e.g., "asavgcp"
region               = "region"               # e.g., "us-central1"
resource_name_prefix = "resource-name-prefix" # e.g., "random"

# Machine Configuration
machine_type       = "machine-type"     # e.g., "n1-standard-4"
source_image_url   = "source-image-url" # e.g., "projects/cisco-public/global/images/cisco-ftdv-7-6-0-113"
enable_secure_boot = false              # Supported from version 10.0 onwards. Set true to enable Secure Boot

# Autoscaling Configuration
cpu_utilization_target = 0.5
cool_down_period_sec   = 30
min_ftd_replicas       = 1
max_ftd_replicas       = 2
zone                   = "b" # Deployment zone (comma separated alphabets, 3 at most), e.g. "b,c" Valid zones : https://cloud.google.com/compute/docs/regions-zones


# External Load Balancer Configuration
elb_port_name           = "tcp"
elb_protocol            = "TCP"
elb_protocol_name       = "TCP"
elb_ip_protocol         = "TCP"
elb_timeout_sec         = 5
elb_unhealthy_threshold = 2
elb_fe_ports            = ["80", "22"]

# Internal Load Balancer Configuration
ilb_protocol             = "TCP"
ilb_protocol_name        = "TCP"
ilb_draining_timeout_sec = 60
ilb_check_interval_sec   = 10
ilb_timeout_sec          = 5
ilb_unhealthy_threshold  = 3

# Security and Authentication of FTDv
public_key              = "public-key"            # e.g., "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGzAH1x13iuhyS6RSbUlOXMjPt/N8ptO2sasBCRJazsFq4q random@jasm-M-03LT"
service_account_mail_id = "service-account-email" # e.g., "random@asav.iam.gserviceaccount.com"

# VPC and Subnetwork Configuration
outside_vpc_name    = "outside-vpc-name"        # e.g., "random-outside-vpc"
outside_subnet_name = "outside-subnetwork-name" # e.g., "random-outside-subnet"
inside_vpc_name     = "inside-vpc-name"         # e.g., "random-inside-vpc"
inside_subnet_name  = "inside-subnetwork-name"  # e.g., "random-inside-subnet"
mgmt_vpc_name       = "mgmt-vpc-name"           # e.g., "random-mgmt-vpc"
mgmt_subnet_name    = "mgmt-subnetwork-name"    # e.g., "random-mgmt-subnet"
diag_vpc_name       = "diag-vpc-name"           # e.g., "random-diag-vpc"
diag_subnet_name    = "diag-subnetwork-name"    # e.g., "random-diag-subnet"

# Deployment and Diagnostic Configuration of FTDv
assign_public_ip_to_mgmt = false
with_diagnostic          = false

# Firewall Rules
mgmt_firewall_rule_name         = "allow-ftd-m" # e.g., "allow-ftd-m"
outside_firewall_rule_name      = "allow-ftd-o" # e.g., "allow-ftd-o"
inside_firewall_rule_name       = "allow-ftd-i" # e.g., "allow-ftd-i"
health_check_firewall_rule_name = "allow-ftd-h" # e.g., "allow-ftd-h"
diag_firewall_rule_name         = "allow-ftd-d" # e.g., "allow-ftd-d"

# FMC Configuration
fmc_ip                     = "fmc-ip"              # e.g., "10.115.0.2"
fmc_username               = "fmc-username"        # e.g., "admin"
fmc_password_secret        = "fmc-password-secret" # e.g., "random-fmc-password"
reg_id                     = "reg-id"              # e.g., "regID"
nat_id                     = "nat-id"              # e.g., "natId"
grp_id                     = "grp-id"              # e.g., "random"
policy_id                  = "policy-id"           # e.g., "random"
ftd_reg_via_public_ip      = false                 # true or false - for FMC-FTD registration
license_caps               = "BASE,MALWARE,THREAT"
instance_prefix_in_fmc     = "instance-prefix-in-fmc" # e.g., "random"
health_check_port          = "80"                     # e.g., "80"

# Gateway and Security Zone Configuration
outside_gw_name  = "outside-gw-name" # e.g., "random-outside-gw"
inside_gw_name   = "inside-gw-name"  # e.g., "random-inside-gw"
outside_sec_zone = "outside"         # e.g., "outside"
inside_sec_zone  = "inside"          # e.g., "inside"

# Secrets
new_ftd_password_secret = "new-ftd-password-secret" # e.g., "random-ftd-password"

# VPC Connector
vpc_connector_name = "vpc-connector-name" # e.g., "randomftdv-connector"