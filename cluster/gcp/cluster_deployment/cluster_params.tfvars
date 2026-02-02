# --------------------
# General Configuration
# --------------------
type_of_deployment           = ""                                                    # Type of deployment (north_south or east_west)

# --------------------
# Project Information
# --------------------
project_id                   = "<project-id>"                                        # GCP project ID
region                       = "<region>"                                            # Deployment region
zone1                        = "a"                                                   # Deployment zone, e.g. a,b,c,d
zone2                        = "b"                                                   # Deployment zone, e.g. a,b,c,d
zone3                        = "c"                                                   # Deployment zone, e.g. a,b,c,d
resource_name_prefix         = "<resource-name>"                                     # Prefix for naming resources
service_account_mail_id      = ""                                                    # Service account email, e.g. service-account-mail@example-project.iam.gserviceaccount.com

# --------------------
# VPC and Subnet Configuration
# --------------------
mgmt_vpc_name                = "<resource-name>-ftdv-mgmt-vpc"                       # Management VPC name
mgmt_subnet_name             = "<resource-name>-ftdv-mgmt-subnet"                    # Management subnet name
inside_vpc_name              = "<resource-name>-ftdv-inside-vpc"                     # Inside VPC name
inside_subnet_name           = "<resource-name>-ftdv-inside-subnet"                  # Inside subnet name
outside_vpc_name             = "<resource-name>-ftdv-outside-vpc"                    # Outside VPC name
outside_subnet_name          = "<resource-name>-ftdv-outside-subnet"                 # Outside subnet name
diag_vpc_name                = "<resource-name>-ftdv-diag-vpc"                       # Diagnostics VPC name
diag_subnet_name             = "<resource-name>-ftdv-diag-subnet"                    # Diagnostics subnet name
ccl_vpc_name                 = "<resource-name>-ftdv-ccl-vpc"                        # CCL VPC name
ccl_subnet_name              = "<resource-name>-ftdv-ccl-subnet"                     # CCL subnet name

# --------------------
# Firewall Rules
# --------------------
diag_firewall_rule_name      = "<resource-name>-ftdv-diag-firewall-rule"             # Firewall rule for diagnostics
ccl_firewall_rule_name       = "<resource-name>-ftdv-ccl-firewall-rule"              # Firewall rule for CCL
mgmt_firewall_rule_name      = "<resource-name>-ftdv-mgmt-firewall-rule"             # Firewall rule for management
inside_firewall_rule_name    = "<resource-name>-ftdv-inside-firewall-rule"           # Firewall rule for inside network
outside_firewall_rule_name   = "<resource-name>-ftdv-outside-firewall-rule"          # Firewall rule for outside network
inside_hc_firewall_rule_name = "<resource-name>-ftdv-inside-hc-firewall-rule"        # Firewall rule for inside network
outside_hc_firewall_rule_name= "<resource-name>-ftdv-outside-hc-firewall-rule"       # Firewall rule for outside network

# --------------------
# Instance Details
# --------------------
machine_type                 = "n1-standard-8"                                       # GCP Supported machine type
source_image_url             = "projects/cisco-public/global/images/<image-name>"    # Source image location for FTDv
public_key                   = "<ssh-public-key>"                                    # Public Key for SSH access, e.g. ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4v

# --------------------
# Autoscale Details
# --------------------
auto_scaling                 = true                                                  # Enable autoscaling
cpu_utilization_target       = 0.60                                                  # Target CPU utilization for autoscaling (0.0 to 1.0)
min_ftd_count                = 0                                                     # Minimum number of FTDv instances
max_ftd_count                = 2                                                     # Maximum number of FTDv instances

# --------------------
# FTDv Specific Configuration
# --------------------
ftd_password_secret_name     = ""                                                    # Name of the secret for New Admin password for FTDv, Device will used this password after first time login.
hostname                     = "ftdv"                                                # Hostname for FTDv, e.g. cisco-ngfwv
ccl_subnet_range             = "<first ip> <last ip>"                                # Subnet range for CCL, space separated
cluster_grp_name             = "<any-name-for-cluster>"                              # Cluster group name for FTDv
with_diagnostic              = false                                                 # Whether to enable diagnostics
assign_public_ip_to_mgmt     = true                                                  # Whether to assign public IP to management interface
ftd_reg_via_public_ip        = true                                                  # Whether to register FTDv with public IP
enable_secure_boot           = false                                                 # Supported from version 10.0 onwards only. Whether to enable secure boot

# --------------------
# FMC Information & FTDv Configuration
# --------------------
reg_id                       = "cisco"                                               # FMC registration ID
nat_id                       = "cisco"                                               # NAT ID for FMC
policy_id                    = ""                                                    # Initial policy ID created in FMC, e.g. ftdv-ini-pol
fmc_ip                       = ""                                                    # FMC IP address, e.g. 10.112.0.2 / 34.113.15.29
fmc_password_secret_name     = ""                                                    # Name of FMC login password Secret.
fmc_username                 = ""                                                    # FMC login username e.g. restapi
license_caps                 = ""                                                    # License capabilities e.g. BASE,MALWARE,URLFilter,THREAT
performance_tier             = ""                                                    # Performance tier for FTDv e.g. FTDv20, FTDv30 etc.
vpc_connector_name           = "<resource-name>-connector"                           # Name of VPC connector

# --------------------
# Internal Load Balancer Configuration
# --------------------
ilb_frontend_protocol        = "TCP"                                                 # Load balancer protocol
ilb_backend_protocol         = "TCP"                                                 # Backend protocol

# ILB Health Check
ilb_health_check_port        = 8989                                                  # ILB Health-check balancer port, NAT required in FMC
ilb_timeout_sec              = 5                                                     # Load balancer timeout (seconds)
ilb_draining_timeout_sec     = 60                                                    # Timeout for draining connections (seconds)
ilb_check_interval_sec       = 10                                                    # Interval between health checks for ILB (seconds)
ilb_unhealthy_threshold      = 1                                                     # Number of failed health checks before marking unhealthy

# The below parameters are used for 'north_south' deployment type only
# --------------------
# External Load Balancer Configuration
# --------------------
elb_frontend_protocol        = "TCP"                                                 # Port name for ELB
elb_backend_protocol         = "TCP"                                                 # Load balancer protocol
elb_front_end_ports          = "all"                                                 # List of ELB frontend(listener) ports, e.g. "all" or [22, 80, 443] 

# ELB Health Check
elb_health_check_port        = 7878                                                  # ELB health-check port, NAT required in FMC
elb_timeout_sec              = 5                                                     # Load balancer timeout (seconds)
elb_unhealthy_threshold      = 2                                                     # Number of failed health checks before marking unhealthy
elb_check_interval_sec       = 10                                                    # Interval between health checks for ELB (seconds)
elb_draining_timeout_sec     = 60                                                    # Timeout for draining connections (seconds)