# --------------------
# General Configuration
# --------------------
type_of_deployment = "" # Type of deployment (north_south or east_west)

# --------------------
# Project Information
# --------------------
project_id            = "<project-id>"    # GCP project ID
region                = "<region>"        # Deployment region
zone                  = "a"               # Deployment zone, e.g. a,b,c,d
resource_name_prefix  = "<resource-name>" # Prefix for naming resources
service_account_email = ""                # Service account email, e.g. service-account-mail@example-project.iam.gserviceaccount.com

# --------------------
# VPC and Subnet Configuration
# --------------------
mgmt_vpc_name       = "<resource-name>-ftdv-mgmt-vpc"       # Management VPC name
mgmt_subnet_name    = "<resource-name>-ftdv-mgmt-subnet"    # Management subnet name
inside_vpc_name     = "<resource-name>-ftdv-inside-vpc"     # Inside VPC name
inside_subnet_name  = "<resource-name>-ftdv-inside-subnet"  # Inside subnet name
outside_vpc_name    = "<resource-name>-ftdv-outside-vpc"    # Outside VPC name
outside_subnet_name = "<resource-name>-ftdv-outside-subnet" # Outside subnet name
diag_vpc_name       = "<resource-name>-ftdv-diag-vpc"       # Diagnostics VPC name
diag_subnet_name    = "<resource-name>-ftdv-diag-subnet"    # Diagnostics subnet name
ccl_vpc_name        = "<resource-name>-ftdv-ccl-vpc"        # CCL VPC name
ccl_subnet_name     = "<resource-name>-ftdv-ccl-subnet"     # CCL subnet name

# --------------------
# Firewall Rules
# --------------------
diag_firewall_rule         = "<resource-name>-ftdv-diag-firewall-rule"         # Firewall rule for diagnostics
ccl_firewall_rule          = "<resource-name>-ftdv-ccl-firewall-rule"          # Firewall rule for CCL
mgmt_firewall_rule         = "<resource-name>-ftdv-mgmt-firewall-rule"         # Firewall rule for management
inside_firewall_rule       = "<resource-name>-ftdv-inside-firewall-rule"       # Firewall rule for inside network
outside_firewall_rule      = "<resource-name>-ftdv-outside-firewall-rule"      # Firewall rule for outside network
health_check_firewall_rule = "<resource-name>-ftdv-health-check-firewall-rule" # Firewall rule for health checks

# --------------------
# Instance Details
# --------------------
# Supported machine types are  "c2-standard-4", "c2-standard-8", "c2-standard-16", "n1-standard-4", "n1-standard-8", "n1-standard-16", "n2-standard-4", "n2-standard-8", "n2-standard-16","n2-highmem-4", "n2-highmem-8", "n1-highmem-4","n1-highmem-8", "n1-highmem-16", "n2d-standard-4", "n2d-standard-8", "n2d-standard-16", "c2d-standard-4", "c2d-standard-8", "c2d-standard-16"
machine_type           = "n1-standard-8"                                            # GCP machine type
source_image_url       = "projects/cisco-public/global/images/cisco-ftdv-7-6-0-113" # Source image for FTDv
cpu_utilization_target = 0.60                                                       # Target CPU utilization for autoscaling
ftdv_replicas          = 2                                                          # Number of FTDv instances to deploy

# --------------------
# FTDv Specific Configuration
# --------------------
admin_password   = ""                       # Admin password for FTDv, e.g. Cisco@1984
hostname         = "ftdv"                   # Hostname for FTDv, e.g. cisco-ngfwv
ccl_subnet_range = "<first ip> <last ip>"   # Subnet range for CCL, space separated
cluster_grp_name = "<any-name-for-cluster>" # Cluster group name for FTDv
with_diagnostic  = true                     # Whether to enable diagnostics

# --------------------
# FMC Information & FTDv Configuration
# --------------------
deploy_with_external_ip = "False"                     # Whether to deploy with an external IP ("True" or "False")
retry_count             = 16                          # Number of retry attempts
reg_id                  = "cisco"                     # FMC registration ID
nat_id                  = "cisco"                     # NAT ID for FMC
cls_grp_name            = "<resource-name>"           # Cluster group name
policy_id               = ""                          # Initial policy ID created in FMC, e.g. ftdv-ini-pol
fmc_ip                  = ""                          # FMC IP address, e.g. 10.112.0.2 / 34.113.15.29
fmc_password            = ""                          # FMC login password e.g. Cisco@1984
fmc_username            = ""                          # FMC login username e.g. restapi
ftdv_password           = ""                          # FTDv login password e.g. Cisco@1984
license_caps            = ""                          # License capabilities e.g. BASE,MALWARE,URLFilter,THREAT
performance_tier        = ""                          # Performance tier for FTDv e.g. FTDv5, FTDv10, FTDv20
vpc_connector_name      = "<resource-name>-connector" # Name of VPC connector

# --------------------
# Internal Load Balancer Configuration
# --------------------
ilb_port                 = 8989  # ILB Health-check balancer port, NAT required in FMC
ilb_protocol             = "TCP" # Load balancer protocol
ilb_timeout_sec          = 5     # Load balancer timeout (seconds)
ilb_draining_timeout_sec = 60    # Timeout for draining connections (seconds)
ilb_check_interval_sec   = 10    # Interval between health checks for ILB (seconds)
ilb_unhealthy_threshold  = 1     # Number of failed health checks before marking unhealthy

# The below parameters are used for 'north_south' deployment type only
# --------------------
# Load Balancer Configuration Options
# --------------------
elb_port            = 7878  # ELB health-check port, NAT required in FMC
elb_front_end_ports = "all" # List of ELB frontend(listener) ports, e.g. "all" | [22, 80, 443] 

# --------------------
# External Load Balancer Configuration
# --------------------
elb_port_name           = "tcp" # Port name for ELB
elb_protocol            = "TCP" # Load balancer protocol
elb_timeout_sec         = 5     # Load balancer timeout (seconds)
elb_protocol_name       = "tcp" # Protocol name
elb_unhealthy_threshold = 2     # Number of failed health checks before marking unhealthy
elb_ip_protocol         = "TCP" # IP protocol
