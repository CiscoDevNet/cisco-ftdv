# Project Configuration
resource_name_prefix = "cim-tg" # e.g., "random"
region               = "us-central1"               # e.g., "us-central1"
project_id           = "asavgcp-poc-4krn"           # e.g., "ftdv"

# Network Configuration
mgmt_ip_cidr_range          = "10.115.0.0/27"          # e.g., "10.115.0.0/24"
vpc_connector_ip_cidr_range = "10.115.50.0/28" # e.g., "10.115.50.0/28"
diag_ip_cidr_range          = "10.115.19.0/27"    # e.g., "10.115.19.0/24"
inside_ip_cidr_range        = "10.115.1.0/27"        # e.g., "10.115.1.0/24"
outside_ip_cidr_range       = "10.115.2.0/27"       # e.g., "10.115.2.0/24"

# Diagnostic Configuration
with_diagnostic = false # true if you want to enable diagnostic on FTDv
