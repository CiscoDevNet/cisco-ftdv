# Project Configuration
resource_name_prefix = "resource-name-prefix" # e.g., "random"
region               = "region"               # e.g., "us-central1"
project_id           = "project-id"           # e.g., "ftdv"

# Network Configuration
mgmt_ip_cidr_range          = "mgmt-ip-cidr-range"          # e.g., "10.115.0.0/24"
vpc_connector_ip_cidr_range = "vpc-connector-ip-cidr-range" # e.g., "10.115.50.0/28"
diag_ip_cidr_range          = "diagnostic-ip-cidr-range"    # e.g., "10.115.19.0/24"
inside_ip_cidr_range        = "inside-ip-cidr-range"        # e.g., "10.115.1.0/24"
outside_ip_cidr_range       = "outside-ip-cidr-range"       # e.g., "10.115.2.0/24"

# Diagnostic Configuration
with_diagnostic = true # true if you want to enable diagnostic on FTDv
