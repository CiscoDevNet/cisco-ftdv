project_id = "<project-id>" # GCP project ID, e.g. test-project-12345
resource_name_prefix = "<resource-name>" #any string, e.g. ftdv (lowercase aplhabets only)
region = "us-central1" # GCP region to deploy, e.g us-central1
mgmt_ip_cidr_range = "" # e.g. 10.112.0.0/24
vpc_connector_ip_cidr_range = "" # /28 subnet only, e.g. 10.112.50.0/28
with_diagnostic = false # Enable diagnostic subnet, value : true | false
diag_ip_cidr_range = "" # e.g. 10.112.19.0/24
inside_ip_cidr_range = "" # e.g. 10.112.1.0/24
outside_ip_cidr_range = "" # e.g. 10.112.2.0/24
ccl_ip_cidr_range = "" # /27 subnet preferred, e.g. 10.112.100.0/27

