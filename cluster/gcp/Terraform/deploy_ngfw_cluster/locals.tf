locals {
  instance_template_name = "${var.resourceNamePrefix}-ftdv-instance-template"
  cluster_name = "${var.resourceNamePrefix}-cluster"
  inside_vpc_name = "${var.resourceNamePrefix}-ftdv-inside-vpc"
  outside_vpc_name = "${var.resourceNamePrefix}-ftdv-outside-vpc"
  inside_subnet_name =  "${var.resourceNamePrefix}-ftdv-inside-subnet"
  startup_script_with_diagonistic = "{ \"AdminPassword\": \"${var.adminPassword}\", \"Hostname\": \"${var.hostname}\", \"FirewallMode\": \"routed\", \"ManageLocally\": \"No\", \"Cluster\": { \"CclSubnetRange\": \"${var.cclSubnetRange}\", \"ClusterGroupName\": \"${local.cluster_name}\" } }"
  startup_script_without_diagonistic = "{ \"AdminPassword\": \"${var.adminPassword}\", \"Hostname\": \"${var.hostname}\", \"FirewallMode\": \"routed\", \"ManageLocally\": \"No\", \"Diagnostic\": \"OFF\", \"Cluster\": { \"CclSubnetRange\": \"${var.cclSubnetRange}\", \"ClusterGroupName\": \"${local.cluster_name}\" } }"
}