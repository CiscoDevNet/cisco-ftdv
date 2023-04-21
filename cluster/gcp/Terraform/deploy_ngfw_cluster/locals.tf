locals {
  instance_template_name = "${var.resourceNamePrefix}-ftdv-instance-template"
  cluster_name = "${var.resourceNamePrefix}-cluster"
  inside_vpc_name = "${var.resourceNamePrefix}-ftdv-inside-vpc"
  outside_vpc_name = "${var.resourceNamePrefix}-ftdv-outside-vpc"
  inside_subnet_name =  "${var.resourceNamePrefix}-ftdv-inside-subnet"
}