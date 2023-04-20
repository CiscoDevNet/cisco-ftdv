locals {
  filter_rule = "(resource.type=\"gce_instance_group_manager\" AND resource.labels.instance_group_manager_name = \"${var.resourceNamePrefix}-ftdv-instance-group\" AND protoPayload.methodName = \"v1.compute.regionInstanceGroupManagers.insert\" AND operation.last = true)  OR (resource.type = \"cloud_function\" AND resource.labels.function_name = \"${var.resourceNamePrefix}-ftdv-cluster-action\" AND textPayload:\"Reattempt\")"
  cluster_name = "${var.resourceNamePrefix}-cluster"
}

