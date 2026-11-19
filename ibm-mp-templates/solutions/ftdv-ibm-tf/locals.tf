locals {
  ftdv_catalog_id          = "1082e7d2-5e2f-0a11-a3bc-f88a8e1931fc"
  ftdv_catalog_offering_id = "29e54f20-ff16-45e5-9a18-469652bbeab1-global"
  ftdv_version_crn_prefix  = "crn:v1:bluemix:public:globalcatalog-collection:global::${local.ftdv_catalog_id}:version:${local.ftdv_catalog_offering_id}/"

  ftdv_image_catalog                  = jsondecode(file("${path.module}/ftdv-images.json"))
  ftdv_image_releases                 = local.ftdv_image_catalog.releases
  selected_ftdv_image_version         = var.ftdv_image_version == null ? local.ftdv_image_catalog.default_version : var.ftdv_image_version
  selected_ftdv_image                 = try(local.ftdv_image_releases[local.selected_ftdv_image_version], {})
  catalog_version_crn                 = try(trimspace(local.selected_ftdv_image.version_crn), "")
  catalog_plan_crn                    = try(trimspace(local.selected_ftdv_image.plan_crn), "")
  catalog_supported_regions           = try(toset(local.selected_ftdv_image.supported_regions), toset([]))
  catalog_supported_profiles          = try(toset(local.selected_ftdv_image.supported_profiles), toset([]))
  catalog_supported_secure_boot_modes = try(toset(local.selected_ftdv_image.secure_boot_modes), toset([]))
  catalog_reference_ready = (
    try(local.selected_ftdv_image.catalog_reference_verified, false) &&
    try(contains(["public", "selected_accounts"], local.selected_ftdv_image.reference_access_scope), false) &&
    local.catalog_version_crn != "" &&
    startswith(local.catalog_version_crn, local.ftdv_version_crn_prefix) &&
    try(local.selected_ftdv_image.catalog_version_locator == "${local.ftdv_catalog_id}.${split("/", local.catalog_version_crn)[1]}", false)
  )

  subnet_ids                   = [data.ibm_is_subnet.data_1.id, data.ibm_is_subnet.data_2.id, data.ibm_is_subnet.management.id, data.ibm_is_subnet.data_3.id]
  subnet_vpc_ids               = [data.ibm_is_subnet.data_1.vpc, data.ibm_is_subnet.data_2.vpc, data.ibm_is_subnet.management.vpc, data.ibm_is_subnet.data_3.vpc]
  subnet_zones                 = [data.ibm_is_subnet.data_1.zone, data.ibm_is_subnet.data_2.zone, data.ibm_is_subnet.management.zone, data.ibm_is_subnet.data_3.zone]
  deployment_zone              = data.ibm_is_subnet.management.zone
  deployment_region            = replace(local.deployment_zone, "/-[0-9]+$/", "")
  requested_security_group_ids = toset([var.data_security_group_1_id, var.data_security_group_2_id, var.management_security_group_id, var.data_security_group_3_id])
  vpc_security_group_ids       = toset([for sg in data.ibm_is_security_groups.target_vpc.security_groups : sg.id])
  missing_security_group_ids   = setsubtract(local.requested_security_group_ids, local.vpc_security_group_ids)
  effective_user_data          = try(trimspace(var.user_data), "") == "" ? null : var.user_data
}
