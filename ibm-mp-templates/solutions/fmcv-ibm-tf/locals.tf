locals {
  fmcv_catalog_id          = "1082e7d2-5e2f-0a11-a3bc-f88a8e1931fc"
  fmcv_catalog_offering_id = "319ec1e1-0b9f-421c-a4f8-88e2ea84c887-global"
  fmcv_version_crn_prefix  = "crn:v1:bluemix:public:globalcatalog-collection:global::${local.fmcv_catalog_id}:version:${local.fmcv_catalog_offering_id}/"

  fmcv_image_catalog                  = jsondecode(file("${path.module}/fmcv-images.json"))
  fmcv_image_releases                 = local.fmcv_image_catalog.releases
  selected_fmcv_image_version         = var.fmcv_image_version == null ? local.fmcv_image_catalog.default_version : var.fmcv_image_version
  selected_fmcv_image                 = try(local.fmcv_image_releases[local.selected_fmcv_image_version], {})
  catalog_version_crn                 = try(trimspace(local.selected_fmcv_image.version_crn), "")
  catalog_plan_crn                    = try(trimspace(local.selected_fmcv_image.plan_crn), "")
  catalog_supported_regions           = try(toset(local.selected_fmcv_image.supported_regions), toset([]))
  catalog_supported_profiles          = try(toset(local.selected_fmcv_image.supported_profiles), toset([]))
  catalog_supported_secure_boot_modes = try(toset(local.selected_fmcv_image.secure_boot_modes), toset([]))
  catalog_reference_ready = (
    try(local.selected_fmcv_image.catalog_reference_verified, false) &&
    try(contains(["public", "selected_accounts"], local.selected_fmcv_image.reference_access_scope), false) &&
    local.catalog_version_crn != "" &&
    startswith(local.catalog_version_crn, local.fmcv_version_crn_prefix) &&
    try(local.selected_fmcv_image.catalog_version_locator == "${local.fmcv_catalog_id}.${split("/", local.catalog_version_crn)[1]}", false)
  )

  subnet_ids                   = [data.ibm_is_subnet.management.id]
  subnet_vpc_ids               = [data.ibm_is_subnet.management.vpc]
  subnet_zones                 = [data.ibm_is_subnet.management.zone]
  deployment_zone              = data.ibm_is_subnet.management.zone
  deployment_region            = replace(local.deployment_zone, "/-[0-9]+$/", "")
  requested_security_group_ids = toset([var.management_security_group_id])
  vpc_security_group_ids       = toset([for sg in data.ibm_is_security_groups.target_vpc.security_groups : sg.id])
  missing_security_group_ids   = setsubtract(local.requested_security_group_ids, local.vpc_security_group_ids)
  effective_user_data          = try(trimspace(var.user_data), "") == "" ? null : var.user_data
}
