locals {
  asav_catalog_id          = "1082e7d2-5e2f-0a11-a3bc-f88a8e1931fc"
  asav_catalog_offering_id = "452f20c1-add3-4191-bbbf-476c9314932f-global"
  asav_version_crn_prefix  = "crn:v1:bluemix:public:globalcatalog-collection:global::${local.asav_catalog_id}:version:${local.asav_catalog_offering_id}/"

  # Publisher-controlled image lock, bundled with this module. Adding/removing
  # compatible releases or changing the default only requires editing this file.
  asav_image_catalog                  = jsondecode(file("${path.module}/asav-images.json"))
  asav_image_releases                 = local.asav_image_catalog.releases
  selected_asav_image_version         = var.asav_image_version == null ? local.asav_image_catalog.default_version : var.asav_image_version
  selected_asav_image                 = local.asav_image_releases[local.selected_asav_image_version]
  catalog_version_crn                 = local.selected_asav_image.version_crn
  catalog_plan_crn                    = try(trimspace(local.selected_asav_image.plan_crn), "")
  catalog_supported_regions           = toset(local.selected_asav_image.supported_regions)
  catalog_supported_profiles          = toset(local.selected_asav_image.supported_profiles)
  catalog_supported_secure_boot_modes = toset(local.selected_asav_image.secure_boot_modes)

  subnet_ids = [
    data.ibm_is_subnet.management.id,
    data.ibm_is_subnet.data_1.id,
    data.ibm_is_subnet.data_2.id,
  ]

  subnet_vpc_ids = [
    data.ibm_is_subnet.management.vpc,
    data.ibm_is_subnet.data_1.vpc,
    data.ibm_is_subnet.data_2.vpc,
  ]

  subnet_zones = [
    data.ibm_is_subnet.management.zone,
    data.ibm_is_subnet.data_1.zone,
    data.ibm_is_subnet.data_2.zone,
  ]

  deployment_zone   = data.ibm_is_subnet.management.zone
  deployment_region = replace(local.deployment_zone, "/-[0-9]+$/", "")

  requested_security_group_ids = toset([
    var.management_security_group_id,
    var.data_security_group_1_id,
    var.data_security_group_2_id,
  ])
  vpc_security_group_ids = toset([
    for security_group in data.ibm_is_security_groups.target_vpc.security_groups : security_group.id
  ])
  missing_security_group_ids = setsubtract(
    local.requested_security_group_ids,
    local.vpc_security_group_ids,
  )

  effective_user_data = try(trimspace(var.user_data), "") == "" ? null : var.user_data
}
