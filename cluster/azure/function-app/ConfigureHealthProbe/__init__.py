"""
Copyright (c) 2024 Cisco Systems Inc or its affiliates.

All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
--------------------------------------------------------------------------------

Name:       __init__.py
Purpose:    This python file is used for configuring platform settings for NLB health probe.
"""

import os
import logging as log
import azure.functions as func
from SharedCode.Utils import FMC

def main(req: func.HttpRequest):
    fmc = FMC()

    gwlbSupport = os.environ.get("GWLB_SUPPORT")
    if gwlbSupport == "YES":
        log.info("ConfigureHealthProbe:::: Health probe configuration is not required for GWLB - skipping")
        return func.HttpResponse("SUCCESS", status_code=200)

    resource_prefix = os.environ.get("RESOURCE_PREFIX_NAME")
    health_check_port = os.environ.get("HEALTH_CHECK_PORT_NUMBER")
    fmc_inside_zone = os.environ.get("INSIDE_ZONE")
    fmc_outside_zone = os.environ.get("OUTSIDE_ZONE")
    dev_group_name = os.environ.get("CLUSTER_GROUP_NAME")

    req_body = req.get_json()
    log.info("ConfigureHealthProbe:::: Json Request : {}".format(req_body))

    log.info("ConfigureHealthProbe:::: Creating Platform Settings for NLB Health Check")
    # Force token refresh before platform settings operations
    fmc.getFmcAuthToken()
    platform_settings_name = resource_prefix + "_health_check"
    
    platform_policy_id = fmc.fmcCreatePlatformSettingsPolicy(platform_settings_name)
    if platform_policy_id == "ERROR":
        platform_policy_id = fmc.fmcGetPlatformSettingsPolicyId(platform_settings_name)
        if platform_policy_id == "ERROR":
            log.error("ConfigureHealthProbe:::: Failed to create/get Platform Settings Policy")
            return func.HttpResponse("Failed to create Platform Settings Policy", status_code=400)
        log.info("ConfigureHealthProbe:::: Platform Settings Policy already exists, using existing ID: {}".format(platform_policy_id))
    else:
        log.info("ConfigureHealthProbe:::: Created Platform Settings Policy with ID: {}".format(platform_policy_id))

    inside_zone_id = fmc.getDevIdByName(fmc_inside_zone, "ZONE")
    outside_zone_id = fmc.getDevIdByName(fmc_outside_zone, "ZONE")
    
    if inside_zone_id == "ERROR" or outside_zone_id == "ERROR":
        log.error("ConfigureHealthProbe:::: Failed to get security zone IDs. Inside: {}, Outside: {}".format(inside_zone_id, outside_zone_id))
        return func.HttpResponse("Failed to get security zone IDs", status_code=400)

    log.info("ConfigureHealthProbe:::: Updating Platform Settings with HTTP access for health check on port: {}".format(health_check_port))
    if fmc.fmcUpdatePlatformSettingsHttpAccess(platform_policy_id, health_check_port, inside_zone_id, outside_zone_id, fmc_inside_zone, fmc_outside_zone) == "ERROR":
        log.error("ConfigureHealthProbe:::: Failed to update Platform Settings with HTTP access")
        return func.HttpResponse("Failed to update Platform Settings", status_code=400)

    # Try to get cluster ID first (for FTD clusters), then fall back to device group
    target_type = "DeviceCluster"
    dev_group_id = fmc.getClusterIdByName(dev_group_name)
    if dev_group_id == "ERROR":
        log.info("ConfigureHealthProbe:::: Not found as cluster, trying device group...")
        target_type = "DeviceGroup"
        dev_group_id = fmc.getDevGroupIdByName(dev_group_name)
    if dev_group_id == "ERROR":
        log.error("ConfigureHealthProbe:::: Failed to get Cluster/Device Group ID for: {}".format(dev_group_name))
        return func.HttpResponse("Failed to get Cluster/Device Group ID", status_code=400)

    log.info("ConfigureHealthProbe:::: Assigning Platform Settings Policy to {}: {}".format(target_type, dev_group_name))
    if fmc.fmcAssignPlatformSettingsToDeviceGroup(platform_policy_id, platform_settings_name, dev_group_id, target_type) == "ERROR":
        log.error("ConfigureHealthProbe:::: Failed to assign Platform Settings to {}".format(target_type))
        return func.HttpResponse("Failed to assign Platform Settings", status_code=400)

    log.info("ConfigureHealthProbe:::: Successfully created and assigned Platform Settings for NLB Health Check")

    return func.HttpResponse("SUCCESS", status_code=200)
