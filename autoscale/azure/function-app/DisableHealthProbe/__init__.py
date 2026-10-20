"""
Copyright (c) 2026 Cisco Systems Inc or its affiliates.

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
Purpose:    This python file is used for disabling FTD health probe routes.
"""

import os
import logging as log
import azure.functions as func
from SharedCode.Utils import FMC, getFtdDeviceId


def main(req: func.HttpRequest):
    fmc = FMC()
    gwlbSupport = os.environ.get("GWLB_SUPPORT")
    if gwlbSupport != "YES":
        fmc_inside_nic_name = os.environ.get("INSIDE_NIC_NAME")
    fmc_outside_nic_name = os.environ.get("OUTSIDE_NIC_NAME")
    azure_utility_ip_name = os.environ.get("AZURE_UTILITY_IP_NAME")
    outside_gw = os.environ.get("OUTSIDE_GW_OBJ_NAME")
    route_creation_error = 0
    log.warning("DisableHealthProbe:::: Disabling health Probe ")

    req_body = req.get_json()
    ftdv_name = req_body.get('ftdDevName')

    device_id = getFtdDeviceId(fmc, req_body)
    azure_obj_id = fmc.getObjIdByName(azure_utility_ip_name, "HOST")
    out_gw_obj_id = fmc.getObjIdByName(outside_gw, "HOST")

    if device_id == "ERROR" or azure_obj_id == "ERROR" or out_gw_obj_id == "ERROR":
        log.error("CreateStaticRoutes:::: Failed to get Device ID")
        log.error("CreateStaticRoutes:::: outGwObjId={}, azureObjId={} ".format(out_gw_obj_id, azure_obj_id))
        return func.HttpResponse("Failed to get resource ID",status_code=400)

    if fmc.fmcCreateHostRoutes(device_id, fmc_outside_nic_name, azure_utility_ip_name, azure_obj_id, azure_utility_ip_name, azure_obj_id, "1") == "ERROR":
        log.error("CreateStaticRoutes:::: Failed to create route to disable HP of ELB")
        route_creation_error = 1
    if gwlbSupport != "YES":
        if fmc.fmcCreateHostRoutes(device_id, fmc_inside_nic_name, azure_utility_ip_name, azure_obj_id, outside_gw, out_gw_obj_id, "2") == "ERROR":
            log.error("CreateStaticRoutes:::: Failed to create route to disable HP of ILB")
            route_creation_error = 1

    return func.HttpResponse("SUCCESS",status_code=200)
