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
Purpose:    This python file is used for disabling the health probe.
"""

import os
import logging as log
import azure.functions as func
from SharedCode.Utils import FMC


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
    log.info("DisableHealthProbe: Json Request : {}".format(req_body))
    ftdv_name = req_body.get('ftdDevName')
    ftdv_public_ip = req_body.get('ftdPublicIp')

    device_id = fmc.getDevIdByName(ftdv_public_ip, "FTD")
    log.info("DisableHealthProbe:::: FTDv {} Device ID : {}".format(ftdv_name, device_id))
    azure_obj_id = fmc.getObjIdByName(azure_utility_ip_name, "HOST")
    out_gw_obj_id = fmc.getObjIdByName(outside_gw, "HOST")
    log.info("DisableHealthProbe:::: Azure Utility IP obj Name : {} Outside Network GW Object Name : {}".format(azure_obj_id, out_gw_obj_id))

    if device_id == "ERROR" or azure_obj_id == "ERROR" or out_gw_obj_id == "ERROR":
        log.error("DisableHealthProbe:::: Failed to get Device ID")
        log.error("DisableHealthProbe:::: outGwObjId={}, azureObjId={} ".format(out_gw_obj_id, azure_obj_id))
        return func.HttpResponse("Failed to get resource ID",status_code=400) 

    return func.HttpResponse("SUCCESS",status_code=200) 
