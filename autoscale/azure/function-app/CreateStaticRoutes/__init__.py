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
Purpose:    This python file is used for creating FMC static routes.
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
        inside_gw = os.environ.get("INSIDE_GW_OBJ_NAME")
        in_gw = os.environ.get("IN_NET_GW")

    fmc_outside_nic_name = os.environ.get("OUTSIDE_NIC_NAME")
    outside_gw = os.environ.get("OUTSIDE_GW_OBJ_NAME")
    cidr = os.environ.get("NETWORK_CIDR")
    out_gw = os.environ.get("OUT_NET_GW")

    azure_utility_ip = os.environ.get("AZURE_UTILITY_IP")
    azure_utility_ip_name = os.environ.get("AZURE_UTILITY_IP_NAME")
    any_ipv4_name = os.environ.get("ANY_IPV4_NAME")
    network_name = os.environ.get("NETWORK_NAME")

    req_body = req.get_json()
    ftdv_name = req_body.get('ftdDevName')
    ftdv_private_ip = req_body.get('ftdPrivateIp')

    log.warning("CreateStaticRoutes:::: Creating static routes {} : {}".format(ftdv_name, ftdv_private_ip))

    # ----------------Create Host Object--------
    log.info("CreateStaticRoutes:::: Creating objects")

    # Orchestrator will retry if failed
    r = fmc.fmcHostObjectCreate(outside_gw, out_gw, "Host Object for outside gateway")
    if gwlbSupport != "YES":
        r = fmc.fmcHostObjectCreate(inside_gw, in_gw, "Host Object for inside gateway")
    r = fmc.fmcHostObjectCreate(azure_utility_ip_name, azure_utility_ip, "Host Object for azure_utility_ip")

    # Create Network objects
    if gwlbSupport != "YES":
        r = fmc.fmcNetworkObjectCreate(any_ipv4_name, "0.0.0.0/0", "network object for any ip")
        r = fmc.fmcNetworkObjectCreate(network_name, cidr, "network object for local net cidr")

    log.info("CreateStaticRoutes:::: --------Creating Static routes-------------")
    dev_id = getFtdDeviceId(fmc, req_body)
    if gwlbSupport != "YES":
        in_gw_obj_id = fmc.getObjIdByName(inside_gw, "HOST")
    out_gw_obj_id = fmc.getObjIdByName(outside_gw, "HOST")
    azure_obj_id = fmc.getObjIdByName(azure_utility_ip_name, "HOST")
    if gwlbSupport != "YES":
        vnet_obj_id = fmc.getObjIdByName(network_name, "NETWORK")
        anyip_obj_name = fmc.getObjIdByName(any_ipv4_name, "NETWORK")

    route_creation_error = 0

    if gwlbSupport != "YES":
        if dev_id == "ERROR" or in_gw_obj_id == "ERROR" or out_gw_obj_id == "ERROR" or azure_obj_id == "ERROR" or vnet_obj_id == "ERROR" or anyip_obj_name == "ERROR":
            log.error("CreateStaticRoutes:::: Failed to get Device ID")
            log.error("CreateStaticRoutes:::: devId={}, inGwObjId={}, outGwObjId={}, azureObjId={}, vnetObjId={}, anyipObjName={}".format(dev_id, in_gw_obj_id, out_gw_obj_id, azure_obj_id, vnet_obj_id, anyip_obj_name))
            return func.HttpResponse("Unable to get Object Ids",status_code=400)
    else:
        if dev_id == "ERROR" or out_gw_obj_id == "ERROR" or azure_obj_id == "ERROR":
            log.error("CreateStaticRoutes:::: Failed to get Device ID")
            log.error("CreateStaticRoutes:::: devId={}, outGwObjId={}, azureObjId={}".format(dev_id, out_gw_obj_id, azure_obj_id))
            return func.HttpResponse("Unable to get Object Ids",status_code=400)


    if gwlbSupport != "YES":
        if fmc.fmcCreateHostRoutes(dev_id, fmc_outside_nic_name, any_ipv4_name, anyip_obj_name, outside_gw, out_gw_obj_id, "2", "Network") == "ERROR":
            log.error("CreateStaticRoutes:::: Failed to create route-2")
            route_creation_error = 1

        if fmc.fmcCreateHostRoutes(dev_id, fmc_inside_nic_name, network_name, vnet_obj_id, inside_gw, in_gw_obj_id, "1", "Network") == "ERROR":
            log.error("CreateStaticRoutes:::: Failed to create route-1")
            route_creation_error = 1

        if fmc.fmcCreateHostRoutes(dev_id, fmc_inside_nic_name, azure_utility_ip_name, azure_obj_id, inside_gw, in_gw_obj_id, "3") == "ERROR":
            log.error("CreateStaticRoutes:::: Failed to create route-3")
            route_creation_error = 1
    else:
        if fmc.fmcCreateHostRoutes(dev_id, fmc_outside_nic_name, azure_utility_ip_name, azure_obj_id, outside_gw, out_gw_obj_id, "3") == "ERROR":
            log.error("CreateStaticRoutes:::: Failed to create Azure health-probe route")
            route_creation_error = 1

    if route_creation_error == 1:
        return func.HttpResponse("Failed to create route",status_code=400)

    log.info("CreateStaticRoutes:::: Successfully created static routes")
    return func.HttpResponse("SUCCESS",status_code=200)
