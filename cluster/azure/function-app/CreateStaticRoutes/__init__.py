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
Purpose:    This python file is used for creating the static route on the instances.
"""

import os
import logging as log
import time
import azure.functions as func
from SharedCode.Utils import FMC
from SharedCode.cluster_utils import ClusterUtils

def main(req: func.HttpRequest):
    fmc = FMC()

    gwlbSupport = os.environ.get("GWLB_SUPPORT")
    if gwlbSupport != "YES":
        fmc_inside_nic_name = os.environ.get("INSIDE_NIC_NAME")
        in_gw = os.environ.get("INSIDE_NETWORK_GATEWAY")
        inside_gw = os.environ.get("INSIDE_GW_OBJ_NAME")

    cidr = os.environ.get("NETWORK_CIDR")
    outside_gw = os.environ.get("OUTSIDE_GW_OBJ_NAME")
    fmc_outside_nic_name = os.environ.get("OUTSIDE_NIC_NAME")
    out_gw = os.environ.get("OUTSIDE_NETWORK_GATEWAY")
    
    azure_utility_ip = os.environ.get("AZURE_UTILITY_IP")
    azure_utility_ip_name = os.environ.get("AZURE_UTILITY_IP_NAME")
    any_ipv4_name = os.environ.get("ANY_IPV4_NAME")
    network_name = os.environ.get("NETWORK_NAME")

    req_body = req.get_json()
    log.info("CreateStaticRoutes: Json Request : {}".format(req_body))
    ftdv_name = req_body.get('ftdDevName')
    ftdv_private_ip = req_body.get('ftdPrivateIp')
    ftdv_public_ip = req_body.get('ftdPublicIp')
    ftdv_port_number = 22
    ftdv_username = os.environ.get("FTD_USERNAME")
    ftdv_password = os.environ.get("FTD_PASSWORD")

    log.warning("CreateStaticRoutes:::: Creating static routes {} : {}".format(ftdv_name, ftdv_private_ip))

    # --------- Checking if the ftdv device is a data node ------------------------------------
    ftdv = ClusterUtils(ftdv_public_ip, ftdv_port_number, ftdv_username, ftdv_password)
    cluster_info_status, cluster_info = ftdv.get_cluster_info()
    if cluster_info_status == "SUCCESS":
        if ftdv.is_control_node(cluster_info):
            log.info("CreateStaticRoutes:::: FTDv {} is a control node".format(ftdv_public_ip))
            cluster_node = "CONTROL_NODE"
        else:
            log.info("CreateStaticRoutes:::: FTDv {} is a data node".format(ftdv_public_ip))
            cluster_node = "DATA_NODE"

    if cluster_node == "DATA_NODE":
        log.info("CreateStaticRoutes::: FTDv {} is a data node. Skipping the Static Route Configuration Step".format(ftdv_public_ip))
        time.sleep(60)
        return func.HttpResponse("SUCCESS", status_code=200)

    # ----------------Create Host Object--------
    log.info("CreateStaticRoutes:::: Creating objects")

    # Orchestrator will retry if failed
    r = fmc.fmcHostObjectCreate(outside_gw, out_gw, "Host Object for outside gateway")
    if gwlbSupport != "YES":
        r = fmc.fmcHostObjectCreate(inside_gw, in_gw, "Host Object for inside gateway")

    r = fmc.fmcHostObjectCreate(azure_utility_ip_name, azure_utility_ip, "Host Object for azure_utility_ip")

    # Create Network objects
    r = fmc.fmcNetworkObjectCreate(any_ipv4_name, "0.0.0.0/0", "network object for any ip")
    r = fmc.fmcNetworkObjectCreate(network_name, cidr, "network object for local net cidr")

    log.info("CreateStaticRoutes:::: --------Creating Static routes-------------")
    dev_id = fmc.getDevIdByName(ftdv_public_ip, "FTD")
    log.info("CreateStaticRoutes: Device ID for FTDv Instance {}:{} : {}".format(ftdv_name, ftdv_public_ip, dev_id))
    out_gw_obj_id = fmc.getObjIdByName(outside_gw, "HOST")
    azure_obj_id = fmc.getObjIdByName(azure_utility_ip_name, "HOST")
    vnet_obj_id = fmc.getObjIdByName(network_name, "NETWORK")
    anyip_obj_name = fmc.getObjIdByName(any_ipv4_name, "NETWORK")

    if gwlbSupport != "YES":
        in_gw_obj_id = fmc.getObjIdByName(inside_gw, "HOST")

    route_creation_error = 0

    if gwlbSupport != "YES":
        if dev_id == "ERROR" or in_gw_obj_id == "ERROR" or out_gw_obj_id == "ERROR" or azure_obj_id == "ERROR" or vnet_obj_id == "ERROR" or anyip_obj_name == "ERROR":
            log.error("CreateStaticRoutes:::: Failed to get Device ID")
            log.error("CreateStaticRoutes:::: devId={}, inGwObjId={}, outGwObjId={}, azureObjId={}, vnetObjId={}, anyipObjName={}".format(dev_id, in_gw_obj_id, out_gw_obj_id, azure_obj_id, vnet_obj_id, anyip_obj_name))
            return func.HttpResponse("Unable to get Object Ids",status_code=400) 
    else:
        if dev_id == "ERROR" or out_gw_obj_id == "ERROR" or azure_obj_id == "ERROR" or vnet_obj_id == "ERROR" or anyip_obj_name == "ERROR":
            log.error("CreateStaticRoutes:::: Failed to get Device ID")
            log.error("CreateStaticRoutes:::: devId={}, outGwObjId={}, azureObjId={}, vnetObjId={}, anyipObjName={}".format(dev_id, out_gw_obj_id, azure_obj_id, vnet_obj_id, anyip_obj_name))
            return func.HttpResponse("Unable to get Object Ids",status_code=400)

    if fmc.fmcCreateHostRoutes(dev_id, fmc_outside_nic_name, any_ipv4_name, anyip_obj_name, outside_gw, out_gw_obj_id, "2") == "ERROR":
        log.error("CreateStaticRoutes:::: Failed to create route-2")
        route_creation_error = 1

    if gwlbSupport != "YES":
        if fmc.fmcCreateHostRoutes(dev_id, fmc_inside_nic_name, network_name, vnet_obj_id, inside_gw, in_gw_obj_id, "1") == "ERROR":
            log.error("CreateStaticRoutes:::: Failed to create route-1")
            route_creation_error = 1

        if fmc.fmcCreateHostRoutes(dev_id, fmc_inside_nic_name, azure_utility_ip_name, azure_obj_id, inside_gw, in_gw_obj_id, "3") == "ERROR":
            log.error("CreateStaticRoutes:::: Failed to create route-3")
            route_creation_error = 1

    if route_creation_error == 1:
        return func.HttpResponse("Failed to create route",status_code=400)
        
    log.info("CreateStaticRoutes:::: Successfully created static routes")
    return func.HttpResponse("SUCCESS",status_code=200)