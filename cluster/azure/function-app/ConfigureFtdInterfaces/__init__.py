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
Purpose:    This python file is used for configuring the FTDv interfaces.
"""

import os
import time
import azure.functions as func
import logging as log
from SharedCode.Utils import FMC
from SharedCode.cluster_utils import ClusterUtils

fmc_ip = os.environ.get("FMC_IP")
domain_uuid = os.environ.get("FMC_DOMAIN_UUID")

def main(req: func.HttpRequest):

    fmc = FMC()

    gwlbSupport = os.environ.get("GWLB_SUPPORT")
    log.info("ConfigureFtdInterfaces:::: GWLB Support Value : {}".format(gwlbSupport))

    if gwlbSupport != "YES":
        fmc_inside_zone = os.environ.get("INSIDE_ZONE")
        fmc_inside_nic_name = os.environ.get("INSIDE_NIC_NAME")
        fmc_inside_nic = os.environ.get("INSIDE_NIC_INTERFACE")
        inside_interface_mtu = 1300
        outside_interface_mtu = 1300
    else:
        outside_interface_mtu = 1374

    fmc_outside_zone = os.environ.get("OUTSIDE_ZONE")
    fmc_outside_nic_name = os.environ.get("OUTSIDE_NIC_NAME")
    fmc_outside_nic = os.environ.get("OUTSIDE_NIC_INTERFACE")
    fmc_registration_url = "https://" + fmc_ip + "/api/fmc_config/v1/domain/" + domain_uuid + "/devices/devicerecords/"

    req_body = req.get_json()
    ftdv_name = req_body.get('ftdDevName') 
    log.warning("ConfigureFtdInterfaces:::: Started Device Configuration for {}".format(ftdv_name))

    ftdv_public_ip = req_body.get('ftdPublicIp')
    ftdv_port_number = 22
    ftdv_username = os.environ.get("FTD_USERNAME")
    ftdv_password = os.environ.get("FTD_PASSWORD")

    # --------- Checking if the ftdv device is a data node ------------------------------------
    ftdv = ClusterUtils(ftdv_public_ip, ftdv_port_number, ftdv_username, ftdv_password)
    cluster_info_status, cluster_info = ftdv.get_cluster_info()
    if cluster_info_status == "SUCCESS":
        if ftdv.is_control_node(cluster_info):
            log.info("ConfigureFtdInterfaces:::: FTDv {} is a control node".format(ftdv_public_ip))
            cluster_node = "CONTROL_NODE"
        else:
            log.info("ConfigureFtdInterfaces:::: FTDv {} is a data node".format(ftdv_public_ip))
            cluster_node = "DATA_NODE"

    if cluster_node == "DATA_NODE":
        log.info("ConfigureFtdInterfaces::: FTDv {} is a data node. Skipping the configure Interface Step".format(ftdv_public_ip))
        time.sleep(60)
        return func.HttpResponse("SUCCESS", status_code=200)
        
    # ------------Get resource Ids------------------------------------------
    log.info("ConfigureFtdInterfaces:::: Getting FTD device ID")
    dev_id = fmc.getDevIdByName(ftdv_public_ip, "FTD")
    if (dev_id == "ERROR"):
        log.error("ConfigureFtdInterfaces:::: Failed to get Device ID")
        return func.HttpResponse("Unable to get Device Group ID",status_code=400)

    if gwlbSupport != "YES":
        log.info("ConfigureFtdInterfaces:::: Getting Inside NIC ID")
        inside_nic_id = fmc.getDevIdByName(fmc_inside_nic, "NIC", dev_id)
        if inside_nic_id == "ERROR":
            log.error("ConfigureFtdInterfaces:::: Failed to get Inside NIC Id")
            return func.HttpResponse("Failed to get Inside NIC Id",status_code=400)
        log.info("ConfigureFtdInterfaces:::: Inside NIC ID : {}".format(inside_nic_id))

    log.info("ConfigureFtdInterfaces:::: Getting Outside NIC ID")
    outside_nic_id = fmc.getDevIdByName(fmc_outside_nic, "NIC", dev_id)
    if outside_nic_id == "ERROR":
        log.error("ConfigureFtdInterfaces:::: Failed to get Outside NIC Id")
        return func.HttpResponse("Failed to get Outside NIC Id",status_code=400) 

    log.info("ConfigureFtdInterfaces:::: Outside NIC ID : {}".format(outside_nic_id))

    # ------------Get zone Id by name------------------------------------------
    if gwlbSupport != "YES":
        inside_zone_id = fmc.getDevIdByName(fmc_inside_zone, "ZONE")
        if inside_zone_id == "ERROR":
            log.error("ConfigureFtdInterfaces:::: Failed to get inside zone Id")
            return func.HttpResponse("Failed to get Inside Zone Id",status_code=400) 
        log.info("ConfigureFtdInterfaces:::: Inside zone ID : {}".format(inside_zone_id))

    outside_zone_id = fmc.getDevIdByName(fmc_outside_zone, "ZONE")
    if outside_zone_id == "ERROR":
        log.error("ConfigureFtdInterfaces:::: Failed to get outside zone Id")
        return func.HttpResponse("Failed to get Outside Zone Id",status_code=400) 

    log.info("ConfigureFtdInterfaces:::: Outside zone ID : {}".format(outside_zone_id))

    # -------------------Configure inside interface
    if gwlbSupport != "YES":
        url = fmc_registration_url + dev_id + "/physicalinterfaces/" + inside_nic_id
        put_data = { 
            "type": "PhysicalInterface", 
            "managementOnly": "false",
            "ipv4": { 
                "dhcp": {
                    "enableDefaultRouteDHCP": "false",
                    "dhcpRouteMetric": 1 
                } 
            },
            "securityZone": {
                "id": inside_zone_id,
                "type": "SecurityZone" 
            },
            "mode": "NONE",
            "ifname":fmc_inside_nic_name , 
            "enabled": "true",
            "MTU": inside_interface_mtu,
            "name": fmc_inside_nic, 
            "id": inside_nic_id
        }

        r = fmc.rest_put(url, put_data)
    
        if not (200 <= r.status_code <= 300):
            log.error("ConfigureFtdInterfaces:::: Failed to configure inside interface")
            log.info("ConfigureFtdInterfaces::::  Configure inside interface status - {}".format(r.content))
            return func.HttpResponse("Failed to configure inside interface", status_code=400) 
    
        log.info("ConfigureFtdInterfaces:::: Successfully configured Inside Interface")
    
    # -------------------Configure outside interface
    url = fmc_registration_url + dev_id + "/physicalinterfaces/" + outside_nic_id
    put_data = { 
        "type": "PhysicalInterface",  
        "managementOnly": "false",
        "ipv4": { 
            "dhcp": { 
                "enableDefaultRouteDHCP": "false",
                "dhcpRouteMetric": 1  
            }  
        },
        "securityZone": {  
            "id": outside_zone_id,  
            "type": "SecurityZone"  
        }, 
        "mode": "NONE",  
        "enabled": "true",
        "MTU": outside_interface_mtu,
        "ifname":fmc_outside_nic_name,
        "name": fmc_outside_nic,  
        "id": outside_nic_id
    }

    r = fmc.rest_put(url, put_data)
    
    if not (200 <= r.status_code <= 300):
        log.error("ConfigureFtdInterfaces:::: Failed to configure outside interface")
        log.info("ConfigureFtdInterfaces::::  Configure outside interface status - {}".format(r.content))
        return func.HttpResponse("Failed to configure outside interface",status_code=400) 

    log.info("configureFtdInterfaces:::: Interface Configuration is skipped as it is not needed for the cluster")
    log.info("ConfigureFtdInterfaces:::: Successfully configured Outside Interface")
    return func.HttpResponse("SUCCESS",status_code=200)