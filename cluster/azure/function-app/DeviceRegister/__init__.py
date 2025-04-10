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
Purpose:    This python file is used for registering the FTDv instance to the FMCv.
"""

import logging as log
import os
import time
import azure.functions as func
from SharedCode.Utils import FMC
from SharedCode.cluster_utils import ClusterUtils


fmc_ip = os.environ.get("FMC_IP")
domain_uuid = os.environ.get("FMC_DOMAIN_UUID")

def main(req: func.HttpRequest):

    cluster_group_name = os.environ.get("CLUSTER_GROUP_NAME")
    performance_tier_value = os.environ.get('PERFORMANCE_TIER')
    license = os.environ.get("LICENSE_CAPABILITY")
    reg_key = os.environ.get("REG_KEY")
    nat_id = os.environ.get("NAT_ID")
    policy_name = os.environ.get("POLICY_NAME")

    fmc = FMC()

    req_body = req.get_json()
    ftdv_name = req_body.get('ftdDevName')
    ftdv_public_ip = req_body.get('ftdPublicIp')
    ftdv_username = os.environ.get("FTD_USERNAME")
    ftdv_password = os.environ.get("FTD_PASSWORD")
    ftdv_port_number = 22

    # -------------------------- Checking If the FTDv is a control Node -----------------------
    ftdv = ClusterUtils(ftdv_public_ip, ftdv_port_number, ftdv_username, ftdv_password)
    cluster_info_status, cluster_info = ftdv.get_cluster_info()
    if cluster_info_status == "SUCCESS":
        if ftdv.is_control_node(cluster_info):
            log.info("DeviceRegister:::: FTDv {} is a control node".format(ftdv_public_ip))
            cluster_node = "CONTROL_NODE"
        else:
            log.info("DeviceRegister:::: FTDv {} is a data node".format(ftdv_public_ip))
            cluster_node = "DATA_NODE"

    if cluster_node == "DATA_NODE":
        log.info("DeviceRegister::: FTDv {} is data node. Skipping the device registration".format(ftdv_public_ip))
        ret_val = "{ \"ftdDevName\" : \"" + ftdv_name + "\", \"ftdPublicIp\" : \"" + ftdv_public_ip + "\"}"
        time.sleep(60)
        return func.HttpResponse(ret_val, status_code=200)
    else:
        fmc_registration_url = "https://" + fmc_ip + "/api/fmc_config/v1/domain/" + domain_uuid + "/devices/devicerecords"
        log.warning("DeviceRegister:::: Received Request to Register FTD with FMC")
        log.info("DeviceRegister:::: FTD Public IP : {}".format(ftdv_public_ip))
        log.info("DeviceRegister:::: FTD Instance Name : {}".format(ftdv_name))
        log.info("DeviceRegister:::: FMC IP : {}".format(fmc_ip))
        log.info("DeviceRegister:::: Policy Name : {}".format(policy_name))

        # ---------------------------Get Policy ID by name------------------------------------------
        log.info("DeviceRegister:::: Getting Access policy ID")
        policy_id = fmc.getAccessPolicyIdByName(policy_name)

        if policy_id == "ERROR" or len(policy_id) == 0:
            log.error("DeviceRegister:::: Unable to get Policy ID from Policy Name {}".format(policy_name))
            return func.HttpResponse("Unable to get Policy ID", status_code=400) # need to change

        log.info("DeviceRegister:::: Found Policy {} ID : {} ".format(policy_name, policy_id))

        # ---------------------------Register FTD------------------------------------------
        # Orchestrator will retry if failed
        log.info("DeviceRegister:::: Registering FTD with FMC")
        log.warning("Grouping this FTD under the Cluster Group :{} ".format(cluster_group_name))

        log.warning("License detailed entered by user : {}".format(license))
        license = license.replace(" ", "")
        license = license.split(",")
        log.warning("License after formatting: {}".format(license))

        post_data = {
            "name": ftdv_public_ip, 
            "hostName": ftdv_public_ip,
            "regKey": reg_key,
            "natID": nat_id ,
            "type": "Device",
            "license_caps": license,
            "performanceTier": performance_tier_value,
            "accessPolicy": {
                "id": policy_id ,
                "type": "AccessPolicy"
            }
        }

        log.info("DeviceRegister:::: Registration Content : {}".format(post_data))
        r = fmc.rest_post(fmc_registration_url, post_data)

        if not (200 <= r.status_code <= 300):
            log.error("DeviceRegister:::: Failed Device Registration")
            return func.HttpResponse("Device Registration Failed",status_code=400) 

        ret_val = "{ \"ftdDevName\" : \"" + ftdv_name + "\", \"ftdPublicIp\" : \"" + ftdv_public_ip + "\"}"
        return func.HttpResponse(ret_val, status_code=200)
