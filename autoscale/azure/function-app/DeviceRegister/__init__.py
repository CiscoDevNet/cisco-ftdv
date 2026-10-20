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
Purpose:    This python file is used for registering FTD devices with FMC.
"""

import logging as log
import os
import time
import json
import azure.functions as func
from SharedCode.Utils import FMC, getFtdDeviceId, getFtdRegistrationIp, getInstanceNatId

fmc_ip = os.environ.get("FMC_IP")
domain_uuid = os.environ.get("FMC_DOMAIN_UUID")


def _success_response(req_body):
    return func.HttpResponse(json.dumps(req_body), status_code=200)


def _is_registered(fmc, req_body):
    ftdv_name = req_body.get('ftdDevName')
    try:
        return getFtdDeviceId(fmc, req_body) != "ERROR"
    except Exception as e:
        log.warning("DeviceRegister:::: Unable to check existing device {}: {}".format(ftdv_name, e))
        return False


def main(req: func.HttpRequest):
    # FMC URLs for REST API's
    dev_group_name = os.environ.get("DEVICE_GROUP_NAME")
    performance_tier_value = os.environ.get("PERFORMANCE_TIER")
    license = os.environ.get("LICENSE_CAPABILITY")
    reg_key = os.environ.get("REG_KEY")
    nat_id = os.environ.get("NAT_ID")
    policy_name = os.environ.get("POLICY_NAME")
    fmc = FMC()

    req_body = req.get_json()
    ftdv_name = req_body.get('ftdDevName')
    ftdv_public_ip = req_body.get('ftdPublicIp')
    ftdv_private_ip = req_body.get('ftdPrivateIp')
    registration_using_public_fmc_ip = (os.environ.get("REGISTRATION_USING_PUBLIC_FMC_IP") or "NO").upper()
    ftdv_registration_ip = getFtdRegistrationIp(req_body)
    nat_id = getInstanceNatId(nat_id, ftdv_name)

    fmc_registration_url = "https://" + fmc_ip + "/api/fmc_config/v1/domain/" + domain_uuid + "/devices/devicerecords"
    log.warning("DeviceRegister:::: Received Request to Register FTD with FMC")
    log.info("DeviceRegister:::: FTD Public IP : {}".format(ftdv_public_ip))
    log.info("DeviceRegister:::: FTD Registration IP : {}".format(ftdv_registration_ip))
    log.info("DeviceRegister:::: Registration Using Public FMC IP : {}".format(registration_using_public_fmc_ip))
    log.info("DeviceRegister:::: FTD Instance Name : {}".format(ftdv_name))
    log.info("DeviceRegister:::: FMC IP : {}".format(fmc_ip))
    log.info("DeviceRegister:::: Policy Name : {}".format(policy_name))

    if not ftdv_name:
        log.error("DeviceRegister:::: Invalid request, ftdDevName is missing")
        return func.HttpResponse("Invalid request, ftdDevName is missing", status_code=400)

    if _is_registered(fmc, req_body):
        log.warning("DeviceRegister:::: FTD {} is already registered with FMC".format(ftdv_name))
        return _success_response(req_body)

    # ---------------------------Get Policy ID by name------------------------------------------
    log.info("DeviceRegister:::: Getting Access policy ID")
    policy_id = fmc.getAccessPolicyIdByName(policy_name)

    if policy_id == "ERROR" or len(policy_id) == 0:
        log.error("DeviceRegister:::: Unable to get Policy ID from Policy Name {}".format(policy_name))
        return func.HttpResponse("Unable to get Policy ID", status_code=400)
    
    log.info("DeviceRegister:::: Found Policy {} ID : {} ".format(policy_name, policy_id))

    # ---------------------------Register FTD------------------------------------------
    # Orchestrator will retry if failed
    log.info("DeviceRegister:::: Registering FTD with FMC")
    log.warning("Grouping this FTD under Device Group :{} ".format(dev_group_name))
    dev_group_id = fmc.getDevGroupIdByName(dev_group_name)
    if dev_group_id == "ERROR":
        log.error("Unable to get Device Group ID")
        return func.HttpResponse("Unable to get Device Group ID", status_code=400)
    log.info("Device group name : {}, ID: {}".format(dev_group_name, dev_group_id))
    log.warning("License detailed entered by user : {}".format(license))
    license = license.replace(" ", "")
    license = license.split(",")
    log.warning("License after formatting: {}".format(license))

    post_data = {
        "name": ftdv_name, 
        "hostName": ftdv_registration_ip,
        "regKey": reg_key ,
        "natID": nat_id ,
        "type": "Device",
        "license_caps": license,
        "performanceTier": performance_tier_value,
        "accessPolicy": {
            "id": policy_id ,
            "type": "AccessPolicy"
        },
        "deviceGroup": {
            "id": dev_group_id ,
            "type": "DeviceGroup"
        }
    }

    log.info("DeviceRegister:::: Registration Content : {}".format(post_data))
    try:
        r = fmc.rest_post(fmc_registration_url, post_data)
    except Exception as e:
        log.warning("DeviceRegister:::: Registration POST failed for {}: {}".format(ftdv_name, e))
        time.sleep(5)
        if _is_registered(fmc, req_body):
            log.warning("DeviceRegister:::: FTD {} was registered despite POST failure".format(ftdv_name))
            return _success_response(req_body)
        raise

    if not (200 <= r.status_code <= 300):
        log.error("DeviceRegister:::: Failed Device Registration")
        time.sleep(5)
        if _is_registered(fmc, req_body):
            log.warning("DeviceRegister:::: FTD {} was registered despite response status {}".format(ftdv_name, r.status_code))
            return _success_response(req_body)
        return func.HttpResponse("Device Registration Failed",status_code=400) 
    return _success_response(req_body)
