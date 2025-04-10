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
Purpose:    This python file is used for unregistering the FTDv instance from the FMC.
"""

import logging as log
import os
import azure.functions as func
from SharedCode.Utils import FMC


fmc_ip = os.environ.get("FMC_IP")
domain_uuid = os.environ.get("FMC_DOMAIN_UUID")

def main(req: func.HttpRequest):
    fmc = FMC()
    
    fmc_registration_url = "https://" + fmc_ip + "/api/fmc_config/v1/domain/" + domain_uuid + "/devices/devicerecords"
    req_body = req.get_json()
    ftdv_name = req_body.get('ftdDevName')
    ftdv_public_ip = req_body.get('ftdPublicIp')
    log.warning("DeviceDeRegister:::: Received Request to De-Register FTD from FMC")
    log.info("DeviceDeRegister:::: FTD Public IP : {}".format(ftdv_public_ip))
    log.info("DeviceDeRegister:::: FTD Name : {}".format(ftdv_name))

    # ---------------------------Get Device ID by name------------------------------------------
    log.info("DeviceDeRegister:::: Getting FTD Device ID by name")
    dev_id = fmc.getDevIdByName(ftdv_public_ip, "FTD")
    if dev_id == "ERROR":
        log.error("DeviceDeRegister:::: Failed to get Device ID")
        return func.HttpResponse("Unable to get Device ID",status_code=400)
    
    # ---------------------------De-Register FTD------------------------------------------
    # Orchestrator will retry if this fails
    log.info("DeviceDeRegister:::: De-Registering FTD")
    fmc_deregister_url = fmc_registration_url + "/" + dev_id
    r = fmc.rest_delete(fmc_deregister_url)
    if not (200 <= r.status_code <= 300):
        log.error("DeviceDeRegister:::: DeRegistration failed")
        return func.HttpResponse("DeRegistration failed",status_code=400)
    
    log.info("DeviceDeRegister:::: De-Registeration Status : {}".format(r.content))
    return func.HttpResponse("SUCCESS", status_code=200) 