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
Purpose:    This python file is used for waiting on FMC deployment tasks.
"""

import os
import azure.functions as func
from SharedCode.Utils import FMC, getFtdDeviceId, getFtdIdentityCandidates, validateFtdInterfaceDeployment
import logging as log

fmc_ip = os.environ.get("FMC_IP")
domain_uuid = os.environ.get("FMC_DOMAIN_UUID")
fmc_outside_nic_name = os.environ.get("OUTSIDE_NIC_NAME")
outside_azure_nic_name = os.environ.get("OUTSIDE_AZURE_NIC_NAME") or "outsideNic"


def _deployment_completed_response(fmc, device_id, req_body, ftdv_name):
    if req_body.get("VALIDATE_INTERFACE") != "YES":
        log.info("WaitForDeploymentTask:::: Deployment completed for {}".format(ftdv_name))
        return func.HttpResponse("COMPLETED",status_code=200)

    validation_status = validateFtdInterfaceDeployment(
        fmc, device_id, req_body, outside_azure_nic_name, fmc_outside_nic_name
    )
    if validation_status != "SUCCESS":
        log.error("WaitForDeploymentTask:::: Interface validation failed for {}".format(ftdv_name))
        return func.HttpResponse("ERROR : Interface validation failed", status_code=409)

    log.info("WaitForDeploymentTask:::: Deployment completed for {}".format(ftdv_name))
    return func.HttpResponse("COMPLETED",status_code=200)


def _get_request_devices(req_body):
    if isinstance(req_body, list):
        return req_body, "NO"
    if isinstance(req_body, dict) and isinstance(req_body.get("devices"), list):
        return req_body.get("devices"), req_body.get("VALIDATE_INTERFACE")
    return [req_body], req_body.get("VALIDATE_INTERFACE")


def main(req: func.HttpRequest):

    fmc = FMC()

    req_body = req.get_json()
    req_devices, validate_interface = _get_request_devices(req_body)
    ftdv_names = [req_device.get("ftdDevName") for req_device in req_devices]

    log.warning("WaitForDeploymentTask:::: Waiting till Deployment task is finished for {}".format(ftdv_names))
    log.warning("WaitForDeploymentTask:::: Checking Deployment state")

    device_ids = []
    ftd_identity_candidates = []
    for req_device in req_devices:
        ftdv_name = req_device.get("ftdDevName")
        device_id = getFtdDeviceId(fmc, req_device)
        if device_id == "ERROR":
            log.warning("WaitForDeploymentTask:::: FTD {} still not registered in FMC.. waiting".format(ftdv_name))
            return func.HttpResponse("INPROGRESS",status_code=200)
        device_ids.append(device_id)
        for candidate in getFtdIdentityCandidates(req_device):
            if candidate not in ftd_identity_candidates:
                ftd_identity_candidates.append(candidate)

    url = "https://" + fmc_ip + "/api/fmc_config/v1/domain/" + domain_uuid + "/deployment/deployabledevices"
    r = fmc.rest_get(url)
    if not (200 <= r.status_code <= 300):
        log.error("WaitForDeploymentTask:::: Failed deployable device list (Status Code : {}".format(r.status_code))
        return func.HttpResponse("ERROR : Failed deployable device list",status_code=400)
    
    log.info("WaitForDeploymentTask:::: Successfully got Response for deployment status ")
    try:
        for item in r.json()["items"]:
            if str(item["type"]) == "DeployableDevice" and (
                str(item.get("name")) in ftd_identity_candidates or item.get("id") in device_ids
            ):
                log.info("WaitForDeploymentTask:::: Deployment is still in progress for {}".format(ftdv_names))
                return func.HttpResponse("INPROGRESS",status_code=200)
    except:
        pass

    if validate_interface == "YES":
        for device_id, req_device in zip(device_ids, req_devices):
            validation_status = validateFtdInterfaceDeployment(
                fmc, device_id, req_device, outside_azure_nic_name, fmc_outside_nic_name
            )
            if validation_status != "SUCCESS":
                log.error("WaitForDeploymentTask:::: Interface validation failed for {}".format(req_device.get("ftdDevName")))
                return func.HttpResponse("ERROR : Interface validation failed", status_code=409)

    log.info("WaitForDeploymentTask:::: Deployment completed for {}".format(ftdv_names))
    return func.HttpResponse("COMPLETED",status_code=200)
