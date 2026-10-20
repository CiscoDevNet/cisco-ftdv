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
Purpose:    This python file is used for deleting unhealthy FTD instances.
"""

import logging as log
import json
import requests
import os
import time
import azure.functions as func
from SharedCode import azure_utils as azutils
from SharedCode.Utils import FMC


def _get_fmc_device_record(fmc, fmc_ip, domain_uuid, device_name):
    url = "https://" + fmc_ip + "/api/fmc_config/v1/domain/" + domain_uuid + "/devices/devicerecords?expanded=true&limit=1000"
    r = fmc.rest_get(url)
    for item in r.json().get("items", []):
        if item.get("name") == device_name or item.get("hostName") == device_name:
            return item
    return None


def _is_ignorable_gwlb_idle_health(device_record):
    if not device_record:
        return False

    health_message = (device_record.get("healthMessage") or "").lower()
    return (
        device_record.get("healthStatus") == "red"
        and device_record.get("isConnected") is True
        and device_record.get("deploymentStatus") == "DEPLOYED"
        and "interface 'vni1' is not receiving any packets" in health_message
    )


def main(req: func.HttpRequest) -> func.HttpResponse:
    vmname = req.get_json()['data']['context']['name'].split('lb-')[1]
    log.info("name: {}".format(vmname))
    function_app_name = os.environ.get("FUNCTION_APP_NAME")
    resourceGroupName = os.environ.get("RESOURCE_GROUP_NAME")
    vmScalesetName = os.environ.get("VMSS_NAME")
    fmc_ip = os.environ.get("FMC_IP")
    domain_uuid = os.environ.get("FMC_DOMAIN_UUID")     
    gwlb_support = os.environ.get("GWLB_SUPPORT")
    vmss = azutils.get_vmss_vm_list()
    instance_id = None
    for vm in vmss:
        if vm.name == vmname:
            instance_id = vm.instance_id
            log.info("instance ID: {}".format(instance_id))
            break

    if instance_id != None:
        fmc = FMC()
        url = "https://" + fmc_ip + "/api/fmc_config/v1/domain/" + domain_uuid + "/devices/devicerecords"
        if gwlb_support == "YES":
            device_record = _get_fmc_device_record(fmc, fmc_ip, domain_uuid, vmname)
            if _is_ignorable_gwlb_idle_health(device_record):
                log.warning(
                    "DeleteUnhealthyFtd:::: Skipping delete for {}. FMC health red is only idle vni1 packet warning.".format(vmname)
                )
                return func.HttpResponse("SUCCESS", status_code=200)

        if gwlb_support == "YES":
            log.info("DeleteAlertRule:::: deleting the alert rule {}".format("gwlb-"+vmname))
            delete_alert_rule = azutils.delete_alert_rule("gwlb-"+vmname)
        else:
            # ---------------------------Delete Alert Rule---------------------------------------
            log.info("DeleteAlertRule:::: deleting the alert rule 1 {}".format("ilb-"+vmname))
            delete_alert_rule1 = azutils.delete_alert_rule("ilb-"+vmname)

            # ---------------------------Delete Alert Rule---------------------------------------
            log.info("DeleteAlertRule:::: deleting the alert rule 2 {}".format("elb-"+vmname))
            delete_alert_rule2 = azutils.delete_alert_rule("elb-"+vmname)

        # ---------------------------Get Device ID by name------------------------------------------
        log.info("DeviceDeRegister:::: Getting FTD Device ID by name")
        dev_id = fmc.getDevIdByName(vmname, "FTD")
        if dev_id == "ERROR":
            log.error("DeviceDeRegister:::: Failed to get Device ID")
            return func.HttpResponse("Unable to get Device Group ID",status_code=400)
        
        # ---------------------------De-Register FTD------------------------------------------
        # Orchestrator will retry if this fails
        log.info("DeviceDeRegister:::: De-Registering FTD")
        fmc_deregister_url = url + "/" + dev_id
        r = fmc.rest_delete(fmc_deregister_url)
        if not (200 <= r.status_code <= 300):
            log.error("DeviceDeRegister:::: DeRegistration failed")
            return func.HttpResponse("DeRegistration failed",status_code=400)

        log.info("DeviceDeRegister:::: DeRegistration Successful")

        # -----------------------------Delete Unhealthy Device----------------------------------
        log.info("FtdScaleIn:::: Device Deletion started")
        operationDelay = 90
        vmss = azutils.get_vmss_obj()
        vmssCapacity = vmss.sku.capacity
        log.info("FtdScaleIn:::: Current VMSS Capacity : {}".format(vmssCapacity))
        log.info("FtdScaleIn:::: FTD Scale-In Started RG : {}, VMSS: {}, FTD InstanceId to Delete: {} ".format(resourceGroupName, vmScalesetName, instance_id))
        
        delete = azutils.vmss_vm_delete(instance_id)
        time.sleep(operationDelay)
        
        ## check delete status	
        vmss = azutils.get_vmss_obj()
        log.info("FtdScaleIn:::: Post ScaleIn VMSS Capacity : {}".format(vmss.sku.capacity))

        if (vmss.sku.capacity != (vmssCapacity - 1)):
            log.error("FtdScaleIn:::: Failed ScaleIn Operation (vmss capacity: {})".format(vmss.sku.capacity))
            log.error("ERROR: Failed ScaleIn Operation. Don't worry, Azure may be taking longer time to delete, but eventually it may delete")
            return func.HttpResponse("ERROR",status_code=400)

        return func.HttpResponse("SUCCESS",status_code=200)
