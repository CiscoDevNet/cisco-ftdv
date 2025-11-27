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
from SharedCode import azure_utils as azutils
from azure.identity import ManagedIdentityCredential
from azure.mgmt.compute import ComputeManagementClient

fmc_ip = os.environ.get("FMC_IP")
domain_uuid = os.environ.get("FMC_DOMAIN_UUID")

def main(req: func.HttpRequest):
    dev_group_name = os.environ.get("DEVICE_GROUP_NAME")
    policy_name = os.environ.get("POLICY_NAME")
    fmc = FMC()
    gwlbSupport = os.environ.get("GWLB_SUPPORT")
    if gwlbSupport != "YES":
        fmc_inside_zone = os.environ.get("INSIDE_ZONE")

    fmc_outside_zone = os.environ.get("OUTSIDE_ZONE")
    # ---------------------------Get Policy ID by name------------------------------------------

    # Check if policy is present in FMC
    log.info("MinimumConfigVerification:::: Getting Access policy ID")
    policy_id = fmc.getAccessPolicyIdByName(policy_name)
    log.debug("Policy ID: %s" % policy_id)
    
    if policy_id == "ERROR":
        log.error("MinimumConfigVerification:::: Policy {} is not present in FMC".format(policy_name))
        return func.HttpResponse("ERROR: Policy NOT Present in FMC",status_code=400)
    
    log.info("MinimumConfigVerification:::: Found Policy({}) ID : {} ".format(policy_name, policy_id))

    if gwlbSupport != "YES":
        in_zone_id = fmc.getDevIdByName(fmc_inside_zone, "ZONE")
        log.debug("MinimumConfigVerification:::: Inside Zone ID: {}".format(in_zone_id))
        if in_zone_id == "ERROR":
            log.error("MinimumConfigVerification:::: Failed to get inside zone Id")
            return func.HttpResponse("ERROR : Failed get  inside zone Id",status_code=400)
    
        log.info("MinimumConfigVerification:::: inside zone ID : {}".format(in_zone_id))

    out_zone_id = fmc.getDevIdByName(fmc_outside_zone, "ZONE")
    log.debug("MinimumConfigVerification:::: Outside Zone ID: {}".format(out_zone_id))
    if out_zone_id == "ERROR":
        log.error("MinimumConfigVerification:::: Failed to get outside zone Id")
        return func.HttpResponse("ERROR : Failed get  outside zone Id",status_code=400)
    
    log.info("MinimumConfigVerification:::: outside zone ID : {}".format(out_zone_id))

    collect_garbage = os.environ.get("GARBAGE_COLLECTOR")
    if collect_garbage == "ON":
        log.warning("MinimumConfigVerification:::: Garbage collector is ON, detecting orphan FTDs in Azure")
        
        vmss = azutils.get_vmss_vm_list()
        log.warning("MinimumConfigVerification:::: FTD count : {}".format(len(vmss)))

        if len(vmss) != 0:
            for vm in vmss:
                log.info("MinimumConfigVerification:::: Check if {} is present in FMC".format(vm.name))

                if fmc.getDevIdByName(vm.name, "FTD") == "ERROR":
                    log.warning("MinimumConfigVerification:::: FTD {} is only present in Azure and not present in FMC...Deleting it".format(vm.name))
                    operation_delay = 30  # 30sec
                    delay = azutils.vmss_vm_delete(vm.instance_id)
                    time.sleep(operation_delay)
                    log.warning("MinimumConfigVerification:::: Deleted FTD {}".format(vm.name))
                    return func.HttpResponse("DELETED Garbage FTD", status_code=400) 

        log.warning("MinimumConfigVerification:::: Considering Garbage collector is OFF..")

    return func.HttpResponse("SUCCESS", status_code=200) 
