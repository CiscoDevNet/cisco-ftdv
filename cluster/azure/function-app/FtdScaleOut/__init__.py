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
Purpose:    This python file is used for scale-out operation.
"""

import os
import time
import logging as log
import azure.functions as func
from SharedCode import azure_utils as azutils



def main(req: func.HttpRequest):
    operationDelay = 60
    resourceGroupName = os.environ.get("RESOURCE_GROUP_NAME")
    vmScalesetName = os.environ.get("VMSS_NAME")

    req_body = req.get_json()
    COUNT = req_body.get('COUNT')
    ftdCountInt = int(COUNT)
    
    log.info("FtdScaleOut:::: count {} ".format(COUNT))
    log.info("FtdScaleOut:::: FTD ScaleOut Started (RG : {}, VMSS: {}, Count: {}".format(resourceGroupName, vmScalesetName, COUNT))

    vMachineScaleSet = azutils.get_vmss_obj()
    vm_count_before_scale_out = vMachineScaleSet.sku.capacity
    log.info("FtdScaleOut:::: Current VMSS Capacity : {}".format(vMachineScaleSet.sku.capacity))

    update = azutils.vmss_create_or_update(location = vMachineScaleSet.location, overprovision = "false", name = vMachineScaleSet.sku.name, tier = vMachineScaleSet.sku.tier, capacity = (vMachineScaleSet.sku.capacity + ftdCountInt))

    ##  update status from creat_update pending ##
    log.info("FtdScaleOut:::: FTD Scale Out Started... Please wait")
    update.wait(operationDelay)
    log.info("FtdScaleOut:::: FTD Scale Out Status : {}".format(update.status()))

    if update.status() != "InProgress":
        log.info("FtdScaleOut:::: ScaleOut Operation failed (Status : {})".format(update.status()))
        log.error("ERROR: ScaleOut Operation failed")
        return func.HttpResponse("ERROR", status_code=400) 

    vMachineScaleSet = azutils.get_vmss_obj()
    vm_count_after_scale_out = vMachineScaleSet.sku.capacity
    log.info("FtdScaleOut:::: VMSS Instance count after Scale-Out : {}".format(vMachineScaleSet.sku.capacity))

    if vm_count_after_scale_out <= vm_count_before_scale_out:
        log.info("FtdScaleOut:: VM count is not incremented even after the scale-out operation")
        return func.HttpResponser("ERROR", status_code=400)

    log.warning("FtdScaleOut:::: Post ScaleOut VMSS Capacity : {}".format(vMachineScaleSet.sku.capacity))
    return func.HttpResponse("SUCCESS", status_code=200)
