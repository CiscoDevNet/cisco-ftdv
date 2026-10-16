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
Purpose:    This python file is used for scaling out FTD instances.
"""

import os
import logging as log
import azure.functions as func
from SharedCode import azure_utils as azutils



def main(req: func.HttpRequest):
    resourceGroupName = os.environ.get("RESOURCE_GROUP_NAME")
    vmScalesetName = os.environ.get("VMSS_NAME")

    req_body = req.get_json()
    COUNT = req_body.get('COUNT')
    ftdCountInt = int(COUNT)
    

    log.info("FtdScaleOut:::: count {} ".format(COUNT))
    log.info("FtdScaleOut:::: FTD ScaleOut Started (RG : {}, VMSS: {}, Count: {}".format(resourceGroupName, vmScalesetName, COUNT))

    vMachineScaleSet = azutils.get_vmss_obj()
    log.info("FtdScaleOut:::: Current VMSS Capacity : {}".format(vMachineScaleSet.sku.capacity))

    update = azutils.vmss_create_or_update(location = vMachineScaleSet.location, overprovision = "false", name = vMachineScaleSet.sku.name, tier = vMachineScaleSet.sku.tier, capacity = (vMachineScaleSet.sku.capacity + ftdCountInt))

    log.info("FtdScaleOut:::: FTD Scale Out request submitted")
    log.info("FtdScaleOut:::: FTD Scale Out Status : {}".format(update.status()))
    return func.HttpResponse("SCALEOUT_STARTED", status_code=202)
