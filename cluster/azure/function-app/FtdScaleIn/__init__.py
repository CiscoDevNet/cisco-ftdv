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
Purpose:    This python file is used for the scale-in operation.
"""

import os
import time
import logging as log
import azure.functions as func
from SharedCode import azure_utils as azutils
from SharedCode.cluster_utils import ClusterUtils

def main(req: func.HttpRequest):
    operationDelay = 90 
    resourceGroupName = os.environ.get("RESOURCE_GROUP_NAME")
    vmScalesetName = os.environ.get("VMSS_NAME")
    
    req_body = req.get_json()
    instanceid = req_body.get("instanceid")
    ftdv_public_ip = req_body.get("ftdPublicIp")
    ftdv_username = os.environ.get("FTD_USERNAME")
    ftdv_password = os.environ.get("FTD_PASSWORD")
    ftdv_port_number = 22

    if instanceid == None:
        log.info("FtdScaleIn:: Invalid FTD Instance Id for ScaleIn")
        log.error("ERROR: Invalid FTD Instance Id for ScaleIn")
        return func.HttpResponse("ERROR",status_code=400)

    log.info("FtdScaleIn:: FTD Scale-In Started RG : {}, VMSS: {}, FTD InstanceId to Delete: {} ".format(resourceGroupName, vmScalesetName, instanceid))

    #Disabling the cluster on the node
    log.info("FtdScaleIn:: Disabling cluster on the FTDv : {}".format(ftdv_public_ip))
    ftdv = ClusterUtils(ftdv_public_ip, ftdv_port_number, ftdv_username, ftdv_password)
    status, msg = ftdv.disable_cluster()
    log.info("FtdScaleIn:: Cluster Disable Status : {} Message : {}".format(status,msg))

    vMachineScaleSet = azutils.get_vmss_obj()

    vmssCapacity = vMachineScaleSet.sku.capacity
    log.info("FtdScaleIn:: Current VMSS Capacity : {}".format(vmssCapacity))

    
    delete = azutils.vmss_vm_delete(instanceid)
    
    time.sleep(operationDelay)
	
	## check delete status	

    vMachineScaleSet = azutils.get_vmss_obj()
    log.info("FtdScaleIn:::: Post ScaleIn VMSS Capacity : {}".format(vMachineScaleSet.sku.capacity))

    if (vMachineScaleSet.sku.capacity != (vmssCapacity - 1)):
        log.error("FtdScaleIn:::: Failed ScaleIn Operation (vmss capacity: {})".format(vMachineScaleSet.sku.capacity))
        log.error("ERROR: Failed ScaleIn Operation. Don't worry, Azure may be taking longer time to delete, but eventually it may delete")
        return func.HttpResponse("ERROR",status_code=400)
    
    return func.HttpResponse("SUCCESS",status_code=200)
