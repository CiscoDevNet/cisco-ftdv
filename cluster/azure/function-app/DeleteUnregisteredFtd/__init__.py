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
Purpose:    This python file is used for deleting the unhealthy FTDv from Azure Scale set.
"""

import os
import logging as log
import time
import azure.functions as func
from SharedCode.Utils import FMC
from SharedCode import azure_utils as azutils
from SharedCode.cluster_utils import ClusterUtils

def main(req: func.HttpRequest):
    fmc = FMC()
    del_bad_ftd = os.environ.get("DELETE_FAULTY_FTD")

    if del_bad_ftd != "YES":
        log.error("DeleteUnRegisteredFTD:::: Feature to delete unregistered FTD is not enabled")
        return func.HttpResponse("SUCCESS" ,status_code=200)

    req_body = req.get_json()
    ftdv_name = req_body.get('ftdDevName')
    ftdv_public_ip = req_body.get('ftdPublicIp')
    ftdv_port_number = 22
    ftdv_username = os.environ.get("FTD_USERNAME")
    ftdv_password = os.environ.get("FTD_PASSWORD")
    log.warning("DeleteUnRegisteredFTD:::: Checking if {}:{} is registered to FMC".format(ftdv_name,ftdv_public_ip))

    # --------- Checking if the ftdv device is a data node ------------------------------------
    ftdv = ClusterUtils(ftdv_public_ip, ftdv_port_number, ftdv_username, ftdv_password)
    cluster_info_status, cluster_info = ftdv.get_cluster_info()
    if cluster_info_status == "SUCCESS":
        if ftdv.is_control_node(cluster_info):
            log.info("DeleteUnRegisteredFTD:::: FTDv {} is a control node".format(ftdv_public_ip))
            cluster_node = "CONTROL_NODE"
        else:
            log.info("DeleteUnRegisteredFTD:::: FTDv {} is a data node".format(ftdv_public_ip))
            cluster_node = "DATA_NODE"

    if cluster_node == "DATA_NODE":
        log.info("DeleteUnRegisteredFTD::: FTDv {} is a data node. Skipping the WaitForDeploymentTask Step".format(ftdv_public_ip))
        time.sleep(60)
        return func.HttpResponse("SUCCESS", status_code=200)  

    ftd_id = fmc.getDevIdByName(ftdv_public_ip, "FTD")

    if ftd_id == "ERROR":
        log.error("DeleteUnRegisteredFTD:::: FTD {} is not registered to FMC.. Deleting it from Azure".format(ftdv_name))
        resource_group_name = os.environ.get("RESOURCE_GROUP_NAME")
        vm_scle_set_name = os.environ.get("VMSS_NAME")

        vmss = azutils.get_vmss_vm_list()
        for vm in vmss:
            if vm.name == ftdv_name:
                log.warning("DeleteUnRegisteredFTD:::: Found {} in Azure, Azure instance Id : {}".format(vm.name, vm.instance_id))
                operation_delay = 30000 # 30sec
                delay = azutils.vmss_vm_delete(vm.instance_id)
                delay.wait(operation_delay)
                log.warning("DeleteUnRegisteredFTD:::: Deleted FTD {}".format(vm.name))
                return func.HttpResponse("DELETED Unregistered FTD",status_code=400) 
        
        log.error("DeleteUnRegisteredFTD:::: Unable to find {} in Azure VMSS".format(ftdv_name))
        return func.HttpResponse("Unable to find this FTD in Azure",status_code=400)
    else:
        log.warning("DeleteUnRegisteredFTD:::: FTD {} is registered to FMC".format(ftdv_name))
    
    return func.HttpResponse("SUCCESS" ,status_code=200)
