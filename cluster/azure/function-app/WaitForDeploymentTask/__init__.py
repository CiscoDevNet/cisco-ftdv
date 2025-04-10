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
Purpose:    This python file is used for checking the fmcv device deployment completion.
"""

import os
import azure.functions as func
import logging as log
import time
from SharedCode.Utils import FMC, FtdSshClient
from SharedCode.cluster_utils import ClusterUtils


fmc_ip = os.environ.get("FMC_IP")
domain_uuid = os.environ.get("FMC_DOMAIN_UUID")

def main(req: func.HttpRequest):

    fmc = FMC()
    fmc_inside_nic = os.environ.get("INSIDE_NIC_INTERFACE")

    req_body = req.get_json()
    ftdv_name = req_body.get('ftdDevName')
    ftdv_public_ip = req_body.get('ftdPublicIp')
    ftdv_port_number = 22
    ftdv_username = os.environ.get("FTD_USERNAME")
    ftdv_password = os.environ.get("FTD_PASSWORD")

    log.info("WaitForDeploymentTask:::: Deployment task for the ftdv : {}".format(ftdv_name))

    # --------- Checking if the ftdv device is a data node ------------------------------------
    ftdv = ClusterUtils(ftdv_public_ip, ftdv_port_number, ftdv_username, ftdv_password)
    cluster_info_status, cluster_info = ftdv.get_cluster_info()
    if cluster_info_status == "SUCCESS":
        if ftdv.is_control_node(cluster_info):
            log.info("WaitForDeploymentTask:::: FTDv {} is a control node".format(ftdv_public_ip))
            cluster_node = "CONTROL_NODE"
        else:
            log.info("WaitForDeploymentTask:::: FTDv {} is a data node".format(ftdv_public_ip))
            cluster_node = "DATA_NODE"

    if cluster_node == "DATA_NODE":
        log.info("WaitForDeploymentTask::: FTDv {} is a data node. Skipping the WaitForDeploymentTask Step".format(ftdv_public_ip))
        return func.HttpResponse("COMPLETED", status_code=200)   


    log.warning("WaitForDeploymentTask:::: Waiting till Deployment task is finished for {}".format(ftdv_name))
    log.warning("WaitForDeploymentTask:::: Checking Deployment state")

    device_id = fmc.getDevIdByName(ftdv_public_ip, "FTD")
    if device_id == "ERROR":
        log.warning("WaitForDeploymentTask:::: FTD {} {} still not registered in FMC.. waiting".format(ftdv_name,ftdv_public_ip))
        return func.HttpResponse("INPROGRESS",status_code=200) 
    
    inside_nic_id = fmc.getDevIdByName(fmc_inside_nic, "NIC", device_id)
    if inside_nic_id == "ERROR":
        log.warning("WaitForDeploymentTask:::: FTD {}:{} still not registered in FMC.. waiting".format(ftdv_name,ftdv_public_ip))
        return func.HttpResponse("INPROGRESS",status_code=200) 
    
    ftd_ssh_client = FtdSshClient() 
    res = ftd_ssh_client.ftdSsh(ftdv_public_ip, "Completed")

    if res != "AVAILABLE":
        return func.HttpResponse("INPROGRESS",status_code=200) 
    
    url = "https://" + fmc_ip + "/api/fmc_config/v1/domain/" + domain_uuid + "/deployment/deployabledevices"
    r = fmc.rest_get(url)
    if not (200 <= r.status_code <= 300):
        log.error("WaitForDeploymentTask:::: Failed deployable device list (Status Code : {}".format(r.status_code))
        return func.HttpResponse("ERROR : Failed deployable device list",status_code=400)
    
    log.info("WaitForDeploymentTask:::: Successfully got Response for deployment status ")
    try:
        for item in r.json()["items"]:
            if str(item["type"]) == "DeployableDevice" and str(item["name"]) == ftdv_public_ip:
                log.info("WaitForDeploymentTask:::: Deployment is still in progress for {}:{}".format(ftdv_name,ftdv_public_ip))
                return func.HttpResponse("INPROGRESS",status_code=200) 
    except:
        log.info("WaitForDeploymentTask:::: Deployment completed for {}:{}".format(ftdv_name,ftdv_public_ip))
        return func.HttpResponse("COMPLETED",status_code=200) 
    
    log.info("WaitForDeploymentTask:::: Deployment completed for {}:{}".format(ftdv_name,ftdv_public_ip))
    return func.HttpResponse("COMPLETED",status_code=200) 