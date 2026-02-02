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
Purpose:    This python file is used for checking whether the ssh for the ftdv is working
"""

import os
import logging as log
import azure.functions as func
from SharedCode.Utils import FtdSshClient

def main(req: func.HttpRequest):
    try:
        req_body = req.get_json()
    except ValueError as e:
        log.error("WaitForFtdToComeUp:: Invalid JSON in request: {}".format(str(e)))
        return func.HttpResponse("ERROR: Invalid JSON in request", status_code=400)

    log.info("WaitForFtdToComeUp:: JSON Input : {}".format(req_body))
    
    if not req_body:
        log.error("WaitForFtdToComeUp:: Empty request body")
        return func.HttpResponse("ERROR: Empty request body", status_code=400)
    
    ftdv_name = req_body.get('ftdDevName')
    ftdv_public_ip = req_body.get('ftdPublicIp')
    
    if not ftdv_name or not ftdv_public_ip:
        log.error("WaitForFtdToComeUp:: Missing required fields. ftdDevName: {}, ftdPublicIp: {}".format(ftdv_name, ftdv_public_ip))
        return func.HttpResponse("ERROR: Missing required fields (ftdDevName or ftdPublicIp)", status_code=400)

    set_unique_host_name = os.environ.get("SET_UNIQUE_HOST_NAME")
    ftd_ssh_client = FtdSshClient()
    res = ftd_ssh_client.ftdSsh(ftdv_public_ip, "Pending")
    if res == "AVAILABLE":
        if set_unique_host_name == "YES":
            log.info("FTDv up and running {}".format(ftdv_name))
            log.info("Setting host name to {}".format(ftdv_name))
            ftd_ssh_client.ftdSshSetHostName(ftdv_public_ip, ftdv_name)

                    
        # TEMPORARY WORKAROUND: Ping CCL to populate ARP table for cluster join
        # This fixes the issue where newly deployed nodes don't have ARP entry for control node
        # New approach: Get this FTD's CCL IP, then ping it from all other VMSS instances
        
        ccl_interface_name = os.environ.get("CCL_NIC_INTERFACE")
        if ccl_interface_name:
            log.info("WaitForFtdToComeUp:: Starting CCL ARP population from other nodes")
            status, message = ftd_ssh_client.ftdSshPingCclFromOtherNodes(ftdv_public_ip, ccl_interface_name)
            if status == "SUCCESS":
                log.info("WaitForFtdToComeUp:: Successfully populated ARP table. Details: {}".format(message))
            else:
                log.warning("WaitForFtdToComeUp:: Failed to populate ARP table from other nodes. Details: {}".format(message))
        else:
            log.warning("WaitForFtdToComeUp:: CCL_INTERFACE_NAME not found in environment variables")
        
        return func.HttpResponse("READY",status_code=200)

    return func.HttpResponse("WAITING",status_code=200)
