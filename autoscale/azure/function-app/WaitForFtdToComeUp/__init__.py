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
Purpose:    This python file is used for waiting until an FTD instance is ready.
"""

import os
import logging as log
import azure.functions as func
from SharedCode.Utils import FtdSshClient, getFtdSshIps, getInstanceNatId

def main(req: func.HttpRequest):
    req_body = req.get_json()
    ftdv_name = req_body.get('ftdDevName')
    ftdv_ssh_ips = getFtdSshIps(req_body)

    set_unique_host_name = os.environ.get("SET_UNIQUE_HOST_NAME")
    reg_key = os.environ.get("REG_KEY")
    nat_id = getInstanceNatId(os.environ.get("NAT_ID"), ftdv_name)
    manager_host = os.environ.get("FTD_MANAGER_HOST") or "DONTRESOLVE"
    ftd_ssh_client = FtdSshClient()
    for ftdv_ssh_ip in ftdv_ssh_ips:
        res = ftd_ssh_client.ftdSsh(ftdv_ssh_ip, "Pending")
        if res == "AVAILABLE":
            log.info("Configuring FTD manager for {} via {} with host {} and per-instance NAT ID {}".format(ftdv_name, ftdv_ssh_ip, manager_host, nat_id))
            manager_status = ftd_ssh_client.ftdSshConfigureManager(ftdv_ssh_ip, manager_host, reg_key, nat_id)
            if manager_status not in ("SUCCESS", "PENDING"):
                return func.HttpResponse("WAITING",status_code=200)
            if set_unique_host_name == "YES":
                log.info("FTDv up and running {}".format(ftdv_name))
                log.info("Setting host name to {}".format(ftdv_name))
                ftd_ssh_client.ftdSshSetHostName(ftdv_ssh_ip, ftdv_name)
            return func.HttpResponse("READY",status_code=200)

    return func.HttpResponse("WAITING",status_code=200)
