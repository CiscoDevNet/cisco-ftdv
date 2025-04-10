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
    req_body = req.get_json()
    log.info("WaitForFtdToComeUp:: JSON Input : {}".format(req_body))
    ftdv_name = req_body.get('ftdDevName')
    ftdv_public_ip = req_body.get('ftdPublicIp')

    set_unique_host_name = os.environ.get("SET_UNIQUE_HOST_NAME")
    ftd_ssh_client = FtdSshClient()
    res = ftd_ssh_client.ftdSsh(ftdv_public_ip, "Pending")
    if res == "AVAILABLE":
        if set_unique_host_name == "YES":
            log.info("FTDv up and running {}".format(ftdv_name))
            log.info("Setting host name to {}".format(ftdv_name))
            ftd_ssh_client.ftdSshSetHostName(ftdv_public_ip, ftdv_name)
        return func.HttpResponse("READY",status_code=200)

    return func.HttpResponse("WAITING",status_code=200)