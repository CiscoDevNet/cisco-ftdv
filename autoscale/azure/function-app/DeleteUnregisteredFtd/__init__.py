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
Purpose:    This python file is used for handling unregistered FTD cleanup.
"""

import os
import logging as log
import azure.functions as func
from SharedCode.Utils import FMC, getFtdDeviceId

def main(req: func.HttpRequest):
    fmc = FMC()
    del_bad_ftd = os.environ.get("DELETE_FAULTY_FTD")

    req_body = req.get_json()
    ftdv_name = req_body.get('ftdDevName')

    log.warning("DeleteUnRegisteredFTD:::: Checking if {} is registered to FMC".format(ftdv_name))
    log.info("DeleteUnRegisteredFTD:::: Delete faulty FTD setting: {}".format(del_bad_ftd))

    ftd_id = getFtdDeviceId(fmc, req_body)
    if ftd_id == "ERROR":
        log.warning(
            "DeleteUnRegisteredFTD:::: FTD {} is not visible in FMC yet; stopping configuration".format(ftdv_name)
        )
        return func.HttpResponse("FTD registration is not visible in FMC", status_code=409)
    else:
        log.warning("DeleteUnRegisteredFTD:::: FTD {} is registered to FMC".format(ftdv_name))
    
    return func.HttpResponse("SUCCESS" ,status_code=200)
