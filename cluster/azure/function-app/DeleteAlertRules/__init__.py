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
Purpose:    This python file is used for deleting the alert rules.
"""

import logging as log
import os
import azure.functions as func
from SharedCode import azure_utils as azutils

def main(req: func.HttpRequest) -> func.HttpResponse:
    del_unhealthy_ftd = os.environ.get("DELETE_UNHEALTHY_FTD")

    if del_unhealthy_ftd != "YES":
        log.error("CreateAlertRules:::: Feature to delete unhealthy FTD is not enabled")
        return func.HttpResponse("SUCCESS" ,status_code=200)

    req_body = req.get_json()
    ftdv_name = req_body.get('ftdDevName')

    try:
        # ---------------------------Delete Alert Rule---------------------------------------
        log.info("DeleteAlertRule:::: deleting the alert rule 1 {}".format("ilb-"+ftdv_name))
        delete_alert_rule1 = azutils.delete_alert_rule("ilb-"+ftdv_name)

        # ---------------------------Delete Alert Rule---------------------------------------
        log.info("DeleteAlertRule:::: deleting the alert rule 2 {}".format("elb-"+ftdv_name))
        delete_alert_rule2 = azutils.delete_alert_rule("elb-"+ftdv_name)
    except:
        log.info("DeleteAlertRule:::: Failed to delete the alert rules")
        return func.HttpResponse("Failed to delete the alert rules", status_code=400)
    
    log.info("DeleteAlertRule:::: Failed to delete the alert rules")
    return func.HttpResponse("SUCCESS", status_code=200)
    