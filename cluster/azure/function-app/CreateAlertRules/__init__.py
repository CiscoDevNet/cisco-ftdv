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
Purpose:    This python file is used for creating the alert rules.
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

    prefixName = os.environ.get('RESOURCE_PREFIX_NAME')
    log.info("prefix name: {}".format(prefixName))
    req_body = req.get_json()
    ftdv_name = req_body.get('ftdDevName')
    vmss = azutils.get_vmss_vm_list()
    for vm in vmss:
        if vm.name == ftdv_name:
            vmIndex = vm.instance_id
            log.info("instance ID: {}".format(vmIndex))
            break

    outsideInterfaceName = "outsideNic"
    insideInterfaceName = "insideNic"

    try:
        interfaces = azutils.get_vmss_intf_list()
        for intf in interfaces:
            if intf.name == outsideInterfaceName and intf.id.split("/")[10] == vmIndex:
                outside_ip = intf.ip_configurations[0].private_ip_address
            if intf.name == insideInterfaceName and intf.id.split("/")[10] == vmIndex:
                inside_ip = intf.ip_configurations[0].private_ip_address
    except:
        log.error("CreateAlertRule:::: Unable to get the interface ips")
        return func.HttpResponse("Unable to get the interface ips",status_code=400)
    
    log.info("outside ip: {}".format(outside_ip))
    log.info("inside ip: {}".format(inside_ip))
    try:
        action_group_name = prefixName+"-action-group"
        action_group_short_name = prefixName+"ag"
        ilb_name = prefixName+"-ilb"
        elb_name = prefixName+"-elb"
        try:
            action_group = azutils.get_action_group(action_group_name)
            log.info("CreateAlertRule:::: Action Group {} already exits".format(action_group_name))
        except:
            log.info("CreateAlertRule:::: Action Group {} does not exit. Creating one".format(action_group_name))
            action_group = azutils.create_action_group(action_group_name,action_group_short_name)
        alert_rule1 = azutils.create_alert_rule(ilb_name, inside_ip, "ilb-"+ftdv_name, action_group_name)
        log.info("Alert Rule 1: {}".format(alert_rule1))
        alert_rule2 = azutils.create_alert_rule(elb_name, outside_ip, "elb-"+ftdv_name, action_group_name) 
        log.info("Alert Rule 2: {}".format(alert_rule2))
    except:
        log.error("CreateAlertRule:::: Failed to create Alert Rules")
        return func.HttpResponse("Faled to create Alert Rules", status_code=400)

    log.info("CreateAlertRule:::: Successfully created alert rules")
    return func.HttpResponse("SUCCESS", status_code=200)

