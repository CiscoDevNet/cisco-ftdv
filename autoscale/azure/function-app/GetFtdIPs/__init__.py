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
Purpose:    This python file is used for retrieving FTD instance IP addresses.
"""

import os
import time
import logging as log
import json
import azure.functions as func
from SharedCode import azure_utils as azutils


def _vmss_instance_id_from_resource_id(resource_id):
    resource_id_parts = resource_id.split("/")
    try:
        return resource_id_parts[resource_id_parts.index("virtualMachines") + 1]
    except (ValueError, IndexError):
        return ""


def _get_private_ip(interface_list, network_interface_name, vmindex):
    for interface in interface_list:
        if interface.name != network_interface_name:
            continue

        intf_id = interface.ip_configurations[0].id
        current_vm_index = _vmss_instance_id_from_resource_id(intf_id)
        if current_vm_index == vmindex:
            private_ip = interface.ip_configurations[0].private_ip_address
            log.info("GetFtdIPs:::: Private IP of New FTD (VM index {}) = {}".format(vmindex, private_ip))
            return private_ip

    return ""


def _build_ftd_ip_response(vmindex, vm_name, interface_list, network_interface_name, ip_configuration_name, public_ip_address_name):
    try:
        public_ip = azutils.get_vmss_public_ip(vmindex, network_interface_name, ip_configuration_name, public_ip_address_name)
    except Exception as e:
        log.error("GetFtdIPs:::: Unable to get Public IP of new FTD (index {}): {}".format(vmindex, repr(e)))
        raise

    if public_ip is None:
        raise ValueError("Public IP is empty for VM index {}".format(vmindex))

    log.info("GetFtdIPs:::: Public IP of New FTD (VM index {}) = {}".format(vmindex, public_ip))

    private_ip = _get_private_ip(interface_list, network_interface_name, vmindex)
    if private_ip == "":
        raise ValueError("Unable to get Private IP for VM index {}".format(vmindex))

    return {
        "ftdDevName": vm_name,
        "ftdPublicIp": public_ip,
        "ftdPrivateIp": private_ip,
    }


def main(req: func.HttpRequest):
    resourceGroupName = os.environ.get("RESOURCE_GROUP_NAME")
    vmScalesetName = os.environ.get("VMSS_NAME")
    networkInterfaceName = os.environ.get("MNGT_NET_INTERFACE_NAME")
    ipConfigurationName = os.environ.get("MNGT_IP_CONFIG_NAME")
    publicIpAddressName = os.environ.get("MNGT_PUBLIC_IP_NAME")

    req_body = req.get_json()
    COUNT = req_body.get('COUNT')
    TYPE = req_body.get('TYPE')
    MODE = req_body.get('MODE')

    ftdCountInt = int(COUNT)
    index = 1

    if(TYPE == "REGULAR"):
        log.warning("GetFtdIPs:::: This is regular scale-out ") 
    elif(TYPE == "INIT"):
        log.warning("GetFtdIPs:::: This is initial deployment")
    else:
        log.error("ERROR: Invalid request TYPE")
        return func.HttpResponse("ERROR: Invalid request TYPE",status_code=400)

    log.warning("GetFtdIPs:::: Getting Public IP of new FTD (RG : {}, VMSS: {} )".format(resourceGroupName, vmScalesetName))
    log.info("GetFtdIPs:::: Network Interface name : {}, IP Configuration Name : {}, Public IP Address Name : {}".format(networkInterfaceName, ipConfigurationName, publicIpAddressName))

    vmlist = list(azutils.get_vmss_vm_list())
    vm_by_instance_id = {}
    for vm in vmlist:
        instance_id = getattr(vm, "instance_id", None)
        if instance_id is None:
            vm_id_parts = (getattr(vm, "id", "") or "").split("/")
            instance_id = vm_id_parts[-1] if vm_id_parts else None
        if instance_id is not None:
            vm_by_instance_id[str(instance_id)] = vm

    interfaceList = list(azutils.get_vmss_intf_list())
    candidates = []
    # only for Mgmt Interface
    for interface in interfaceList:
        if interface.name == networkInterfaceName:
            intfID = interface.ip_configurations[0].id  #config id
            currentVmIndex = _vmss_instance_id_from_resource_id(intfID)
            if currentVmIndex == "":
                log.error("GetFtdIPs:::: Unable to parse VM index from interface id {}".format(intfID))
                continue

            vmStatus = "ON"
            currentVmName = "ERROR"

            v = vm_by_instance_id.get(str(currentVmIndex))
            if v is not None:
                status_codes = [
                    status.code for status in getattr(getattr(v, "instance_view", None), "statuses", [])
                    if getattr(status, "code", None)
                ]
                if status_codes and "PowerState/running" not in status_codes:
                    vmStatus = "OFF"
                if v.name != None:
                    currentVmName = v.name
                else:
                    currentVmName = "{}_{}".format(vmScalesetName, currentVmIndex)

            if vmStatus == "OFF":
                log.error("GetFtdIPs:::: VM index :{} is in unknown state..skip".format(currentVmIndex))
                continue

            if currentVmName == "ERROR":
                log.error("GetFtdIPs:::: VM index :{} VM name not found...skip".format(currentVmIndex))
                continue

            candidates.append((int(currentVmIndex), currentVmIndex, currentVmName))

    if not candidates:
        log.error("GetFtdIPs:::: No valid VM found")
        return func.HttpResponse(
            "ERROR: No valid VM found; mgmtNic={}, vmIds={}, interfaceIds={}".format(
                networkInterfaceName,
                sorted(vm_by_instance_id.keys()),
                [interface.ip_configurations[0].id for interface in interfaceList if interface.name == networkInterfaceName],
            ),
            status_code=400,
        )

    if TYPE == "INIT":
        ordered_candidates = sorted(candidates, key=lambda item: item[0])
    else:
        ordered_candidates = sorted(candidates, key=lambda item: item[0], reverse=True)

    if MODE == "BATCH":
        selected_candidates = ordered_candidates[:ftdCountInt]
        ftd_ip_responses = []
        for _, vmindex, vmName in selected_candidates:
            try:
                ftd_ip_responses.append(
                    _build_ftd_ip_response(
                        vmindex, vmName, interfaceList, networkInterfaceName, ipConfigurationName, publicIpAddressName
                    )
                )
            except Exception as e:
                return func.HttpResponse("ERROR: Unable to get IPs for VM index {}: {}".format(vmindex, repr(e)), status_code=400)

        return func.HttpResponse(json.dumps(ftd_ip_responses), status_code=200, mimetype="application/json")

    if TYPE == "INIT":
        if ftdCountInt > len(ordered_candidates):
            return func.HttpResponse("ERROR: No valid VM found for count {}".format(ftdCountInt), status_code=400)
        _, vmindex, vmName = ordered_candidates[ftdCountInt - 1]
    else:
        _, vmindex, vmName = ordered_candidates[0]

    try:
        ftd_ip_response = _build_ftd_ip_response(
            vmindex, vmName, interfaceList, networkInterfaceName, ipConfigurationName, publicIpAddressName
        )
    except Exception as e:
        return func.HttpResponse("ERROR: Unable to get IPs for VM index {}: {}".format(vmindex, repr(e)), status_code=400)

    return func.HttpResponse(json.dumps(ftd_ip_response), status_code=200, mimetype="application/json")
