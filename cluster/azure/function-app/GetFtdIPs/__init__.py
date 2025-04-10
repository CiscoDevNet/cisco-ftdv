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
Purpose:    This python file is used for fetching the FTDv instances IP addresses from VMSS.
"""

import os
import logging as log
import azure.functions as func
from SharedCode import azure_utils as azutils
from SharedCode.cluster_utils import ClusterUtils
    
def main(req: func.HttpRequest):
    resourceGroupName = os.environ.get("RESOURCE_GROUP_NAME")
    vmScalesetName = os.environ.get("VMSS_NAME")
    networkInterfaceName = os.environ.get("MNGT_NET_INTERFACE_NAME")
    ipConfigurationName = os.environ.get("MNGT_IP_CONFIG_NAME")
    publicIpAddressName = os.environ.get("MNGT_PUBLIC_IP_NAME")
    private_ip = ""
    req_body = req.get_json()
    COUNT = req_body.get('COUNT')
    TYPE = req_body.get('TYPE')

    ftdCountInt = int(COUNT)
    index = 1

    ftdv_username = os.environ.get("FTD_USERNAME")
    ftdv_password = os.environ.get("FTD_PASSWORD")
    ftdv_port_number = 22
    if(TYPE == "REGULAR"):
        log.warning("GetFtdIPs:: This is regular scale-out ") 
    elif(TYPE == "INIT"):
        log.warning("GetFtdIPs:: This is initial deployment")
        vmlist = azutils.get_vmss_vm_list()

        vm_details = []
        is_control_node_found = False
        for v in vmlist:
            vm = {}

            vmName = v.name
            publicIP = azutils.get_vmss_public_ip(v.instance_id, networkInterfaceName, ipConfigurationName, publicIpAddressName)
            if publicIP == None:
                log.error("GetControlNode:: Unable to get Public IP of new FTD (index {0}".format(v.instance_id))
                return func.HttpResponse("ERROR",status_code=400)
            
            vm["vm_index"] = v.instance_id
            vm["public_ip"] = publicIP
            vm["vm_name"] = vmName
            vm["private_ip"] = private_ip
            vm_details.append(vm)
        
        # Identifying the control node
        for vm in vm_details:
            log.info("GetFtdIPs:: Checking if {} is a control node..".format(vm["public_ip"]))
            ftdv = ClusterUtils(vm["public_ip"], ftdv_port_number, ftdv_username, ftdv_password)
            cluster_info_status, cluster_info = ftdv.get_cluster_info()

            if cluster_info_status == "SSH_FAILURE":
                log.info("GetFtdIPs:: Unable to establish the SSH connection. Skipping the device")
                continue

            log.info("GetFtdIPs:: Cluster Status : {} Cluster Info : {}".format(cluster_info_status, cluster_info))
            if cluster_info_status == "SUCCESS":
                if ftdv.is_control_node(cluster_info):
                    is_control_node_found = True
                    log.info("GetFtdIPs:: FTDv {} is a control node".format(vm["public_ip"]))
                    commandStr = "{ \"ftdDevName\": \"" + vm["vm_name"] + "\", \"ftdPublicIp\": \"" + vm["public_ip"] + "\", \"ftdPrivateIp\" : \"" + vm["private_ip"] + "\"  }"
                    return func.HttpResponse(commandStr, status_code=200)
                else:
                    log.info("GetFtdIPs:: FTDv {} is a data node".format(vm["public_ip"]))

        if is_control_node_found is False:
            log.error("GetFtdIPs:: Unable to find the control Node.")
            return func.HttpResponse("ERROR",status_code=400)

    else:
        log.error("ERROR: Invalid request TYPE")
        return func.HttpResponse("ERROR",status_code=400)

    log.warning("GetFtdIPs:: Getting Public IP of new FTD (RG : {}, VMSS: {} )".format(resourceGroupName, vmScalesetName))
    log.info("GetFtdIPs:: Network Interface name : {}, IP Configuration Name : {}, Public IP Address Name : {}".format(networkInterfaceName, ipConfigurationName, publicIpAddressName))
    
    tmpVmName = "ERROR"
    vmlist = azutils.get_vmss_vm_list()
    interfaceList = azutils.get_vmss_intf_list()
    vmindex = ""
    intVmindex = 0
    privateIP = ""
    log.info("GetFtdIPs:: Count : {}".format(COUNT))
    
    #only for Mgmt Interface
    for interface in interfaceList:
        if interface.name == networkInterfaceName:
            privateIP = interface.ip_configurations[0].private_ip_address
            intfID = interface.ip_configurations[0].id  #config id
            idList = intfID.split("/")

            vmindex = idList[10]

            vmStatus = "ON"

            for v in vmlist:
                #Added for get Control ip
                log.info("Vm details: {}".format(v))
                vmId = v.id
                vmName = v.name
                vmIdList = vmId.split("/")
                vmInstanceIndex = vmIdList[-1]
                #Added for get Control ip
                if vmInstanceIndex == vmindex:
                    if v.instance_view.statuses[1].code != "PowerState/running":
                        vmStatus = "OFF"
                    if v.name != None:
                        tmpVmName = v.name
                    break

            if (vmStatus == "OFF"):
                log.error("GetFtdIPs:::: VM index :{} is in unknown state..skip".format(vmindex))
                continue
            if tmpVmName == "ERROR":
                log.error("GetFtdIPs:::: VM index :{} VM name not found...skip".format(vmindex))
                continue
            if TYPE == "INIT":
                if ftdCountInt == index:
                    #Added for get control IP
                    log.info("Ftd type init ftdCountInt : {} index ; {}".format(ftdCountInt, index))
                    break
                index = index + 1
            else:
                if int(vmindex) < intVmindex:
                    log.warning("GetFtdIPs:::: Azure index jumbling detected")
                    vmindex = intVmindex
                else:
                    intVmindex = int(vmindex)
     
    publicIP = azutils.get_vmss_public_ip(vmindex, networkInterfaceName, ipConfigurationName, publicIpAddressName)
    
    if publicIP == None:
        log.error("GetFtdIPs:: Unable to get Public IP of new FTD (index {0}".format(vmindex))
        return func.HttpResponse("ERROR",status_code=400)

    log.info("GetFtdIPs:: Public IP of New FTD (VM index {}) = {}".format(vmindex, publicIP))
    log.info("GetFtdIPs:: Private IP of New FTD (VM index {}) = {}".format(vmindex, privateIP))

    commandStr = "{ \"ftdDevName\": \"" + vmName + "\", \"ftdPublicIp\": \"" + publicIP + "\", \"ftdPrivateIp\" : \"" + privateIP + "\"  }"
    return func.HttpResponse(commandStr, status_code=200)
