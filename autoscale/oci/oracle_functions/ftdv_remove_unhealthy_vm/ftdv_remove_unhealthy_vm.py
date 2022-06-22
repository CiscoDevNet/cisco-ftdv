"""
Copyright (c) 2021 Cisco Systems Inc or its affiliates.

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

Name:       remove_unhealthy_vms.py
Purpose:    This python file has ASAv related class & methods
            Classes in this python files are being used for 
            performing Remove-Unhealthy-Backend action in OCI ASAv Autoscale.
"""

import io
import json
import logging

import paramiko
import socket
import time

import oci
from fdk import response

from utility import TokenCaller
import utility as utl
from cisco_oci import OCIInstance
from ngfw import ManagedDevice
from manager import *

logging.basicConfig(force=True, level="INFO")
logging.getLogger("paramiko").setLevel(logging.WARNING)
logger = logging.getLogger()

class RemoveBackend:
    def __init__(self):
        self.auth = self.get_signer()
        self.computeClient = oci.core.ComputeClient(config={}, signer=self.auth)
        self.virtualNetworkClient = oci.core.VirtualNetworkClient(config={}, signer=self.auth)
        self.computeManagementClient = oci.core.ComputeManagementClient(config={}, signer=self.auth)
        self.loadBalancerClient = oci.load_balancer.LoadBalancerClient(config={}, signer=self.auth)
        self.retries = 3

    def get_signer(self):
        try:
            auth = oci.auth.signers.get_resource_principals_signer()
            return auth
        except Exception as e:
            logger.error("CONFIGURE FTDv:  ERROR IN OBTAINING SIGNER  "+repr(e))
            return None

    def get_unhealthy_backends(self, loadBalancerId, backendSetName):
        """
        Purpose:   To get list of all the unhealthy backends in the Instance Pool.
        Parameters: Load Balancer OCID, Backend Set Name
        Returns:    list(Obj(Instnace))
        Raises:
        """
        try:
            backend_set_health_response = self.loadBalancerClient.get_backend_set_health(
            load_balancer_id = loadBalancerId,
            backend_set_name = backendSetName).data

            logger.info("REMOVE UNHEALTHY VM FUNCTION: Backend Set Health retrieved successfully")
            return backend_set_health_response
        except Exception as e:
            logger.error("REMOVE UNHEALTHY VM FUNCTION  "+repr(e))
            return None

    def get_all_instances_in_pool(self, compartmentId, instancePoolId):
        """
        Purpose:   To get ID of all instances in the Instance Pool 
        Parameters: 
        Returns:    Response
        Raises:
        """
        for i in range(0, self.retries):
            try:
                all_instances_in_instance_pool = self.computeManagementClient.list_instance_pool_instances(compartment_id = compartmentId, instance_pool_id = instancePoolId).data
                return all_instances_in_instance_pool
            except Exception as e:
                logger.error("REMOVE UNHEALTHY VM FUNCTION: ERROR IN GETTING INSTANCE LIST FROM INSTANCE POOL, RETRY COUNT:{0}, REASON:{1}".format(str(i+1), repr(e)))
                continue
        return None

    def get_instance_interface_ip(self, compartmentId, instanceId, insideInterfaceName, outsideInterfaceName):
        """
        Purpose:    To get inside and outside interface ip addresses.
        Parameters:
        Returns:    Dict Example: {'inside_ip': '10.0.100.139','outside_ip': '10.0.200.116'}   
        Raises:
        """
        interface_ip = {}
        try:
            vnic_attachments = oci.pagination.list_call_get_all_results(
            self.computeClient.list_vnic_attachments,
            compartment_id = compartmentId,
            instance_id = instanceId
            ).data
        except Exception as e:
            logger.error("REMOVE UNHEALTHY VM FUNCTION: ERROR IN RETRIEVING VNIC ATTACHMENT "+repr(e))
            return None

        vnics = [self.virtualNetworkClient.get_vnic(va.vnic_id).data for va in vnic_attachments]
        try:
            for vnic in vnics:
                if vnic.display_name == insideInterfaceName:
                    ip_response = vnic.private_ip
                    interface_ip.update({'inside_ip': ip_response})
                        
                elif vnic.display_name == outsideInterfaceName:
                    ip_response = vnic.private_ip
                    interface_ip.update({'outside_ip': ip_response})
                        
        except Exception as e:
            logger.error("REMOVE UNHEALTHY VM FUNCTION: ERROR IN RETRIEVING INTERFACES IP ADDRESS "+repr(e))
            return None
        
        logger.debug("REMOVE UNHEALTHY VM FUNCTION: Retrieved Interfaces IP Successfully")
        return interface_ip

    def remove_backend_from_load_balancer(self, lbName, loadBalancerId, backedSetName, ipAddr, portNo):
        """
        Purpose:    Removes particular backend server from the Load Balancer
        Parameters: Load Balancer OCID, Load Balancer Backend Set Name, IP Addr, Port No)
        Returns: None
        Raises: 
        """
        try:
            remove_backend_from_load_balancer_response = self.loadBalancerClient.delete_backend(
                load_balancer_id = loadBalancerId,
                backend_set_name = backedSetName,
                backend_name = str(str(ipAddr)+':'+str(portNo))).data
            
            logger.info("REMOVE UNHEALTHY VM FUNCTION: {0} VM REMOVED SUCCESSFULLY FOR LISTENER PORT NO: {1}".format(lbName,portNo))
            return True

        except Exception as e:
            logger.error("REMOVE UNHEALTHY VM FUNCTION: ERROR IN REMOVING {0} VM FROM LOAD BALANCER FOR LISTENER PORT NO: {1} ERROR: {2}".format(lbName, portNo, repr(e)))
            return None

def handler(ctx, data: io.BytesIO = None):
    try:
        body = json.loads(data.getvalue())
        alarm_message_type = body.get("type")
        
        if alarm_message_type == "FIRING_TO_OK" or alarm_message_type == "RESET":
            logger.info("REMOVE UNHEALTHY VM: ALARM HAS BEEN MOVED TO 'OK' STATE")
            return "False Alarm"
        
        logger.info("---Remove Unhealthy VM Called---")
    except Exception as ex:
        logger.error('REMOVE UNHEALTHY VM: ERROR IN PARSING JSON PAYLOAD' + repr(ex))
        return "REMOVE UNHEALTHY VM: ERROR IN PARSING JSON PAYLOAD"

    try:
        environmentVariables = ctx.Config()

        compartmentId = environmentVariables["compartment_id"]
        instancePoolId = environmentVariables["instance_pool_id"]

        ELB_Id = environmentVariables["elb_id"]
        ELB_BackendSetName = environmentVariables["elb_backend_set_name"]
        ELB_ListenerPortNumber = (environmentVariables["elb_listener_port_no"])
        ILB_Id = environmentVariables["ilb_id"]
        ILB_BackendSetName = environmentVariables["ilb_backend_set_name"]
        ILB_ListenerPortNumber = (environmentVariables["ilb_listener_port_no"])
    
        ftdv_username = environmentVariables["ftdv_username"]
        ftdv_configuration_json_url = environmentVariables["ftdv_configuration_json_url"]
        autoScaleGroupPrefix = environmentVariables["autoscale_group_prefix"]

        fmc_ip = environmentVariables["fmc_ip"]
        fmc_username = environmentVariables["fmc_username"]
        
        cryptEndpoint = environmentVariables["cryptographic_endpoint"]
        master_key_id = environmentVariables["master_key_id"]
        environmentVariables["ftdv_password"] = utl.decrypt_cipher(str(environmentVariables["ftdv_encrypted_password"]), cryptEndpoint, master_key_id)
        environmentVariables["fmc_password"] = utl.decrypt_cipher(str(environmentVariables["fmc_encrypted_password"]),cryptEndpoint, master_key_id)
    except Exception as e:
        logger.error("REMOVE UNHEALTHY VM: ERROR IN RETRIEVING ENVIRONMENT VARIABLES: "+repr(e))
        return None

#_____________________________________________________________________________________________    
    # Obtaining User Configuration (JSON) 
    json_var = utl.get_fmc_configuration_input(ftdv_configuration_json_url)
    if json_var == None:
        return "ERROR IN FTDv CONFIGURATION JSON"
    insideInterfaceName = json_var["fmcInsideNicName"]
    outsideInterfaceName = json_var["fmcOutsideNicName"]
#_____________________________________________________________________________________________    
    #OBTAINING AUTH TOKEN FOR FMC FROM FTDv TOKEN MANAGER
    appName = autoScaleGroupPrefix + "_application"
    tokenHandler = TokenCaller(compartmentId, appName)    
    endpoint = environmentVariables['token_endpoint_url']
    token = tokenHandler.get_token(endpoint)
    if token == None:
        logger.info("FTDv REMOVE UNHEALTHY BACKEND: NO TOKEN RECEIVED")
        #terminate_instance_response = ftd.terminate_instance()
        return "NO TOKEN RECEIVED"

    # Obtaining FMC 
    fmc = fmc_cls_init(environmentVariables, json_var, token)
    
    # Obtaining Remove Backend Object
    removeBackendObject = RemoveBackend()

################################ ELB's Unhealthy Backend ###############################

    elb_unhealthy_backends_response = removeBackendObject.get_unhealthy_backends(ELB_Id, ELB_BackendSetName)
    if elb_unhealthy_backends_response == None:
        logger.error("REMOVE UNHEALTHY VM: Health-Check Action Failed")
        return "Health-Check Action Failed"

    elb_critical_backends = elb_unhealthy_backends_response.critical_state_backend_names
    elb_unknown_backends = elb_unhealthy_backends_response.unknown_state_backend_names
    elb_warning_state_backends = elb_unhealthy_backends_response.warning_state_backend_names

################################# ILB's Unhealthy Backend ###############################
    
    ilb_unhealthy_backends_response = removeBackendObject.get_unhealthy_backends(ILB_Id, ILB_BackendSetName)
    if ilb_unhealthy_backends_response == None:
        logger.error("REMOVE UNHEALTHY VM: Health-Check Action Failed")
        return "Health-Check Action Failed"

    ilb_critical_backends = ilb_unhealthy_backends_response.critical_state_backend_names
    ilb_unknown_backends = ilb_unhealthy_backends_response.unknown_state_backend_names
    ilb_warning_state_backends = ilb_unhealthy_backends_response.warning_state_backend_names

################################ GETTING OCID OF TERMINATING INSTANCE ##########################

    elb_critical_ip = list(set([ebackend.split(":")[0] for ebackend in elb_critical_backends]))
    ilb_critical_ip = list(set([ibackend.split(":")[0] for ibackend in ilb_critical_backends]))
    
    unhealthy_instance_to_remove = []
    try:
        all_instances_in_pool = removeBackendObject.get_all_instances_in_pool(compartmentId, instancePoolId)
        currentRunningInstanceList = []
        for instance in all_instances_in_pool:
            if instance.state == "Running":
                interface_ip_response = removeBackendObject.get_instance_interface_ip(compartmentId, instance.id, insideInterfaceName, outsideInterfaceName)

                if interface_ip_response["outside_ip"] in elb_critical_ip:
                    unhealthy_instance_to_remove.append(instance.id)
                    elb_critical_ip.remove(interface_ip_response["outside_ip"])

                if interface_ip_response["inside_ip"] in ilb_critical_ip:
                    unhealthy_instance_to_remove.append(instance.id)
                    ilb_critical_ip.remove(interface_ip_response["inside_ip"])

        unhealthy_instance_to_remove = list(set(unhealthy_instance_to_remove))
        logger.info("REMOVE UNHEALTHY VM: Unhealthy VM going to be terminated : {0}".format(unhealthy_instance_to_remove))

    except Exception as e:
        logger.error("REMOVE UNHEALTHY VM: ERROR IN RETRIEVING UNHEALTHY VM INSTANCE ID "+repr(e))
#______________________________________________________________________________________________________________________________
    ilb_listener_port_list = list(map(lambda x: int(x.strip()), ILB_ListenerPortNumber.split(',')))
    elb_listener_port_list = list(map(lambda x: int(x.strip()), ELB_ListenerPortNumber.split(',')))

# Removing stale entries if any. (Backends whose instance got deleted somehow but entries wasn't removed from the load balancer)
    if len(elb_critical_ip) > 0:
        logger.info("REMOVE UNHEALTHY VM: CLEARING ELB STALE BACKENDS {}".format(elb_critical_ip))
        for elb_stale_ip in elb_critical_ip:
            for ePort in elb_listener_port_list:
                stale_remove_response = removeBackendObject.remove_backend_from_load_balancer("ELB", ELB_Id, ELB_BackendSetName, elb_stale_ip, ePort)
            logger.info("REMOVE UNHEALTHY VM: STALE VM: {} HAS BEEN REMOVED FROM ELB".format(elb_stale_ip))

    if len(ilb_critical_ip) > 0:
        logger.info("REMOVE UNHEALTHY VM: CLEARING ILB STALE BACKENDS {}".format(ilb_critical_ip))
        for ilb_stale_ip in ilb_critical_ip:
            for iPort in ilb_listener_port_list:
                remove_from_Ilb_response = removeBackendObject.remove_backend_from_load_balancer("ILB", ILB_Id, ILB_BackendSetName, ilb_stale_ip, iPort)
            logger.info("REMOVE UNHEALTHY VM: STALE VM: {} HAS BEEN REMOVED FROM ILB".format(ilb_stale_ip))

    if len(unhealthy_instance_to_remove) == 0:
        logger.info("REMOVE UNHEALTHY VM: NO UNHEALTHY VM FOUND")
        return "NO UNHEALTHY VM FOUND"

    #______________________________________________________________________________________________________________________________
    # REMOVING VM FROM LOAD BALANCER 
    for instanceId in unhealthy_instance_to_remove:

        # OBTAINING FTDv Object of this instnaceId.
        ftd = ManagedDevice(compartmentId, instanceId, fmc)
        ftd.vm_name = autoScaleGroupPrefix +"_"+ str(instanceId[-12:])
        
        # EXTRA CHECK SO REMOVE UNHEALTHY VM FUNCTION DO NOT REMOVE NEWLY CREATED INSTANCE
        # WHICH MIGHT BE UNDER CONFIGURATION
        time_since_creation = utl.get_time_since_creation(instanceId)
        if time_since_creation < 30:
            continue

        instance_interface_ip = ftd.get_instance_interface_info(insideInterfaceName, outsideInterfaceName)
        if instance_interface_ip == None:
            return None

        insideInterfaceIp = instance_interface_ip['inside_ip']
        outsideInterfaceIp = instance_interface_ip['outside_ip']

        for ePort in elb_listener_port_list:
            try:
                remove_from_ELB_response = removeBackendObject.remove_backend_from_load_balancer("ELB", ELB_Id, ELB_BackendSetName, outsideInterfaceIp, ePort)
            except Exception in e:
                logger.info("REMOVE UNHEALTHY VM {}: ERROR IN REMOVING VM FROM ELB  {}".format(instanceId[-5:], repr(e)))
                continue
        
        for iPort in ilb_listener_port_list:
            try:
                remove_from_Ilb_response = removeBackendObject.remove_backend_from_load_balancer("ILB", ILB_Id, ILB_BackendSetName, insideInterfaceIp, iPort)
            except Exception in e:
                logger.info("REMOVE UNHEALTHY VM {}: ERROR IN REMOVING VM FROM ILB  {}".format(instanceId[-5:], repr(e)))
                continue 
        
        #DE-REGISTERING THE LICENSE  
        remove_from_fmc_response = ftd.remove_from_fmc()
        if remove_from_fmc_response == "SUCCESS":
            logger.info(f"REMOVE UNHEALTHY VM {instanceId[-5:]}: FTDv instance has been removed from FMCv, successfully")
        else:
            logger.error(f"REMOVE UNHEALTHY VM {instanceId[-5:]}: Unable to remove FTDv  from FMCv")
    #______________________________________________________________________________________________________________________________
    # TERMINATING THE INSTANCE
       
        terminate_instance_response = ftd.terminate_instance()
        if terminate_instance_response == False:
            logger.error("REMOVE UNHEALTHY VM: ERROR IN TERMINATING INSTANCE WITH OCID: {}".format(instanceId))
        else:
            logger.info("REMOVE UNHEALTHY VM: UNHEALTHY INSTANCE HAS BEEN REMOVED WITH OCID: {}".format(instanceId))

    return response.Response(
        ctx, response_data=json.dumps(
            {"REMOVE UNHEALTHY VM FUNCTION Response": "SUCCESSFUL"}),
        headers={"Content-Type": "application/json"}
    )
