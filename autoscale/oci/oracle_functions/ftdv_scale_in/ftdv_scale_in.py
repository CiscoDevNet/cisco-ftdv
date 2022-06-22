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

Name:       scale_in.py
Purpose:    This python file has NGFWv related class & methods
            Classes in this python files are being used for 
            performing Scale-in action in OCI NGFWv Autoscale.
"""

import io
import json
import logging
import time
import oci
from fdk import response
from datetime import datetime
from utility import TokenCaller
import utility as utl
from cisco_oci import OCIInstance
from ngfw import ManagedDevice
from manager import *

logging.basicConfig(force=True, level="INFO")
logging.getLogger("paramiko").setLevel(logging.WARNING)
logger = logging.getLogger()

service_endpoint = {
    "eu-frankfurt-1": "https://telemetry.eu-frankfurt-1.oraclecloud.com",
    "us-phoenix-1": "https://telemetry.us-phoenix-1.oraclecloud.com",
    "us-ashburn-1": "https://telemetry.us-ashburn-1.oraclecloud.com",
    "uk-london-1": "https://telemetry.uk-london-1.oraclecloud.com",
    "ca-toronto-1": "https://telemetry.ca-toronto-1.oraclecloud.com",
    "ap-sydney-1": "https://telemetry.ap-sydney-1.oraclecloud.com",
    "ap-melbourne-1": "https://telemetry.ap-melbourne-1.oraclecloud.com",
    "sa-saopaulo-1": "https://telemetry.sa-saopaulo-1.oraclecloud.com",
    "ca-montreal-1": "https://telemetry.ca-montreal-1.oraclecloud.com",
    "sa-santiago-1": "https://telemetry.sa-santiago-1.oraclecloud.com",
    "ap-hyderabad-1": "https://telemetry.ap-hyderabad-1.oraclecloud.com",
    "ap-mumbai-1": "https://telemetry.ap-mumbai-1.oraclecloud.com",
    "ap-osaka-1": "https://telemetry.ap-osaka-1.oraclecloud.com",
    "ap-tokyo-1": "https://telemetry.ap-tokyo-1.oraclecloud.com",
    "eu-amsterdam-1": "https://telemetry.eu-amsterdam-1.oraclecloud.com",
    "me-jeddah-1": "https://telemetry.me-jeddah-1.oraclecloud.com",
    "ap-seoul-1": "https://telemetry.ap-seoul-1.oraclecloud.com",
    "ap-chuncheon-1": "https://telemetry.ap-chuncheon-1.oraclecloud.com",
    "eu-zurich-1": "https://telemetry.eu-zurich-1.oraclecloud.com",
    "me-dubai-1": "https://telemetry.me-dubai-1.oraclecloud.com",
    "uk-cardiff-1": "https://telemetry.uk-cardiff-1.oraclecloud.com",
    "us-sanjose-1": "https://telemetry.us-sanjose-1.oraclecloud.com"
}

class ScaleIn:
    def __init__(self, auth):
        self.computeClient = oci.core.ComputeClient(config={}, signer=auth)
        self.virtualNetworkClient = oci.core.VirtualNetworkClient(config={}, signer=auth)
        self.computeManagementClient = oci.core.ComputeManagementClient(config={}, signer=auth)
        self.loadBalancerClient = oci.load_balancer.LoadBalancerClient(config={}, signer=auth)
        self.retries = 3

    def get_instance_pool_info(self, instancePoolId):
        """
        Purpose:   To get information of the Instance Pool 
        Parameters: 
        Returns:    List(Instances)
        Raises:
        """
        for i in range(0, self.retries):
            try:
                get_instance_pool_response = self.computeManagementClient.get_instance_pool(instance_pool_id = instancePoolId).data
                return get_instance_pool_response
            except Exception as e:
                logger.error("FTDv SCALE-IN: ERROR IN RETRIEVING INSTANCE POOL INFORMATION")
                continue
            
        return None
    
    def get_all_instances_in_pool(self, compartmentId, instancePoolId):
        """
        Purpose:   To get ID of all instances in the Instance Pool 
        Parameters: 
        Returns:    List(Instances)
        Raises:
        """
        for i in range(0, self.retries):
            try:
                all_instances_in_instance_pool = self.computeManagementClient.list_instance_pool_instances(
                                            compartment_id = compartmentId,
                                            instance_pool_id = instancePoolId).data

                
                return all_instances_in_instance_pool

            except Exception as e:
                logger.error("FTDv SCALE-IN: ERROR IN GETTING INSTANCE LIST FROM INSTANCE POOL, RETRY COUNT:{0}, REASON:{1}".format(str(i+1), repr(e)))
                continue
        
        return None

    def get_instance_interface_ip(self, compartmentId, instanceId, insideInterfaceName, outsideInterfaceName):
        """
        Purpose:    
        Parameters:
        Returns: Dict Example: {'inside_ip': '10.0.100.139','outside_ip': '10.0.200.116'}   
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
            logger.error("FTDv SCALE-IN: ERROR IN RETRIEVING VNIC ATTACHMENT "+repr(e))
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
            logger.error("FTDv SCALE-IN: ERROR IN RETRIEVING INTERFACES IP ADDRESS "+repr(e))
            return None
        
        logger.debug("FTDv SCALE-IN: Retrieved Interfaces IP Successfully")
        return interface_ip

    def remove_backend_from_load_balancer(self, lbName, loadBalancerId, backedSetName, ipAddr, portNo):
        """
        Purpose:    Removes particular backend server from the Load Balancer
        Parameters: Load Balancer OCID, Load Balancer Backend Set Name, Backend Name (IP:PORT)
        Returns: None
        Raises:
        """
        try:
            remove_backend_from_load_balancer_response = self.loadBalancerClient.delete_backend(
                load_balancer_id = loadBalancerId,
                backend_set_name = backedSetName,
                backend_name = str(str(ipAddr)+':'+str(portNo))).data
            
            logger.info("FTDv SCALE-IN: {0} BACKEND {1} REMOVED SUCCESSFULLY FOR LISTENER PORT NO: {2}".format(lbName, ipAddr, portNo))
            return True

        except Exception as e:
            logger.error("FTDv SCALE-IN: ERROR IN REMOVING {0} BACKEND {1} FROM LOAD BALANCER FOR LISTENER PORT NO: {2} ERROR: {3}".format(lbName, ipAddr, portNo, repr(e)))
            return None
    
    def drain_backend_server(self, lbName, loadBalancerId, backendSetName, ipAddr, portNo):
        """
        Purpose:   To add instacne as backend server to the backend set of the load balancer
        Parameters: Ip Address of instance, Port Number, Backend set name, Load Balancer OCID
        Returns:    None
        Raises: 
        """
        try:
            drain_backend_server_response = self.loadBalancerClient.update_backend(
                update_backend_details = oci.load_balancer.models.UpdateBackendDetails(
                    weight = 1,
                    backup = False,
                    drain = True,
                    offline = False
                    ),
                load_balancer_id = loadBalancerId,
                backend_set_name = backendSetName,
                backend_name = str(str(ipAddr)+':'+str(portNo))
                )
            logger.info("FTDv SCALE-IN: {0} BACKEND {1} DRAINED SUCCESSFULLY FOR LISTENER PORT NO: {2}".format(lbName, ipAddr, portNo))
            return True

        except Exception as e:
            logger.error("FTDv SCALE-IN: UNABLE TO DRAIN {0} BACKEND {1} FOR LISTENER PORT NO: {2}, ERROR: {3} ".format(lbName, ipAdd, portNo, repr(e)))
            return None

    def update_instance_pool_size(self, instancePoolId):
        """
        Purpose:   To modify instance pool size. (No. of instances)
        Parameters: Instance Pool ID
        Returns:    Response of type Instance Pool
        Raises:
        """
        instance_pool_information = self.get_instance_pool_info(instancePoolId)
        for i in range(0,self.retries):
            try:
                noRetry = oci.retry.NoneRetryStrategy()
                current_pool_size = int(instance_pool_information.size)
                
                target_pool_size = int(current_pool_size - 1)

                update_instance_pool_response = self.computeManagementClient.update_instance_pool( instance_pool_id = instancePoolId,
                    update_instance_pool_details = oci.core.models.UpdateInstancePoolDetails(size = target_pool_size),
                    retry_strategy = noRetry).data

                return update_instance_pool_response
            
            except Exception as e:
                logger.error("FTDv SCALE-IN: Unable to update Instance Pool size for instance pool ID: {0} Retry Count: {1} Response: {2}".format(instancePoolId, str(i), repr(e)))
                continue

        return None

    def get_management_public_ip(self, compartmentId, instanceId):
        """
        Purpose:    
        Parameters:
        Returns:    Dict
                    Example: {'management_public_ip': '54.88.96.211'}
        Raises:
        """
        for i in range(0, self.retries):
            try:
                vnic_attachments = oci.pagination.list_call_get_all_results(
                self.computeClient.list_vnic_attachments,
                compartment_id = compartmentId,
                instance_id = instanceId,
                ).data        

                vnics = [self.virtualNetworkClient.get_vnic(va.vnic_id).data for va in vnic_attachments]
                
                for vnic in vnics:
                    if vnic.is_primary:
                        ip_response = vnic.public_ip
                        return ip_response
                        
            except Exception as e:
                logger.error("FTDv SCALE-IN: ERROR IN RETRIEVING MANAGEMENT PUBLIC IP "+"RETRY COUNT:"+str(i)+"  "+ repr(e))
                continue
        
        return None

    def detachInstanceFromPool(self, instancePoolId, instanceId):
        """
        Purpose:   To detach instance from instance pool.
        Parameters: 
        Returns: Bool
        Raises:
        """
        try:
            detach_instance_pool_instance_response = self.computeManagementClient.detach_instance_pool_instance(
                instance_pool_id = instancePoolId,
                detach_instance_pool_instance_details=oci.core.models.DetachInstancePoolInstanceDetails(
                    instance_id = instanceId,
                        is_decrement_size = True,
                        is_auto_terminate = True)).data
            return True

        except Exception as e:
            logger.error("SCALE-IN: ERROR IN DETACHING THE INSTANCE: {} FROM INSTANCE POOL  ERROR: {}".format(instanceId[-5:], e))
            return False                

def get_alarm_status(monitoring_client, compartment_id, alarm_name):
    try:
        list_alarms_output = monitoring_client.list_alarms(compartment_id)
        if list_alarms_output.status == 200:
            for alarm in list_alarms_output.data:
                if alarm.display_name == alarm_name:
                    alarm_ocid = alarm.id
                    break

            alarm_status = monitoring_client.get_alarm_history(alarm_ocid).data.entries[0]
            if "the alarm state is firing" in alarm_status.summary.lower():
                return "FIRING"
            else:
                return "NOT FIRING"
        else:
            logger.error("FTDv SCALE-IN: Unable to list the alarms.")
    except Exception as err:
        logger.error("FTDv SCALE-IN: Unable to get the alarm status")


def handler(ctx, data: io.BytesIO = None):

    try:
        body = json.loads(data.getvalue())
        alarm_message_type = body.get("type")
        
        if alarm_message_type == "FIRING_TO_OK" or alarm_message_type == "RESET":
            logger.info("FTDv SCALE-IN: ALARM HAS BEEN MOVED TO 'OK' STATE")
            return "False Alarm"

        alarm_name = body.get("title")
        logger.info("FTDv SCALE-IN HAS BEEN CALLED BY ALARM : {}".format(alarm_name))
    except Exception as ex:
        logger.error('FTDv SCALE-IN: ERROR IN PARSING JSON PAYLOAD' + repr(ex))
        return "FTDv SCALE-IN: ERROR IN PARSING JSON PAYLOAD"

    try:
        environmentVariables = ctx.Config()
        ELB_Id = environmentVariables["elb_id"]
        ELB_BackendSetName = environmentVariables["elb_backend_set_name"]
        ELB_ListenerPortNumber = (environmentVariables["elb_listener_port_no"])
        compartmentId = environmentVariables["compartment_id"]
        ILB_Id = environmentVariables["ilb_id"]
        ILB_BackendSetName = environmentVariables["ilb_backend_set_name"]
        ILB_ListenerPortNumber = (environmentVariables["ilb_listener_port_no"])
        minInstanceCount = int(environmentVariables["min_instance_count"])

        instancePoolId = environmentVariables["instance_pool_id"]
        compartmentId = environmentVariables["compartment_id"]
        autoScaleGroupPrefix = environmentVariables["autoscale_group_prefix"]

        ftdv_configuration_json_url = environmentVariables["ftdv_configuration_json_url"]
        
        fmc_ip = environmentVariables["fmc_ip"]
        fmc_username = environmentVariables["fmc_username"]
        
        cryptEndpoint = environmentVariables["cryptographic_endpoint"]
        master_key_id = environmentVariables["master_key_id"]
        environmentVariables["ftdv_password"] = utl.decrypt_cipher(str(environmentVariables["ftdv_encrypted_password"]), cryptEndpoint, master_key_id)
        environmentVariables["fmc_password"]  = utl.decrypt_cipher(str(environmentVariables["fmc_encrypted_password"]),cryptEndpoint, master_key_id)

        json_var = utl.get_fmc_configuration_input(ftdv_configuration_json_url)
        if json_var == None:
            return "ERROR IN FTDv CONFIGURATION JSON"
        insideInterfaceName = json_var["fmcInsideNicName"]
        outsideInterfaceName = json_var["fmcOutsideNicName"]

    except Exception as e:
        logger.error("FTDv SCALE-IN: ERROR IN RETRIEVING ENVIRONMENT VARIABLES: "+repr(e))
        return None

    try:
        signer = oci.auth.signers.get_resource_principals_signer()
    except Exception as e:
        logger.error("FTDv SCALE-IN: ERROR IN OBTAINING SIGNER: "+repr(e))
        return None

    # ScaleIn CLASS OBJECT
    scaleInObject = ScaleIn(signer)

    #_____________________________________________________________________________________________
    # Checking if instance pool is not under scaling state already
    instance_pool_info = scaleInObject.get_instance_pool_info(instancePoolId)
    if str(instance_pool_info.lifecycle_state) == "SCALING":
        logger.info("FTDv SCALE-IN: INSTANCE POOL IS ALREADY IN SCALING STATE, ABORTING CURRENT OPERATION TO AVOID ANY CONFLICT")
        return "FTDv SCALE-IN: INSTANCE POOL IS ALREADY IN SCALING STATE"

    #_____________________________________________________________________________________________
    # Checking if the scale-out alarm is in triggering state
    cpu_scaleout_alarm_name = autoScaleGroupPrefix + "_cpu_scale_out"
    memory_based_scaling = environmentVariables["publish_memory_metrics"]
    region = environmentVariables["region"]
    monitoring_client = oci.monitoring.MonitoringClient(config={}, service_endpoint=service_endpoint[region], signer=signer)

    cpu_scaleout_alarm_response = get_alarm_status(monitoring_client, compartmentId, cpu_scaleout_alarm_name)
    if cpu_scaleout_alarm_response == "FIRING":
        logger.info("FTDv SCALE-IN: Memory Scale-Out Alarm is in firing state. ABORTING CURRENT OPERATION TO AVOID ANY CONFLICT")
        return "FTDv SCALE-IN: CPU SCALE-OUT ALARM IS IN FIRING STATE"

    if memory_based_scaling == "true":
        memory_scaleout_alarm_name = autoScaleGroupPrefix + "_memory_scale_out"
        memory_scaleout_alarm_response = get_alarm_status(monitoring_client, compartmentId, memory_scaleout_alarm_name)
        if memory_scaleout_alarm_response == "FIRING":
            logger.info("FTDv SCALE-IN: Memory Scale-Out Alarm is in firing state. ABORTING CURRENT OPERATION TO AVOID ANY CONFLICT")
            return "FTDv SCALE-IN: MEMORY SCALE-OUT ALARM IS IN FIRING STATE"

    #________________________________________________________________________________________________________
    # GETTING OCID OF TERMINATING INSTANCE
    try:
        all_instances_in_pool = scaleInObject.get_all_instances_in_pool(compartmentId, instancePoolId)
        if all_instances_in_pool == None:
            return
        currentRunningInstanceList = []
        for instance in all_instances_in_pool:
            if str(instance.state).upper() == "RUNNING" or str(instance.state).upper() == "PROVISIONING":
                currentRunningInstanceList.append(instance)

        if len(currentRunningInstanceList) <= minInstanceCount:
            logger.info("FTDv SCALE-IN: Autoscale Minimum running instance count has reached, Can't terminate anymore instance")
            return "Autoscale Minimum running instance count has reached, Can't terminate anymore instance"

        time_creation_list = [str(instance.time_created) for instance in currentRunningInstanceList]
        time_creation_list.sort(key=lambda date: datetime.strptime(date, "%Y-%m-%d %H:%M:%S.%f%z"))

        oldest_timestamp = time_creation_list[0]

        for instance in currentRunningInstanceList:
            if str(instance.time_created) == oldest_timestamp:
                instanceId = instance.id
                instanceName = instance.display_name
                break

    except Exception as e:
        logger.error("FTDv SCALE-IN: ERROR IN RETRIEVING TARGET INSTANCE ID "+repr(e))
        return "ERROR IN RETRIEVING TARGET INSTANCE ID"
    #________________________________________________________________________________________________________
    # EXTRA CHECK SO SCALE IN FUNCTION DO NOT REMOVE ONLY WORKING INSTANCE
    # WHILE OTHER ONE MIGHT BE UNDER CONFIGURATION
    try:
        if len(currentRunningInstanceList) == 2:
            if currentRunningInstanceList[0].id == instanceId:
                new_instance_index = 1
            else:
                new_instance_index = 0
            new_instance_id = currentRunningInstanceList[new_instance_index].id
            new_instance_name = currentRunningInstanceList[new_instance_index].display_name
            
            time_since_creation = utl.get_time_since_creation(instanceId)
            if time_since_creation < 30:
                logger.info(f"FTDv SCALE-IN: CAN'T REMOVE ONLY WORKING INSTANCE {instanceName}, AS OTHER INSTANCE {new_instance_name} IS NEW AND MAY BE UNDER CONFIGURATION STATE")
                return "CAN'T REMOVE ONLY WORKING INSTANCE"
    
    except Exception as e:
        logger.error("FTDv SCALE-IN: ERROR WHILE EXTRA CHECKING IN CASE OF ONLY 2 INSTANCE IN INSTANCE POOL, WILL GO FORWARD WITH SCALING  "+repr(e))
    
    logger.info("FTDv SCALE-IN: Instance going to be terminated is: {0}, having OCID: {1}".format(instanceName, instanceId))
    #________________________________________________________________________________________________________
    # DRAINING THE BACKEND SERVER
    ilb_listener_port_list = list(map(lambda x: int(x.strip()), ILB_ListenerPortNumber.split(',')))
    elb_listener_port_list = list(map(lambda x: int(x.strip()), ELB_ListenerPortNumber.split(',')))
    
    try:
        instance_interface_ip = scaleInObject.get_instance_interface_ip(compartmentId, instanceId, insideInterfaceName, outsideInterfaceName)
        if instance_interface_ip == None:
            return None
        
        insideInterfaceIp = instance_interface_ip['inside_ip']
        outsideInterfaceIp = instance_interface_ip['outside_ip']
        
        for ePort in elb_listener_port_list:
            try:
                drain_ELB_response = scaleInObject.drain_backend_server("ELB", ELB_Id, ELB_BackendSetName, outsideInterfaceIp, ePort)
            except Exception as e:
                logger.error("FTDv SCALE-IN: ERROR IN DRAINING THE BACKEND FROM ELB  "+repr(e))
        for iPort in ilb_listener_port_list:
            try:
                drain_ILB_response = scaleInObject.drain_backend_server("ILB", ILB_Id, ILB_BackendSetName, insideInterfaceIp, iPort)
            except Exception as e:
                logger.error("FTDv SCALE-IN: ERROR IN DRAINING THE BACKEND FROM ILB  "+repr(e))

    except Exception as e:
        logger.error("FTDv SCALE-IN: ERROR IN DRAINING THE BACKEND  "+repr(e))

    time.sleep(60) # Waiting time for backend to completely drain 
    #________________________________________________________________________________________________________
    # REMOVING BACKEND FROM LOAD BALANCER
    try:
        for ePort in elb_listener_port_list:
            try:
                remove_from_ELB_response = scaleInObject.remove_backend_from_load_balancer("ELB", ELB_Id, ELB_BackendSetName, outsideInterfaceIp, ePort)
            except Exception as e:
                logger.error("FTDv SCALE-IN: ERROR IN REMOVING THE BACKEND FROM ELB,  "+repr(e))

        for iPort in ilb_listener_port_list:
            try:
                remove_from_Ilb_response = scaleInObject.remove_backend_from_load_balancer("ILB", ILB_Id, ILB_BackendSetName, insideInterfaceIp, iPort)
            except Exception as e:
                logger.error("FTDv SCALE-IN: ERROR IN DRAINING THE BACKEND FROM ILB  "+repr(e))

    except Exception as e:
        logger.error("FTDv SCALE-IN: ERROR IN REMOVING BACKENDS FROM LOAD BALANCER: "+repr(e))
    #________________________________________________________________________________________________________
    # DE-REGISTERING FTDv FROM FMC, EVENTUALLY REMOVING LICENSE
    try:
        #OBTAINING AUTH TOKEN FOR FMC FROM "FTDv TOKEN MANAGER"(ORACLE FUNCTION)
        appName = autoScaleGroupPrefix + "_application"
        tokenHandler = TokenCaller(compartmentId, appName)    
        endpoint = environmentVariables['token_endpoint_url']
        token = tokenHandler.get_token(endpoint)
    
        if token == None:
            logger.info("FTDv FTDv SCALE-IN: NO TOKEN RECEIVED")
            #terminate_instance_response = ftd.terminate_instance()
            return "NO TOKEN RECEIVED"
        
        fmc = fmc_cls_init(environmentVariables, json_var, token)
        ftd = ManagedDevice(compartmentId, instanceId, fmc)
        ftd.vm_name = autoScaleGroupPrefix +"_"+ str(instanceId[-12:])
        ftd_deregister_response = ftd.remove_from_fmc()
        if ftd_deregister_response != "SUCCESS":
            return "FAILED TO DEREGISTER FTD FROM FMC"
        
    except Exception as e:
        logger.error("FTDv SCALE-IN: ERROR IN CREATING FMC AND FTDV OBJECTS " + repr(e))
        return "FAILED TO CREATE FMC AND FTD OBJECTS"
    #________________________________________________________________________________________________________
    # DETACHING THE INSTANCE FROM THE INSTANCE POOL AND TERMINATING
    try:
        detach_response = scaleInObject.detachInstanceFromPool(instancePoolId, instanceId)
        if detach_response == True:
            logger.info(f"FTDv SCALE-IN: Instance {instanceId[-5:]} got detached from the instance pool successfully")
        else:
            logger.error(f"FTDv SCALE-IN: INSTANCE {instanceId[-5:]} GOT FAILED TO DETACH FROM THE INSTANCE POOL")
            return "FAILED TO DETACH FROM THE POOL"
    except Exception as e:
        logger.error(F"FTDv SCALE-IN: EXCEPTION IN DETACHING THE INSTANCE {instanceId[-5:]} FROM THE INSTANCE POOL")
        return "EXCEPTION IN DETACHING FROM THE POOL"
    #________________________________________________________________________________________________________    
    
    return response.Response(
        ctx, response_data=json.dumps(
            {"FTDv SCALE-IN Response": "SUCCESSFUL"}),
        headers={"Content-Type": "application/json"}
    )
