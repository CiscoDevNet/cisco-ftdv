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

Name:       post_launch-actions.py
Purpose:    This python file is used for FTDv to attach interfaces, to create queue, to add to load balancer.
            These classes will be initialized in the oracle function
"""

import io
import json
import logging

import ast
import oci
import time
from fdk import response

import utility as utl
logger = logging.getLogger()

class CustomQueue:
    def __init__(self, funcId):
        self.auth = oci.auth.signers.get_resource_principals_signer()
        self.functions_client = oci.functions.FunctionsManagementClient(config={}, signer=self.auth)
        self.funcName = "ftdv_post_launch_actions"
        self.funcId = funcId
        self.identifier = ''

    def read_queue(self):
        try:
            get_function_response = self.functions_client.get_function(function_id=self.funcId).data
            queue_status = get_function_response.config
            return queue_status
        except Exception as e:
            raise Exception(f"POST LAUNCH ACTION {identifier}: ERROR IN RETRIEVING QUEUE  "+repr(e))
    
    def write_queue(self, queue_data):
        try:
            update_function_response = self.functions_client.update_function(
                function_id = self.funcId,
                update_function_details=oci.functions.models.UpdateFunctionDetails(
                    config=queue_data)).data
            return
        except Exception as e:
            raise Exception(f"POST LAUNCH ACTION {identifier}: ERROR IN WRITING QUEUE "+repr(e))
            
    def push_to_queue(self, instanceId, insideInterfaceIpAddress, outsideInterfaceIpAddress):
        try:
            current_queue = self.read_queue()
            current_queue_size = len(current_queue)
            
            event_data = {}
            event_data["instanceId"] = instanceId
            event_data["entry_timestamp"] = int(time.time())
            event_data["insideInterfaceIpAddress"] = insideInterfaceIpAddress
            event_data["outsideInterfaceIpAddress"] = outsideInterfaceIpAddress
            event_data["post_launch_status"] = "PENDING"
            event_data["ftdv_configure_status"] = "PENDING"
            current_queue["event_"+str(current_queue_size+1)] = str(event_data)
            self.write_queue(current_queue)
            return
        except Exception as e:
            raise Exception(f"POST LAUNCH ACTION {identifier}: ERROR IN CREATING QUEUE ENTRY "+repr(e))
    
    def update_queue_data(self, pl_status):
        try:
            current_queue = self.read_queue()
            target_event = ast.literal_eval(current_queue["event_1"])
            target_event["post_launch_status"] = pl_status
            current_queue["event_1"] = str(target_event)
            self.write_queue(current_queue)
            return
        except Exception as e:
            raise Exception(f"POST LAUNCH ACTION {identifier}: ERROR IN UPDATING QUEUE DATA "+repr(e))

    def reorder_queue(self):
        try:
            updated_queue = {}
            current_queue = self.read_queue()
            if len(current_queue)<2:
                self.write_queue({})
                return
            for i in range(1,len(current_queue)):
                updated_queue["event_"+str(i)] = current_queue["event_"+str(i+1)]
            self.write_queue(updated_queue)
            return
        except Exception as e:
            raise Exception("ERROR IN RE-ORDERING QUEUE DATA "+repr(e))

class PostLaunchAction:
    def __init__(self):
        self.auth = oci.auth.signers.get_resource_principals_signer()
        self.computeClient = oci.core.ComputeClient(config={}, signer=self.auth)
        self.virtualNetworkClient = oci.core.VirtualNetworkClient(config={}, signer=self.auth)
        self.computeManagementClient = oci.core.ComputeManagementClient(config={}, signer=self.auth)
        self.loadBalancerClient = oci.load_balancer.LoadBalancerClient(config={}, signer=self.auth)
        self.ons_client = oci.ons.NotificationDataPlaneClient(config={}, signer=self.auth)
        self.functions_client = oci.functions.FunctionsManagementClient(config={}, signer=self.auth)
        self.identifier = ''
        self.retries = 3

    def get_all_instances_id_in_pool(self, compartmentId, instancePoolId):
        """
        Purpose:   To get OCID of all Instances in the Instance Pool 
        Parameters: Compartment OCID, Instance Pool OCID
        Returns:    List(Instance OCID)
        Raises:
        """
        for i in range(0, self.retries):
            try:
                all_instances_in_instance_pool = self.computeManagementClient.list_instance_pool_instances(
                                            compartment_id = compartmentId,
                                            instance_pool_id = instancePoolId).data

                all_instances_id = [instance.id for instance in all_instances_in_instance_pool]
                return all_instances_id

            except Exception as e:
                logger.error(f"POST LAUNCH ACTION {self.identifier}: ERROR IN GETTING INSTANCE LIST FROM INSTANCE POOL, RETRY COUNT:{i+1}, REASON:{repr(e)}")
                continue
        
        return None

    def terminate_instance(self, instanceId):
        """
        Purpose:   To Terminate any Instance in the Instance Pool (Not Scale-In)
        Parameters: Instance OCID to delete.
        Returns:    Boolean
        Raises:
        """
        for i in range(0, self.retries):
            try:
                terminate_instance_response = self.computeClient.terminate_instance(
                instance_id = instanceId,
                preserve_boot_volume=False)

                logger.info(f"POST LAUNCH ACTION {self.identifier}: INSTANCE TERMINATED AS SOMETHING WENT WRONG, PLEASE CHECK PREVIOUS LOGS")
                return True
            
            except Exception as e:
                logger.info(f"POST LAUNCH ACTION {self.identifier}: ERROR OCCURRED WHILE TERMINATING INSTANCE, RETRY COUNT:{i+1}, REASON:{repr(e)}")
                continue
        return

    def get_management_public_ip(self, compartmentId, instanceId):
        """
        Purpose:    To get Management interface (vnic) public IP. 
        Parameters: Compartment OCID, Instance OCID.
        Returns:    Dict     Example: {'management_public_ip': '54.88.96.211'}
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
                logger.error(f"POST LAUNCH ACTION {self.identifier}: ERROR IN RETRIEVING MANAGEMENT PUBLIC IP RETRY COUNT: {i} ERROR: {repr(e)}")
                continue
        return None
                
    def attach_interface(self, instanceId, interfaceName, subnetId, nsgIdList):
        """
        Purpose:   To create Non-primary interface (vnic) in a Instance. 
        Parameters: Instance OCID, Interface Name, Subnet OCID
        Returns:    A Response object with data of type VnicAttachment
        Raises:
        """
        for i in range(0, self.retries):
            try:
                computeCompositeClient = oci.core.ComputeClientCompositeOperations(client=self.computeClient)
                
                attach_vnic_details=oci.core.models.AttachVnicDetails(
                create_vnic_details=oci.core.models.CreateVnicDetails(
                    assign_public_ip = False,
                    skip_source_dest_check = True,
                    subnet_id = subnetId,
                    nsg_ids = nsgIdList),
                    instance_id = instanceId,
                    display_name = interfaceName)

                attach_vnic_response = computeCompositeClient.attach_vnic_and_wait_for_state(attach_vnic_details, wait_for_states=["ATTACHED"]).data

                vnicId = attach_vnic_response.vnic_id
                break
                
            except Exception as e:
                logger.error(f"POST LAUNCH ACTION {self.identifier}: RETRY:{i+1} ERROR:{e}")
                time.sleep((i+1)*15)
                continue

        """
        NOTE: Code following below for this function has been written to update VNIC name after attachment
        because it is not taking given display name at them time of attachment itself.
        If the issue gets resolved in future this code should be removed.
        """
        try:
            virtualNetworkCompositeClient = oci.core.VirtualNetworkClientCompositeOperations(client = self.virtualNetworkClient)
            update_vnic_details=oci.core.models.UpdateVnicDetails(display_name = interfaceName)
            update_vnic_response = virtualNetworkCompositeClient.update_vnic_and_wait_for_state(vnicId, update_vnic_details, wait_for_states=["AVAILABLE"]).data
            
            #logger.info(repr(update_vnic_response))
            return update_vnic_response

        except Exception as e:
            logger.error(f"POST LAUNCH ACTION {self.identifier}: {repr(e)}")
            return None

    def add_to_backend_set(self, loadBalancerId, backendSetName, ipAddr, portNo):
        """
        Purpose:   To add instacne as backend server to the backend set of the load balancer
        Parameters: Ip Address of instance, Port Number, Backend set name, Load Balancer OCID
        Returns:    Str
        Raises: 
        """
        for i in range(0, self.retries):
            try:
                create_backend_response = self.loadBalancerClient.create_backend(
                    create_backend_details = oci.load_balancer.models.CreateBackendDetails(
                                                ip_address = ipAddr,
                                                port = portNo,
                                                #weight=,
                                                #backup=True,
                                                #drain=False,
                                                #offline=False
                                            ),
                        load_balancer_id = loadBalancerId,
                        backend_set_name = backendSetName
                        ).data
                return "Successful"
                
            except Exception as e:
                logger.error(f"POST LAUNCH ACTION {self.identifier}: ERROR IN ADDING TO BACKEND SET "+"RETRY COUNT:"+str(i+1)+"  "+ repr(e) + repr(create_backend_response))
                continue
        
        return "Failed"

    def publish_message(self, topicId, msg):
        """
        Purpose:   To publish message to OCI Notification.
        Parameters: Topic ID, Message
        Returns:    Bool
        Raises:
        """
        for i in range(0, self.retries):
            try:
                publish_message_response = self.ons_client.publish_message(
                    topic_id = topicId,
                    message_details=oci.ons.models.MessageDetails(
                        body = json.dumps(msg),
                        title = "Configure_FTDv_Recall")).data

                return True
            except Exception as e:
                logger.info(f"POST LAUNCH ACTION {self.identifier}: "+repr(e))
                continue
        return False

    def update_application_configuration(self, compartmentId, appName):
        try:
            list_applications_response = self.functions_client.list_applications(
                compartment_id = compartmentId,
                lifecycle_state = "ACTIVE",
                display_name = appName).data
            appId = list_applications_response[0].id
        
            list_functions_response = self.functions_client.list_functions(
                application_id = appId,
                lifecycle_state = "ACTIVE",
                display_name = "ftdv_post_launch_actions").data

            funcId = list_functions_response[0].id
        
            get_application_response = self.functions_client.get_application(application_id=appId).data
            app_config = get_application_response.config
            app_config["post_launch_func_id"] = funcId
            
            update_application_response = self.functions_client.update_application(
                application_id = appId,
                update_application_details=oci.functions.models.UpdateApplicationDetails(config=app_config))
            logger.info(f"POST LAUNCH ACTION {self.identifier}: Post Launch Function OCID updated in Application configuration")
            return funcId
        except Exception as e:
            logger.error(f"POST LAUNCH ACTION {self.identifier}: ERROR IN UPDATING APPLICATION CONFIGURATION "+repr(e))
            return None

def handler(ctx, data: io.BytesIO=None):
    """
    Purpose:   Main Function, receive JSON payload, Environmental Variable, implementation logic. 
    Parameters: ctx (Contains Environmental Variables passed), data (Json Payload emit by event which called this function)
    Returns:    Response
    Raises:
    """
    # POST LAUNCH ACTION CLASS OBJECT
    postLaunchActionObject = PostLaunchAction()
    
    try:
        begin_time = time.time()
        body = json.loads(data.getvalue())
        data = body.get("data")
        instanceId = data.get("resourceId")
        identifier = instanceId[-5:]
        postLaunchActionObject.identifier = identifier
        if not ("ons_flag" in body):
            logger.info("{}:--POST LAUNCH ACTION-- EVENT RECEIVED".format(identifier))
        else:
            logger.info("{}:--POST LAUNCH ACTION-- NOTIFICATION RECEIVED".format(identifier))
    except Exception as ex:
        logger.error('POST LAUNCH ACTION: ERROR IN PARSING JSON PAYLOAD, INSTANCE WILL BE TERMINATED: ' + repr(ex))
        return "POST LAUNCH ACTION: ERROR IN PARSING JSON PAYLOAD"

    try:
        environmentVariables = ctx.Config()
        compartmentId = environmentVariables["compartment_id"]
        autoscaleGroupPrefix = environmentVariables["autoscale_group_prefix"]
        outsideSubnetId = environmentVariables["outside_subnet_id"]
        ELB_Id = environmentVariables["elb_id"]
        ELB_BackendSetName = environmentVariables["elb_backend_set_name"]
        ELB_ListenerPortNumber = environmentVariables["elb_listener_port_no"]
        instancePoolId = environmentVariables["instance_pool_id"]
        insideSubnetId = environmentVariables["inside_subnet_id"]
        ILB_Id = environmentVariables["ilb_id"]
        configure_ftdv_topic_id = environmentVariables["configure_ftdv_topic_id"]
        ILB_BackendSetName = environmentVariables["ilb_backend_set_name"]
        ILB_ListenerPortNumber = environmentVariables["ilb_listener_port_no"]
        outsideNSGId = environmentVariables["outside_nsg_id"]
        insideNSGId = environmentVariables["inside_nsg_id"]

        ftdv_configuration_json_url = environmentVariables["ftdv_configuration_json_url"]
        json_var = utl.get_fmc_configuration_input(ftdv_configuration_json_url)
        insideInterfaceName = json_var["fmcInsideNicName"]
        outsideInterfaceName = json_var["fmcOutsideNicName"]
        post_launch_actions_topic_id = environmentVariables["post_launch_actions_topic_id"]
    except Exception as e:
        logger.error(f"POST LAUNCH ACTION {identifier}:  ERROR IN RETRIEVING ENVIRONMENT VARIABLES,INSTACE WILL BE TERMINATED "+repr(e))
        return "POST LAUNCH ACTION FAILED WITH THIS INSTANCE"
    
    all_instances_id = postLaunchActionObject.get_all_instances_id_in_pool(compartmentId, instancePoolId)
    if all_instances_id == None:
        return

    if instanceId in all_instances_id:
        if not ("ons_flag" in body):
            time.sleep(20)
            try:
                #________________________________________________________________________________________
                # ATTACHING INSIDE VNIC
                attach_inside_interface_response = postLaunchActionObject.attach_interface(instanceId, insideInterfaceName, insideSubnetId, [insideNSGId])
                if attach_inside_interface_response != None:
                    logger.info(f"POST LAUNCH ACTION {identifier}: Inside VNIC attached successfully")
                    insideInterfaceIpAddress = attach_inside_interface_response.private_ip
                else:
                    logger.error(f"POST LAUNCH ACTION {identifier}: Inside VNIC Attachment Failed, INSTACE WILL BE TERMINATED")
                    postLaunchActionObject.terminate_instance(instanceId)
                    return "POST LAUNCH ACTION FAILED WITH THIS INSTANCE"
                #________________________________________________________________________________________
                # ATTACHING OUTSIDE VNIC
                attach_outside_interface_response = postLaunchActionObject.attach_interface(instanceId, outsideInterfaceName, outsideSubnetId, [outsideNSGId])
                if attach_outside_interface_response != None:
                    logger.info(f"POST LAUNCH ACTION {identifier}: Outside VNIC attached successfully")
                    outsideInterfaceIpAddress = attach_outside_interface_response.private_ip
                else:
                    logger.error(f"POST LAUNCH ACTION {identifier}: Outside VNIC Attachment Failed, INSTACE WILL BE TERMINATED")
                    postLaunchActionObject.terminate_instance(instanceId)
                    return "POST LAUNCH ACTION FAILED WITH THIS INSTANCE"
                #________________________________________________________________________________________
            except Exception as e:
                logger.error(f"POST LAUNCH ACTION {identifier}: ATTACH INTERFACE GOT FAILED, INSTACE WILL BE TERMINATED"+repr(e))
                postLaunchActionObject.terminate_instance(instanceId)
                return "POST LAUNCH ACTION FAILED WITH THIS INSTANCE"
        #________________________________________________________________________________________
        # QUEUE MANAGEMENT
        if "post_launch_func_id" in environmentVariables:
            funcId = environmentVariables["post_launch_func_id"]
        else:
            funcId = postLaunchActionObject.update_application_configuration(compartmentId, autoscaleGroupPrefix+"_application")

        queue_manager = CustomQueue(funcId)
        queue_manager.identifier = identifier
        if not ("ons_flag" in body):
            try:
                queue_manager.push_to_queue(instanceId, insideInterfaceIpAddress, outsideInterfaceIpAddress)
                logger.info(f"POST LAUNCH ACTION {identifier}: added to the queue successfully")
            except Exception as e:
                logger.error(f"POST LAUNCH ACTION {identifier}: ERROR IN PUSHING TO QUEUE {e}")
                postLaunchActionObject.terminate_instance(instanceId)
                return "POST LAUNCH ACTION FAILED WITH THIS INSTANCE"
            
        current_queue = queue_manager.read_queue()
        current_event = ast.literal_eval(current_queue["event_1"])
        
        if not (current_event["post_launch_status"] == "PENDING" and current_event["ftdv_configure_status"] == "PENDING"):
            logger.info(f"POST LAUNCH ACTION {identifier}: Other instance getting configured, will wait in the queue")
            return "Other instance getting configured"
        
        queue_manager.update_queue_data("IN_PROGRESS")
        instanceId = current_event["instanceId"]
        insideInterfaceIpAddress = current_event["insideInterfaceIpAddress"]
        outsideInterfaceIpAddress = current_event["outsideInterfaceIpAddress"]
        #________________________________________________________________________________________
        # ADDING TO INTERNAL LOAD BALANCER
        ilb_listener_port_list = list(map(lambda x: int(x.strip()), ILB_ListenerPortNumber.split(',')))
        try:
            for iPort in ilb_listener_port_list:
                add_to_ILB_backend_set_response = postLaunchActionObject.add_to_backend_set(ILB_Id, ILB_BackendSetName, insideInterfaceIpAddress, iPort)
                logger.info("POST LAUNCH ACTION {}: Add to Internal Backend Set response for listener port {} is {}".format(identifier, iPort, repr(add_to_ILB_backend_set_response)))
        except Exception as e:
            logger.error(f"POST LAUNCH ACTION {identifier}:  ADD TO INTERNAL BACKEND SET GOT FAILED, INSTACE WILL BE TERMINATED "+repr(e))
            postLaunchActionObject.terminate_instance(instanceId)
            return "POST LAUNCH ACTION FAILED WITH THIS INSTANCE"
        #________________________________________________________________________________________
        # ADDING TO EXTERNAL LOAD BALANCER
        elb_listener_port_list = list(map(lambda x: int(x.strip()), ELB_ListenerPortNumber.split(',')))
        try:
            for ePort in elb_listener_port_list:
                add_to_ELB_backend_set_response = postLaunchActionObject.add_to_backend_set(ELB_Id, ELB_BackendSetName, outsideInterfaceIpAddress, ePort)
                logger.info("POST LAUNCH ACTION {}: Add to External Backend Set response for listener port {} is {} ".format(identifier, ePort, repr(add_to_ELB_backend_set_response)))
        except Exception as e:
            logger.error(f"POST LAUNCH ACTION {identifier}: ADD TO EXTERNAL BACKEND SET GOT FAILED, INSTACE WILL BE TERMINATED "+repr(e))
            postLaunchActionObject.terminate_instance(instanceId)
            return "POST LAUNCH ACTION FAILED WITH THIS INSTANCE"
        #_______________________________________________________________________________________________________
        # Will wait for some time so that FTDv can finish up first boot and get ready to be configured.
        creation_time = utl.get_time_since_creation(instanceId)
        if creation_time < 8:
            end_time = time.time()
            time_elapsed = round(end_time - begin_time,2)
            logger.info(f"POST LAUNCH ACTION {identifier}: WAITING FOR FTDv TO FINISH FIRST TIME BOOT ...")
            time.sleep(250-time_elapsed)

        configure_ftdv_data = {}
        data = {}
        data["resourceId"] = instanceId
        configure_ftdv_data["data"] = data

        queue_manager.update_queue_data("COMPLETED")
        call_configure_ftdv_response = postLaunchActionObject.publish_message(configure_ftdv_topic_id,configure_ftdv_data)
        if call_configure_ftdv_response == True:
            logger.info(f"POST LAUNCH ACTION {identifier}: Configure FTDv Function has been called successfully")
            logger.info(f"POST LAUNCH ACTION {identifier} COMPLETED SUCCESSFULLY")
            return f"POST LAUNCH ACTION {identifier} COMPLETED SUCCESSFULLY"
        else:
            queue_manager.update_queue_data("FAILED")
            logger.error(f"POST LAUNCH ACTION {identifier} UNABLE TO RE-CALL CONFIGURE FTDv FUNCTION, INSTACE WILL BE TERMINATED")
            terminate_response = self.terminate_instance()
            queue_manager.reorder_queue()
            time.sleep(3)
            current_queue = queue_manager.read_queue()
            if len(current_queue) > 0:
                current_event = ast.literal_eval(current_queue["event_1"])
                data = {}
                data["resourceId"] = current_event["instanceId"]
                body["data"] = data
                body["ons_flag"] = "TRUE"
                postLaunchActionObject.publish_message(post_launch_actions_topic_id, body)
            return f"POST LAUNCH ACTION {identifier} UNABLE TO RE-CALL CONFIGURE FTDv FUNCTION, POST LAUNCH ACTION FAILED"
    else:
        logger.info(f"POST LAUNCH ACTION {identifier}:  Instance does not belongs to particular Instance Pool, Hence no action performed")
        return "Instance does not belongs to particular Instance Pool"
