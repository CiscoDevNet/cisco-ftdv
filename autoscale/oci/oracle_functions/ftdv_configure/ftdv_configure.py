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

Name:       ftdv_configure.py
Purpose:    This python file is used for configuring the ftdv with FMC.
            These classes will be initialized in the oracle function
"""

import io
import json
import logging

import ast
import time
import oci
from fdk import response

from utility import TokenCaller
import utility as utl
from cisco_oci import OCIInstance
from manager import *

logging.basicConfig(force=True, level="INFO")
logging.getLogger("paramiko").setLevel(logging.WARNING)
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
            raise Exception(f"FTDv CONFIGURE {self.identifier}: ERROR IN RETRIEVING QUEUE  "+repr(e))
    
    def write_queue(self, queue_data):
        try:
            update_function_response = self.functions_client.update_function(
                function_id = self.funcId,
                update_function_details=oci.functions.models.UpdateFunctionDetails(
                    config=queue_data)).data
            return
        except Exception as e:
            raise Exception(f"FTDv CONFIGURE {self.identifier}: ERROR IN WRITING QUEUE "+repr(e))
            
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
            raise Exception(f"FTDv CONFIGURE {self.identifier}: ERROR IN CREATING QUEUE ENTRY "+repr(e))
    
    def update_queue_data(self, fc_status):
        try:
            current_queue = self.read_queue()
            target_event = ast.literal_eval(current_queue["event_1"])
            target_event["ftdv_configure_status"] = fc_status
            current_queue["event_1"] = str(target_event)
            self.write_queue(current_queue)
            return
        except Exception as e:
            raise Exception(f"FTDv CONFIGURE {self.identifier}: ERROR IN UPDATING QUEUE DATA "+repr(e))

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
            raise Exception(f"FTDv CONFIGURE {self.identifier}: ERROR IN RE-ORDERING QUEUE DATA "+repr(e))

def handler(ctx, data: io.BytesIO = None):
    try:
        begin_time = int(time.time())         # To Track time throughout the execution
        body = json.loads(data.getvalue())
        data = body.get("data")
        instanceId = data.get("resourceId")
        identifier = instanceId[-5:]          # To better identify and track logs 
        logger.info("{}:----CONFIGURE FTDv CALLED----".format(identifier))
    except (Exception, ValueError) as ex:
        logger.error('FTDv CONFIGURE: Error parsing json payload: ' + str(ex))
        terimate_instance_response = utl.terminate_instance(instanceId)

    try:
        environmentVariables = ctx.Config()
        environmentVariables["begin_time"] = str(begin_time)
        instancePoolId = environmentVariables["instance_pool_id"]
        compartmentId = environmentVariables["compartment_id"]
        autoScaleGroupPrefix = environmentVariables["autoscale_group_prefix"]
        appName = autoScaleGroupPrefix + "_application"
        
        configure_ftdv_topic_id = environmentVariables["configure_ftdv_topic_id"]
        ftdv_username = environmentVariables["ftdv_username"]
        ftdv_license_type = environmentVariables["ftdv_license_type"]
        ftdv_configuration_json_url = environmentVariables["ftdv_configuration_json_url"]
        
        fmc_ip = environmentVariables["fmc_ip"]
        fmc_username = environmentVariables["fmc_username"]
        fmc_device_group_name = environmentVariables["fmc_device_group_name"]
        post_launch_actions_topic_id = environmentVariables["post_launch_actions_topic_id"]
        postLaunchFuncId = environmentVariables["post_launch_func_id"]
        cryptEndpoint = environmentVariables["cryptographic_endpoint"]
        master_key_id = environmentVariables["master_key_id"]
        environmentVariables["ftdv_password"] = utl.decrypt_cipher(str(environmentVariables["ftdv_encrypted_password"]), cryptEndpoint, master_key_id)
        environmentVariables["fmc_password"]  = utl.decrypt_cipher(str(environmentVariables["fmc_encrypted_password"]),cryptEndpoint, master_key_id)
        
    except Exception as e:
        logger.error(f"FTDv CONFIGURE {identifier}: ERROR IN RETRIEVING ENVIRONMENT VARIABLES, INSTACE WILL BE TERMINATED"+repr(e))
        return f"CONFIGURE FTDv FAILED FOR {instanceId}"
    #________________________________________________________________________________________________
    # ADDING COUNTER TO TRACK RECALLING
    if not ("counter" in body):
        body["counter"] = 1
        current_counter = 1
    else:
        current_counter = int(body["counter"]) + 1
        body["counter"] = current_counter

    ftdvInstance = OCIInstance(compartmentId, instanceId)
    #__________________________________________________________________________________________________
    # UPDATING STATUS IN QUEUE
    queueManager = CustomQueue(postLaunchFuncId)
    queueManager.identifier = identifier
    if current_counter == 1:
        try:
            queueManager.update_queue_data("IN_PROGRESS")
        except Exception as e:
            logger.error(f"FTDv CONFIGURE {identifier}: ERROR IN QUEUE MANAGEMENT {repr(e)}")
    #_________________________________________________________________________________________________   
    # OBTAINING USER CONFIGURATION (JSON) 
    try:
        json_var = utl.get_fmc_configuration_input(ftdv_configuration_json_url)
    except Exception as e:
        logger.error(f"FTDv CONFIGURE {identifier}: ERROR IN CONFIGURATION.JSON, PLEASE CHECK IF PRE-AUTHENTICATED URL IS WORKING AND INPUTS ARE IN PROPER JSON FORMAT  "+repr(e))
        return "ERROR IN CONFIGURATION.JSON"
    #__________________________________________________________________________________________________    
    # OBTAINING AUTH TOKEN FOR FMC FROM "FTDv TOKEN MANAGER"(ORACLE FUNCTION)
    try: 
        tokenHandler = TokenCaller(compartmentId, appName)
        if "token_endpoint_url" in environmentVariables:
            endpoint = environmentVariables['token_endpoint_url']
        else:
            endpoint = tokenHandler.update_application_variables()
            environmentVariables["token_endpoint_url"] = endpoint
    
        token = tokenHandler.get_token(endpoint)
        if token == None:
            raise Exception(f"FTDv CONFIGURE {identifier}: NO TOKEN RECEIVED")
    
    except Exception as e: 
        logger.error((f"FTDv CONFIGURE {identifier}: UNEXPECTED ERROR IN GETTING TOKEN "+repr(e)))
        return ftdvInstance.publish_message(configure_ftdv_topic_id, body)
    #____________________________________________________________________________________________________
    # OBTAINING FMC OBJECT
    try:
        fmc = fmc_cls_init(environmentVariables, json_var, token)
    except Exception as e:
        logger.error(f"FTDv CONFIGURE {identifier}: ERROR IN FMC OBJECT CREATION  "+repr(e))
        return ftdvInstance.publish_message(configure_ftdv_topic_id, body)
    #_____________________________________________________________________________________________________
    # CHEKING COUNTER TO TRACK RECALLING
    MAX_RECALL = 10 # Maximum number of time function will be recalled.
    if current_counter > MAX_RECALL:
        # WILL BE DE-REGISTERING FTDv, IN CASE IF FAILED TO CONFIGURE PROPERLY AFTER ALL RETRIES  
        try:
            dereg_ftdv_response = fmc.deregister_device(autoScaleGroupPrefix+"_"+str(instanceId[-12:]))
            logger.info(f"FTDv CONFIGURE {identifier}: "+repr(dereg_ftdv_response))
        except Exception as e:
            logger.error(f"FTDv CONFIGURE {identifier}: UNABLE TO DE-REGISTER FTDv"+repr(e))
        # WILL REMOVE ITS ENTRY FROM QUEUE
        try:
            queueManager.reorder_queue()
        except Exception as e:
            logger.error(f"FTDv CONFIGURE {identifier}: ERROR IN QUEUE REORDER {repr(e)}")
        logger.critical(f"FTDv CONFIGURE {identifier}: MAX RECALL LIMIT OF CONFIGURE FTDv FUNCTION REACHED !!! INSTACE WILL BE TERMINATED")
        # WILL TERMINATE THE FAILES INSTANCE
        terminate_instance_response = utl.terminate_instance(instanceId)
        # POST LAUNCH WILL BE CALLED TO START WORKING ON NEXT INSTANCE IN QUEUE IF ANY.
        current_queue = queueManager.read_queue()
        if len(current_queue) > 0:
            current_event = ast.literal_eval(current_queue["event_1"])
            data = {}
            data["resourceId"] = current_event["instanceId"]
            body["data"] = data
            body["ons_flag"] = "TRUE"
            ftdvInstance.publish_message(post_launch_actions_topic_id, body)
            logger.info(f"FTDv CONFIGURE {identifier}: Post Launch Action called successfully, Queue length: {len(current_queue)}")

        return "CONFIGURE FTDv MAX RECALL LIMIT OF CONFIGURE FTDv FUNCTION REACHED"
    #________________________________________________________________________________________________________       
    # OBTAINING FTDv OBJECT
    try: 
        ftd = ftd_cls_init(compartmentId, instanceId, environmentVariables, json_var, fmc)
    except Exception as e:
        logger.error(f"FTDv CONFIGURE {identifier}: ERROR IN FTD OBJECT CREATION  "+repr(e))
        return ftdvInstance.publish_message(configure_ftdv_topic_id, body)
    #___________________________________________________________________________________________________________
    try:
        # FTDv READY SECTION
        logger.info("FTDv CONFIGURE {}: --VM READY STARTED ({})-- TIME ELAPSED: {} SEC".format(identifier, current_counter, int(time.time()-begin_time)))
        vm_ready_response = execute_vm_ready_first(ftd,2)
        if vm_ready_response == 'FAIL':
            logger.error(f"FTDv CONFIGURE {identifier}: --VM READY FAILED-- Recalling")
            return ftd.publish_message(configure_ftdv_topic_id, body)
        else:
            logger.info("FTDv CONFIGURE {}: --VM READY COMPLETED ({})-- TIME ELAPSED: {} SEC".format(identifier, current_counter, int(time.time()-begin_time)))

        if int(time.time()-begin_time) > 200:
            logger.info(f"FTD CONFIGURE {identifier}: Recalling as ready exceeded time limit")
            return ftd.publish_message(configure_ftdv_topic_id, body)
        #________________________________________________________________________________________________________ 
        # FTDv REGISTRATION SECTION
        logger.info("FTDv CONFIGURE {}: --VM REGISTER STARTED ({})-- TIME ELAPSED: {} SEC".format(identifier, current_counter, int(time.time()-begin_time)))
        vm_register_respone = execute_vm_register_first(ftd)
        if vm_register_respone == 'FAIL':
            logger.error(f"FTDv CONFIGURE {identifier}: --VM REGISTER FAILED-- Recalling")
            return ftd.publish_message(configure_ftdv_topic_id, body)
        else:        
            logger.info("FTDv CONFIGURE {}: --VM REGISTER COMPLETED ({})-- TIME ELAPSED: {} SEC".format(identifier, current_counter, int(time.time()-begin_time)))

        if int(time.time()-begin_time) > 200:
            logger.info(f"FTD CONFIGURE {identifier}: Recalling as register exceeded time limit")
            return ftd.publish_message(configure_ftdv_topic_id, body)
        #________________________________________________________________________________________________________________ 
        # FTDv CONFIGURATION SECTION
        logger.info("FTDv CONFIGURE {}: --VM CONFIGURE STARTED ({})-- TIME ELAPSED: {} SEC".format(identifier, current_counter, int(time.time()-begin_time)))
        vm_configure_response = execute_vm_configure_first(ftd)
        if vm_configure_response == 'FAIL':
            logger.error(f"FTDv CONFIGURE {identifier}: --VM CONFIGURE FAILED-- recalling")
            return ftd.publish_message(configure_ftdv_topic_id, body)
        else:
            logger.info("FTDv CONFIGURE {}: --VM CONFIGURE COMPLETED ({})-- TIME ELAPSED: {} SEC".format(identifier, current_counter, int(time.time()-begin_time)))

        if int(time.time()-begin_time) > 200:
            logger.info("FTD CONFIGURE: Recalling as configure exceeded time limit")
            return ftd.publish_message(configure_ftdv_topic_id, body)
        #________________________________________________________________________________________________________________ 
        # FTDv DEPLOYMENT SECTION
        logger.info("FTDv CONFIGURE {}: --VM DEPLOY STARTED ({})-- TIME ELAPSED: {} SEC".format(identifier, current_counter, int(time.time()-begin_time)))
        vm_deploy_response = execute_vm_deploy_first(ftd, fmc)
        if vm_deploy_response == 'FAIL':
            logger.error(f"FTDv CONFIGURE {identifier}: --VM DEPLOY FAILED-- recalling")
            return ftd.publish_message(configure_ftdv_topic_id, body)
        else:
            logger.info("FTDv CONFIGURE {}: --VM DEPLOY COMPLETED ({})-- TIME ELAPSED: {} SEC".format(identifier, current_counter, int(time.time()-begin_time)))
        #_________________________________________________________________________________________________________________
        # UPDATING THE QUEUE AND CALLING POST LAUNCH TO START WORKING ON NEXT INSTANCE IN QUEUE
        try:
            queueManager.update_queue_data("COMPLETED")
            queueManager.reorder_queue()
            time.sleep(3)
            current_queue = queueManager.read_queue()
            if len(current_queue) > 0:
                current_event = ast.literal_eval(current_queue["event_1"])
                data = {}
                data["resourceId"] = current_event["instanceId"]
                body["data"] = data
                body["ons_flag"] = "TRUE"
                ftdvInstance.publish_message(post_launch_actions_topic_id, body)
                logger.info(f"FTDv CONFIGURE {identifier}: Post Launch Action called successfully, Queue length: {len(current_queue)}")
        except Exception as e:
            logger.error(f"FTDv CONFIGURE {identifier}: ERROR IN QUEUE REORDER {repr(e)}")
        #_________________________________________________________________________________________________________________
        
        logger.info(f"Configure FTDv function performed successfully for {identifier}")
        return response.Response(
            ctx, response_data = json.dumps(
                {"Configure FTDv response": "Configure FTDv function performed successfully"}),
            headers={"Content-Type": "application/json"})

    except Exception as e:
        logger.error(e)
        return ftd.publish_message(configure_ftdv_topic_id, body)
        