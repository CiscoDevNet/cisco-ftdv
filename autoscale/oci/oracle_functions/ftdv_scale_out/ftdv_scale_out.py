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

Name:       scale_out.py
Purpose:    This python file has FTDv related class & methods
            Classes in this python files are being used for 
            performing Scale-Out action in OCI ASAv Autoscale.
"""

import io
import json
import logging

import oci
from fdk import response

logging.basicConfig(force=True, level="INFO")
logger = logging.getLogger()

class ScaleOut:
    def __init__(self, auth):
        self.computeManagementClient = oci.core.ComputeManagementClient(config={}, signer=auth)
        self.retry = 3

    def get_instance_pool_info(self, instancePoolId):
        """
        Purpose:   To get information of the Instance Pool 
        Parameters: 
        Returns:    List(Instances)
        Raises:
        """
        for i in range(0,self.retry):
            try:
                get_instance_pool_response = self.computeManagementClient.get_instance_pool(instance_pool_id = instancePoolId).data
                return get_instance_pool_response
            except Exception as e:
                logger.error("SCALE-OUT: ERROR IN RETRIEVING INSTANCE POOL INFORMATION, RETRY COUNT: {0}, ERROR: {1}".format(str(i), repr(e)))
                continue
        
        return None

    def get_all_instances_in_pool(self, compartmentId, instancePoolId):
        """
        Purpose:   To get ID of all instances in the Instance Pool 
        Parameters: 
        Returns:    List(Instances)
        Raises:
        """
        for i in range(0, self.retry):
            try:
                all_instances_in_instance_pool = self.computeManagementClient.list_instance_pool_instances(
                                            compartment_id = compartmentId,
                                            instance_pool_id = instancePoolId).data

                
                return all_instances_in_instance_pool

            except Exception as e:
                logger.error("SCALE-OUT: ERROR IN GETTING INSTANCE LIST FROM INSTANCE POOL, RETRY COUNT:{0}, REASON:{1}".format(str(i+1), repr(e)))
                continue
        
        return None

    def update_instance_pool_size(self,instancePoolId):
        """
        Purpose:   To modify instance pool size. (No. of instances)
        Parameters: Instance Pool ID
        Returns:    Response of type Instance Pool
        Raises:
        """            
        instance_pool_information = self.get_instance_pool_info(instancePoolId)
        
        for i in range(0,self.retry):
            try:
                noRetry = oci.retry.NoneRetryStrategy()
                current_pool_size = int(instance_pool_information.size)
                
                target_pool_size = int(current_pool_size + 1)
                update_instance_pool_response = self.computeManagementClient.update_instance_pool( instance_pool_id = instancePoolId,
                    update_instance_pool_details = oci.core.models.UpdateInstancePoolDetails(size = target_pool_size),
                    retry_strategy = noRetry).data

                return update_instance_pool_response
            
            except Exception as e:
                logger.error("SCALE-OUT Event: Unable to update Instance Pool size of instance pool ID : {0} Rsponse: {1} Retry Count {2}".format(instancePoolId, repr(e), str(i)))
                continue
        
        return None


def handler(ctx, data: io.BytesIO = None):
    try:
        body = json.loads(data.getvalue())
        alarm_message_type = body.get("type")

        if alarm_message_type == "FIRING_TO_OK" or alarm_message_type == "RESET":
            logger.info("SCALE-OUT: ALARM HAS BEEN MOVED TO 'OK' STATE")
            return "False Alarm"
        alarm_name = body.get("title")
        logger.info("SCALE-OUT HAS BEEN CALLED BY ALARM : {}".format(alarm_name))
    except Exception as ex:
        logger.error('SCALE-OUT: ERROR IN PARSING JSON PAYLOAD' + repr(ex))
        return "SCALE-OUT: ERROR IN PARSING JSON PAYLOAD"
    try:
        environmentVariables = ctx.Config()
        instancePoolId = environmentVariables["instance_pool_id"]
        maxInstanceCount = int(environmentVariables["max_instance_count"])
        compartmentId = environmentVariables["compartment_id"]
    except Exception as e:
        logger.error("SCALE-OUT Event: ERROR IN RETRIEVING ENVIRONMENT VARIABLES: "+repr(e))
        return None

    try:
        signer = oci.auth.signers.get_resource_principals_signer()
    except Exception as e:
        logger.error("SCALE-OUT Event: ERROR IN OBTAINING SIGNER: "+repr(e))
        return None
    
    scaleOutObject = ScaleOut(signer)

    # Checking if instance pool is not under scaling state already
    instance_pool_info = scaleOutObject.get_instance_pool_info(instancePoolId)
    if str(instance_pool_info.lifecycle_state) == "SCALING":
        logger.info("SCALE-OUT: INSTANCE POOL IS ALREADY IN SCALING STATE, ABORTING CURRENT OPERATION TO AVOID ANY CONFLICT")
        return "SCALE-OUT: INSTANCE POOL IS ALREADY IN SCALING STATE"

    try:
        all_instances_in_pool = scaleOutObject.get_all_instances_in_pool(compartmentId,instancePoolId)
        if all_instances_in_pool == None:
            return

        currentRunningInstanceList = []
        for instance in all_instances_in_pool:
            if instance.state == "Running":
                currentRunningInstanceList.append(instance)

        if len(currentRunningInstanceList) >= maxInstanceCount:
            logger.info("SCALE-OUT Event: Autoscale Maximum running instance count has reached, Can't add anymore instance")
            return "Autoscale Maximum running instance count has reached, Can't add anymore instance"
    
    except Exception as e:
        logger.error("SCALE-OUT Event: ERROR OCCURRED IN INSTANCE COUNT CHECK "+ repr(e))

    update_instance_pool_size_response = scaleOutObject.update_instance_pool_size(instancePoolId)
    if update_instance_pool_size_response == None:
        logger.info("SCALE-OUT OPERATION GOT FAILED")
        return "SCALE-OUT OPERATION GOT FAILED"
    else:
        logger.info("SCALE-OUT PERFORMED SUCCESSFULLY")

    return response.Response(
        ctx, response_data=json.dumps(
            {"SCALE-OUT Event Response": "SUCCESSFUL"}),
        headers={"Content-Type": "application/json"}
    )
