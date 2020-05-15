"""
Copyright (c) 2020 Cisco Systems Inc or its affiliates.

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
"""
import json
import os
from aws_methods import *


def lambda_handler(event, context):
    try:
        logger.info("Info:Received the event: " + json.dumps(event, indent=2))
        message = json.loads(event['Records'][0]['Sns']['Message'])
        logger.info("Info:SNS message JSON: " + json.dumps(message))
        # asg_info = message['Trigger']['Dimensions'][0]
        # asg_name = asg_info['value']
        logger.info("Info: ASG Name: " + ASG_NAME)
        scaleout_handler(ASG_NAME)
    except Exception as e:
        logger.error("Error in event handler: %s", str(e))
        return None


def scaleout_handler(asgname):
    try:
        asg_client = boto3.client('autoscaling')
        asg_response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asgname])
        # logger.info("Info: ASG Response : ", asg_response)
        # fixme Error: not all arguments converted during string formatting
        asg_maxsize = asg_response['AutoScalingGroups'][0]['MaxSize']
        logger.info("Info: ASG Max Size : %s ", str(asg_maxsize))
        instance_ids = []
        for i in asg_response['AutoScalingGroups']:
            for k in i['Instances']:
                instance_ids.append(k['InstanceId'])
        # check for maximum capacity before setting desired
        current_vms = len(instance_ids)
        if current_vms == asg_maxsize:
            logger.warn("Warning: Can not Scale, Reached the ASG Maximum Size")
            return None

        desired_vms = current_vms+1
        response = asg_client.set_desired_capacity(AutoScalingGroupName=asgname, DesiredCapacity=desired_vms,
                                                   HonorCooldown=True,)
        logger.debug(response)
        client = boto3.client('events')
        so_ma_event = os.environ['so_ma_event']
        response = client.enable_rule(Name=so_ma_event)
        print("Info:Enabled the event")
        logger.debug(response)
    except Exception as e:
        logger.error("Error in Scale Out handler: %s", str(e))
        return None
