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
--------------------------------------------------------------------------------

Name:       scalein.py
Purpose:    This file has Lambda Handler for scalein lambda
"""

import json
import boto3
import datetime
import time
import sys
import os
import constant as const

def lambda_handler(event, context):
    """
    Purpose:    Scale-In Lambda Handler
    Parameters: events, context
    Returns:
    Raises:
    """
    try:
        print("Info:Received the event: " + json.dumps(event, indent=2))
        message = json.loads(event['Records'][0]['Sns']['Message'])
        print("Info:SNS message JSON: " + json.dumps(message))
        print("Info: ASG Name: " + const.ASG_NAME)
        scalein_handler(const.ASG_NAME)
    except Exception as e:
        print("Error in event handler: %s", str(e))
        return None


def scalein_handler(asgname):
    """
    Purpose:    To decrement desired count by one
    Parameters: AutoScale group name
    Returns:
    Raises:
    """
    asg_client = boto3.client('autoscaling')
    asg_response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asgname])
    print("Info : ASG Response",asg_response)
    region = asg_client.meta.region_name
    print("Info: ASG Region",region)
    asg_minsize = asg_response['AutoScalingGroups'][0]['MinSize']
    print("Info: ASG Min Size",asg_minsize)
    instances=asg_response["AutoScalingGroups"][0]["Instances"]
    instanceids=[]
    instanceids_unprotected=[]
    for i in instances:
        instanceids.append(i["InstanceId"])
        if(i['ProtectedFromScaleIn']==False):
            instanceids_unprotected.append(i["InstanceId"])
    print("Info : Printing scale-in unprotected Instance Ids",instanceids_unprotected)
    print("Info : Printing Instance Ids",instanceids)

    current_vms = len(instanceids)
    if current_vms == asg_minsize:
        print("Warning: Can not Scale-in, Reached the ASG Minimum Size")
        return None

    if len(instanceids_unprotected) == 0:
        print("Warning: Can not Scale-In, there are no scale-in unprotected VMs in ASG")
        return None

    cw = boto3.client('cloudwatch',region)
    instance_to_load = dict()
    #loop starts
    for iid in instanceids_unprotected:
        metriclist = cw.get_metric_statistics(
                     Period=300,
                     StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=600),
                     EndTime=datetime.datetime.utcnow(),
                     MetricName='CPUUtilization',
                     Namespace='AWS/EC2',
                     Statistics=['Average'],
                     Dimensions=[{'Name':'InstanceId', 'Value':iid}]
                     )
        datapoints = metriclist['Datapoints']
        print("Info:Printing Datapoints",datapoints)
        sumofmetric = 0
        k=0
        for eachpoint in datapoints:
            sumofmetric+=eachpoint['Average']
            k+=1

        avgofmetrics = sumofmetric/k
        print("Info: Printing Average of Metrics Corresponding to Instance ID:",iid,avgofmetrics)
        instance_to_load[iid]=avgofmetrics

    #loop ends
    #comparing 2nd element of each tuple
    print("Info: Listing Instance to Load Map/n",instance_to_load)
    instid = min(instance_to_load, key=instance_to_load.get)
    print("Info: Instance to Kill",instid)

    response = asg_client.terminate_instance_in_auto_scaling_group(
    InstanceId=instid,
    ShouldDecrementDesiredCapacity=True)

    #enabling the event
    client = boto3.client('events')
    si_ma_event = os.environ['si_ma_event']
    response = client.enable_rule(Name=si_ma_event)
    print(response)
    return None
