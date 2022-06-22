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

Name:       scaleout_cron.py
Purpose:    To change CloudWatch Scheduled Event state for Scale-Out Lamda
"""
import json
import boto3
import os

def lambda_handler(event, context):
    """
    Purpose:    Lambda for changing Alarm state for Custom Scale-Out Lambda
    Parameters: events, context
    Returns:
    Raises:
    """
    try:
        print("Info:Received the event: " + json.dumps(event, indent=2))
        Eventclient = boto3.client('events')
        Cwclient = boto3.client('cloudwatch')
        #Reset the alarm, get alarm name from env variable scale-out-alarm
        cpu_upper_alarm_arn = os.environ['CPU_UPPER_ALARM_ARN']
        print("Info:Cpu Upper Threshold Alarm Env Variable Arn: "+cpu_upper_alarm_arn)
        alarm_arn_split_list = cpu_upper_alarm_arn.split(':')
        alarm_arn_split_list_len = len(alarm_arn_split_list)
        print("Info:Alarm Arn Split list length : "+str(alarm_arn_split_list_len))
        cpu_upper_alarm_name = str(alarm_arn_split_list[alarm_arn_split_list_len-1])
        print("Info:Alarm Name : "+cpu_upper_alarm_name)
        response = Cwclient.set_alarm_state(
                   AlarmName=cpu_upper_alarm_name,
                   StateValue='OK',
                   StateReason='Scaleout Multiple Alarm Check',
                   StateReasonData='')
        #Get so-ma-rule-name from env variable
        so_ma_event = os.environ['so_ma_event']
        print("Info:Scale Out MA event Name: "+so_ma_event)
        #response = Eventclient.disable_rule(Name=so_ma_event)
        #print("Info:Disabled the event")

    except Exception as e:
        print("Error in event handler: %s", str(e))
        return None
