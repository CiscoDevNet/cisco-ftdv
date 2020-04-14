import json
import boto3
import os

def lambda_handler(event, context):
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

