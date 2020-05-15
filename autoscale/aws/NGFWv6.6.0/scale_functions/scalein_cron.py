import json
import boto3
import os

def lambda_handler(event, context):
    try:
        print("Info:Received the event: " + json.dumps(event, indent=2))
        Eventclient = boto3.client('events')
        Cwclient = boto3.client('cloudwatch')
        #Reset the alarm, get alarm name from env variable scale-in-alarm
        cpu_lower_alarm_arn = os.environ['CPU_LOWER_ALARM_ARN']
        print("Info:Cpu Lower Threshold Alarm Env Variable Arn: "+cpu_lower_alarm_arn)
        alarm_arn_split_list = cpu_lower_alarm_arn.split(':')
        alarm_arn_split_list_len = len(alarm_arn_split_list)
        print("Info:Alarm Arn Split list length : "+str(alarm_arn_split_list_len))
        cpu_lower_alarm_name = str(alarm_arn_split_list[alarm_arn_split_list_len-1])
        print("Info:Alarm Name : "+cpu_lower_alarm_name)
        response = Cwclient.set_alarm_state(
                   AlarmName=cpu_lower_alarm_name,
                   StateValue='OK',
                   StateReason='Scaleout Multiple Alarm Check',
                   StateReasonData='')
        #Get si-ma-evengt name from env variable
        si_ma_event = os.environ['si_ma_event']
        print("Info:Scale-in MA event Name: "+si_ma_event)
       # response = Eventclient.disable_rule(Name=si_ma_event)
       # print("Disabled the event")
    except Exception as e:
        print("Error in event handler: %s", str(e))
        return None