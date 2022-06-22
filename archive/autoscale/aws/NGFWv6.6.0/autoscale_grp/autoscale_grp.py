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

Name:       autoscale_grp.py
Purpose:    This is the main Lambda handler file( autoscale group).
            Takes AWS Lambda triggers & routes the request to appropriate function module.
"""

import time
from aws_methods import *
from datetime import datetime, timezone
import constant as const

# Initialize ASG group class
asg = ASG()
# Initialize EC2 class
ec2_client = EC2()


# LifeCycle Hook Handler
def lambda_handler(event, context):
    """
    Purpose:    Main Lambda functions of AutoScale Group
    Parameters: AWS Events (cloudwatch, SNS)
    Returns:
    Raises:
    """
    put_line_in_log('AutoScale Group Lambda Handler started', 'thick')
    logger.info("Received event: " + json.dumps(event, separators=(',', ':')))

    # EC2 Lifecycle Action
    try:
        instance_id = event['detail']['EC2InstanceId']
        LifecycleHookName = event['detail']['LifecycleHookName']
        AutoScalingGroupName = event['detail']['AutoScalingGroupName']
        eventType = event["detail-type"]
        LifecycleTransition = event['detail']['LifecycleTransition']
    except KeyError as e:
        logger.debug("Error occurred: {}".format(repr(e)))
        logger.info("Not an EC2 Lifecycle CloudWatch event!")
        pass
    else:
        logger.info("Cloud Watch Event Triggered for group {}".format(AutoScalingGroupName))
        logger.info("Triggered Event {}".format(eventType))
        logger.info("Life Cycle Transition {}".format(LifecycleTransition))

        logger.debug("Complete Event {}".format(event))

        # Subscribed only for Lifecycle Action event from cloud watch
        if event["detail-type"] == "EC2 Instance-launch Lifecycle Action":
            status = execute_create_interface_attach_register(instance_id)
            if status == 'SUCCESS':
                asg.complete_lifecycle_action_success(LifecycleHookName, AutoScalingGroupName, instance_id)
            else:
                asg.complete_lifecycle_action_failure(LifecycleHookName, AutoScalingGroupName, instance_id)
        elif event["detail-type"] == "EC2 Instance-terminate Lifecycle Action":
            state = ec2_client.get_instance_state(instance_id)
            if state != 'terminated' or state is not None:
                status = deregister_instance_from_tg(instance_id)
            else:
                logger.info("Instance is already Terminated or No valid State found, "
                            "unable to get private IP to de-register from TGs")
                status = 'FAIL'
            if status == 'SUCCESS':
                asg.complete_lifecycle_action_success(LifecycleHookName, AutoScalingGroupName, instance_id)
            else:
                asg.complete_lifecycle_action_failure(LifecycleHookName, AutoScalingGroupName, instance_id)
        else:
            logger.error("Not a EC2 Instance Lifecycle Action")
        return

    # SNS Event
    try:
        if event["Records"][0]["EventSource"] == "aws:sns":
            sns_data = event["Records"][0]["Sns"]
            handle_sns_event(sns_data)
    except Exception as e:
        logger.info("Exception occurred {}".format(repr(e)))
        logger.info("Received an event but not a SNS notification event")
        pass

    put_line_in_log('AutoScale Group Lambda Handler finished', 'thick')
    return


# Handle Events & redirect to functions
def handle_sns_event(sns_data):
    """
    Purpose:    Handler for SNS event
    Parameters: SNS data from Lambda handler
    Returns:
    Raises:
    """
    put_line_in_log('SNS Handler', 'thin')
    logger.debug("SNS data: " + json.dumps(sns_data, separators=(',', ':')))
    msg = sns_data['Message']
    msg_processed = msg.replace("\\", "")
    msg_json = json.loads(msg_processed)
    logger.info("SNS Message: " + json.dumps(msg_json, separators=(',', ':')))
    if msg_json['NewStateValue'] == 'ALARM' and msg_json["Trigger"]['MetricName'] == 'UnHealthyHostCount':
        instance_tg_health_doctor()
        set_alarm_state(msg_json['AlarmName'], 'INSUFFICIENT_DATA')  # Set the alarm to 'INSUFFICIENT_DATA' or 'OK'
    put_line_in_log('SNS Handler finished', 'thin')
    return


def execute_create_interface_attach_register(instance_id):
    """
    Purpose:    This creates, attaches interfaces to NGFW, and registers the IP(outside) to LB
    Parameters: Instance Id
    Returns:    SUCCESS, FAIL
    Raises:
    """
    # Get Availability zone & subnets
    instance_az = ec2_client.get_instance_az(instance_id)
    logger.info("EC2 instance has been launched in AZ: " + instance_az)
    subnets_list_in_az = ec2_client.get_subnet_list_in_az(instance_az)
    logger.info("List of subnets in " + instance_az)
    logger.info(subnets_list_in_az)

    # Get the security group ID of this instance
    sec_grp_id = ec2_client.get_security_group_id(instance_id)
    logger.info("Security group id found for instance: " + sec_grp_id)

    put_line_in_log('Attaching Diag Interface', 'dot')
    # Create and Attach diag interface from mgmt subnet
    eni_name = instance_id + const.DIAG_ENI_NAME
    subnet_id = ec2_client.get_mgmt_subnet_id(instance_id)
    interface_id = ec2_client.create_interface(subnet_id, sec_grp_id, eni_name)
    if interface_id:
        attachment, err = ec2_client.attach_interface(interface_id, instance_id, 1)
        if not attachment:
            ec2_client.delete_interface(interface_id)
            if len(re.findall('already has an interface attached at', str(err))) >= 1:
                logger.warn("Already has an attached network interface at device index: '1'")
                pass
            put_line_in_log('Attaching Diag Interface: FAILED', 'dot')
            return 'FAIL'
    else:
        put_line_in_log('Attaching Diag Interface: FAILED', 'dot')
        return 'FAIL'
    put_line_in_log('Attaching Inside Interface', 'dot')
    # Create and Attach inside interface from inside subnet
    eni_name = instance_id + const.INSIDE_ENI_NAME
    subnet_id = get_common_member_in_list(subnets_list_in_az, user_input['INSIDE_SUBNET_ID_LIST'])
    interface_id = ec2_client.create_interface(str(subnet_id[0]), sec_grp_id, eni_name)
    if interface_id:
        attachment, err = ec2_client.attach_interface(interface_id, instance_id, 2)
        if not attachment:
            ec2_client.delete_interface(interface_id)
            if len(re.findall('already has an interface attached at', str(err))) >= 1:
                logger.warn("Already has an attached network interface at device index: '2'")
                pass
            put_line_in_log('Attaching Inside Interface: FAILED', 'dot')
            return 'FAIL'
    else:
        put_line_in_log('Attaching Inside Interface: FAILED', 'dot')
        return 'FAIL'

    put_line_in_log('Attaching Outside Interface', 'dot')
    # Create and Attach outside interface from outside subnet
    eni_name = instance_id + const.OUTSIDE_ENI_NAME
    subnet_id = get_common_member_in_list(subnets_list_in_az, user_input['OUTSIDE_SUBNET_ID_LIST'])
    interface_id = ec2_client.create_interface(str(subnet_id[0]), sec_grp_id, eni_name)
    if interface_id:
        attachment, err = ec2_client.attach_interface(interface_id, instance_id, 3)
        if not attachment:
            ec2_client.delete_interface(interface_id)
            if len(re.findall('already has an interface attached at', str(err))) >= 1:
                logger.warn("Already has an attached network interface at device index: '3'")
                pass
            put_line_in_log('Attaching Outside Interface: FAILED', 'dot')
            return 'FAIL'
    else:
        put_line_in_log('Attaching Outside Interface: FAILED', 'dot')
        return 'FAIL'
    put_line_in_log('Registering to Target Groups', 'dot')
    tgARN, ports = ec2_client.get_tgARN_port_from_lb(user_input['LB_ARN_OUTSIDE'])
    if tgARN is not None and ports is not None:
        list_len = len(tgARN)
        for i in range(0, list_len):
            logger.info("Registering Port: %s " % str(ports[i]))
            # Add outside interface ip to target group
            target = ec2_client.register_target_outside(instance_id, tgARN[i], ports[i])
            if not target:
                logger.error("Unable to register target for Target Group: " + str(tgARN[i]) + " for port:" + str(ports[i]))
                put_line_in_log('Registering to Target Groups: FAILED', 'dot')
                return 'FAIL'
    put_line_in_log('Registering to Target Groups: SUCCESS', 'dot')
    return 'SUCCESS'


def deregister_instance_from_tg(instance_id):
    """
    Purpose:    To De-register instance from TG
    Parameters: Instance Id
    Returns:    SUCCESS, FAIL
    Raises:
    """
    put_line_in_log('De-registering from Target Groups', 'dot')
    failure_flag = False
    # Delete outside interface ip from target group
    logger.info("Removing " + instance_id + " from Target Group(s)")
    tgARN, ports = ec2_client.get_tgARN_port_from_lb(user_input['LB_ARN_OUTSIDE'])
    if tgARN is not None and ports is not None:
        list_len = len(tgARN)
        for i in range(0, list_len):
            logger.info("De-Registering Port: %s " % str(ports[i]))
            # Add outside interface ip to target group
            target = ec2_client.deregister_target_instance_outside(instance_id, tgARN[i], ports[i])
            if not target:
                logger.error(
                    "Unable to de-register target, for Target Group: " + str(tgARN[i]) + " for Port: " + str(ports[i]))
                failure_flag = True
                pass

    time.sleep(user_input['DEREGISTRATION_DELAY'])  # Wait for DEREGISTRATION_DELAY sec before completing lifecycle hook
    if failure_flag is False:
        put_line_in_log('De-registering from Target Groups finished: SUCCESS', 'dot')
        return 'SUCCESS'
    else:
        put_line_in_log('De-registering from Target Groups finished: FAIL', 'dot')
        return 'FAIL'


def deregister_ip_from_tg(ip):
    """
    Purpose:    To De-register IP from TG
    Parameters: IP
    Returns:    SUCCESS, FAIL
    Raises:
    """
    put_line_in_log('De-registering from Target Groups', 'dot')
    failure_flag = False
    logger.info("Removing " + ip + " from Target Group(s)")
    tgARN, ports = ec2_client.get_tgARN_port_from_lb(user_input['LB_ARN_OUTSIDE'])
    if tgARN is not None and ports is not None:
        list_len = len(tgARN)
        for i in range(0, list_len):
            logger.info("De-Registering Port: %s " % str(ports[i]))
            # Add outside interface ip to target group
            target = ec2_client.deregister_target_ip_outside(ip, tgARN[i], ports[i])
            if not target:
                logger.error(
                    "Unable to de-register target, for Target Group: " + str(tgARN[i]) + " for Port: " + str(ports[i]))
                failure_flag = True
                pass

    if failure_flag is False:
        put_line_in_log('De-registering from Target Groups finished: SUCCESS', 'dot')
        return 'SUCCESS'
    else:
        put_line_in_log('De-registering from Target Groups finished: FAIL', 'dot')
        return 'FAIL'


def instance_tg_health_doctor():
    """
    Purpose:    To remove un-healthy instances from TG if satisfies conditions
    Parameters:
    Returns:    SUCCESS, FAIL
    Raises:
    """
    put_line_in_log('Instance Doctor', 'dot')
    asg_name = ''
    now = datetime.now(timezone.utc)
    unhealthy_ip_targets = []
    killable_ngfw_instance = []
    try:
        tg_arn, ports = ec2_client.get_tgARN_port_from_lb(user_input['LB_ARN_OUTSIDE'])
        if tg_arn is not None:
            list_len = len(tg_arn)
            for i in range(0, list_len):
                logger.info(tg_arn[i])
                targets = ec2_client.get_target_health(tg_arn[i])
                list_len = len(targets['TargetHealthDescriptions'])
                if list_len > 0:
                    for i in range(0, list_len):
                        target = targets['TargetHealthDescriptions'][i]
                        if target['TargetHealth']['State'] == 'unhealthy':
                            unhealthy_ip_targets.append(target['Target']['Id'])
    except Exception as e:
        logger.debug("Exception occurred: {}".format(repr(e)))
        logger.info("Unable to get unhealthy IP targets!")
        return

    try:
        unhealthy_ip_targets = list(dict.fromkeys(unhealthy_ip_targets))
        logger.info("IPs: " + str(unhealthy_ip_targets) + " found unhealthy!")
        list_len = len(unhealthy_ip_targets)
        if list_len > 0:
            for i in range(0, list_len):
                try:
                    unhealthy_instance = ec2_client.get_describe_instance_private_ip(unhealthy_ip_targets[i])
                    instance = unhealthy_instance['Reservations'][0]['Instances'][0]
                    unhealthy_instance_id = instance['InstanceId']
                except Exception as e:
                    logger.info("Exception occurred {}".format(repr(e)))
                    logger.info("Removing IP: " + str(unhealthy_ip_targets[i]) + " as no associated Instance found!")
                    deregister_ip_from_tg(unhealthy_ip_targets[i])
                    put_line_in_log('Instance Doctor finished', 'dot')
                    return
                for val in instance['Tags']:
                    if val['Key'] == "aws:autoscaling:groupName":
                        asg_name = str(val['Value'])
                if asg_name == user_input['ASG_NAME']:
                    days = (now - instance['LaunchTime']).days
                    hours = (now - instance['LaunchTime']).seconds / 60 / 60
                    logger.info('%s, %s, %d days %d hours alive' % (unhealthy_instance_id,
                                                                    instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S'),
                                                                    days, hours))
                    if days > 0 or hours > 1:
                        killable_ngfw_instance.append(unhealthy_instance_id)
                else:
                    logger.info(unhealthy_instance_id + " is not part of " + str(user_input['ASG_NAME']))
                    logger.info("Removing IP: " + str(unhealthy_ip_targets[i]) + " as it is not of an NGFWv VM!")
                    deregister_ip_from_tg(unhealthy_ip_targets[i])
                    put_line_in_log('Instance Doctor finished', 'dot')
                    return
    except Exception as e:
        logger.error("Exception occurred: {}".format(repr(e)))
        logger.info("Unable to get unhealthy Instances from IPs!")
        put_line_in_log('Instance Doctor finished', 'dot')
        return

    try:
        logger.info("NGFWv instances: " + str(killable_ngfw_instance) + " found unhealthy for more than an hour!")
        list_len = len(killable_ngfw_instance)
        if list_len > 0:
            for i in range(0, list_len):
                response = asg.remove_instance_asg(killable_ngfw_instance[i], False)  #
                if response is not None:
                    logger.info("Removing instance response: " + str(response))
                else:
                    logger.info("Unable to kill instance: " + str(killable_ngfw_instance[i]))
    except Exception as e:
        logger.error("Exception occurred: {}".format(repr(e)))
        logger.info("Unable to terminate unhealthy Instances!")
        put_line_in_log('Instance Doctor finished', 'dot')
        return
    put_line_in_log('Instance Doctor finished', 'dot')
    return
