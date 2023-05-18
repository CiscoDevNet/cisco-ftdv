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

Name:       manager.py
Purpose:    This is the main Lambda handler file( autoscale_manager ).
            Takes AWS Lambda triggers & routes the request to appropriate function module.
Input:      A sample SNS test Event
            {
                "Records": [
                    {
                        "EventSource": "aws:sns",
                        "Sns": {
                            "Message": "{\"Description\": \"Check VM is ready\", \"category\":\"FIRST\",\"counter\":\"3\",\"instance_id\":\"i-0a252104d2913eede\",\"to_function\":\"vm_ready\"}"
                        }
                    }
                ]
            }
"""

import json
import time
from datetime import datetime, timezone
import utility as utl
from ngfw import ManagedDevice
from fmc import DerivedFMC
from aws import SimpleNotificationService, EC2Instance, ElasticLoadBalancer, AutoScaleGroup, CloudWatchEvent
import constant as const


logger = utl.setup_logging()
# Get User input
e_var, j_var = utl.get_user_input_manager()


def lambda_handler(event, context):
    """
    Purpose:    Main Lambda functions of Autoscale Manager
    Parameters: AWS Events (cloudwatch, SNS)
    Returns:
    Raises:
    """
    utl.put_line_in_log('AutoScale Manager Lambda Handler started', 'thick')
    logger.info("Received event: " + json.dumps(event, separators=(',', ':')))

    if const.DISABLE_AUTOSCALE_MANAGER_LAMBDA is True:
        logger.info("Autoscale manager Lambda running is disabled! Check constant.py")
        utl.put_line_in_log('Autoscale manager Lambda Handler finished', 'thick')
        return

    # SNS Event
    try:
        if event["Records"][0]["EventSource"] == "aws:sns":
            sns_data = event["Records"][0]["Sns"]
    except Exception as e:
        logger.debug(str(e))
        pass
    else:
        try:
            handle_sns_event(sns_data)
            utl.put_line_in_log('AutoScale Manager Lambda Handler finished', 'thick')
            return
        except Exception as e:
            logger.exception(e)
            utl.put_line_in_log('AutoScale Manager Lambda Handler finished', 'thick')
            return

    logger.info("Received an event but not a SNS notification event")

    # EC2 CloudWatch Event

    try:
        if event["detail-type"] == "Scheduled Event":
            handle_cron_event(event)
            utl.put_line_in_log('AutoScale Manager Lambda Handler finished', 'thick')
            return
    except Exception as e:
        logger.debug(str(e))
        pass
    logger.info("Received an event but not a Scheduled Event")

    try:
        if event["detail-type"] == "EC2 Instance Launch Successful":
            try:
                instance_id = event['detail']['EC2InstanceId']
            except Exception as e:
                logger.error("Unable to get instance ID from event!")
                logger.error("Error occurred {}".format(repr(e)))
                utl.put_line_in_log('AutoScale Manager Lambda Handler finished', 'thick')
                return
            else:
                try:
                    handle_ec2_launch_event(instance_id)
                    utl.put_line_in_log('AutoScale Manager Lambda Handler finished', 'thick')
                    return
                except Exception as e:
                    logger.exception(e)
                    utl.put_line_in_log('AutoScale Manager Lambda Handler finished', 'thick')
                    return

        elif event["detail-type"] == "EC2 Instance Terminate Successful":
            try:
                instance_id = event['detail']['EC2InstanceId']
            except Exception as e:
                logger.error("Unable to get instance ID from event!")
                logger.error("Error occurred {}".format(repr(e)))
                utl.put_line_in_log('AutoScale Manager Lambda Handler finished', 'thick')
                return
            else:
                try:
                    handle_ec2_terminate_event(instance_id)
                    utl.put_line_in_log('AutoScale Manager Lambda Handler finished', 'thick')
                    return
                except Exception as e:
                    logger.exception(e)
                    utl.put_line_in_log('AutoScale Manager Lambda Handler finished', 'thick')
                    return
    except Exception as e:
        logger.debug(str(e))
        pass
    logger.info("Received an event but not an EC2 CloudWatch event")

    # When its not any expected event / run cron event
    # Initialize DerivedFMC & AutoScaleGroup
    handle_cron_event(event)

    utl.put_line_in_log('AutoScale Manager Lambda Handler finished', 'thick')
    return


def handle_sns_event(sns_data):
    """
    Purpose:    Handler for SNS event
    Parameters: SNS data from Lambda handler
    Returns:
    Raises:
    """
    utl.put_line_in_log('SNS Handler', 'thin')
    logger.debug("SNS Message: " + json.dumps(sns_data, separators=(',', ':')))

    # SNS class initialization
    sns = SimpleNotificationService()

    _m_attr = json.loads(sns_data['Message'])
    logger.info("SNS Message: " + json.dumps(_m_attr, separators=(',', ':')))

    if _m_attr is None:
        logger.critical("Unable to get required attributes from SNS message!")
        utl.put_line_in_log('SNS Handler Finished', 'thin')
        return

    if _m_attr['instance_id'] is None:
        logger.critical("Received instance_id None!")
        utl.put_line_in_log('SNS Handler Finished', 'thin')
        return

    # AutoScaleGroup
    aws_grp = aws_asg_cls_init()
    # Initialize DerivedFMC
    fmc = fmc_cls_init()
    # FTD class initialization
    ftd = ftd_cls_init(_m_attr['instance_id'], fmc)

    try:
        if int(_m_attr['counter']) <= 0 and _m_attr['to_function'] != 'vm_delete':
            logger.critical("Lambda has ran out of retries, calling vm_delete")
            # Email to user
            details_of_the_device = json.dumps(ftd.get_instance_tags())
            logger.info(details_of_the_device)
            if e_var['USER_NOTIFY_TOPIC_ARN'] is not None:

                message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' ' + \
                                  _m_attr['instance_id'] + ' ' + 'unable to complete ' + \
                                  _m_attr['to_function']
                msg_body = utl.sns_msg_body_user_notify_topic('VM not completing ' + _m_attr['to_function'],
                                                              e_var['AutoScaleGrpName'],
                                                              _m_attr['instance_id'], details_of_the_device)
                sns.publish_to_topic(e_var['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
            # -------------
            if not const.DISABLE_VM_DELETE_FUNC:
                message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' ' + 'instance delete' + ' ' + \
                                  _m_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_ftdv_topic('vm_delete', 'FIRST',
                                                                 _m_attr['instance_id'])
                sns.publish_to_topic(e_var['AutoScaleManagerTopic'], message_subject, msg_body)
            else:
                logger.info(" vm_delete function is disabled! Check constant.py")
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return

        elif int(_m_attr['counter']) <= 0 and _m_attr['to_function'] == 'vm_delete':
            logger.critical("Unable to delete device %s" % _m_attr['instance_id'])
            # Email to user
            details_of_the_device = json.dumps(ftd.get_instance_tags())
            logger.info(details_of_the_device)
            if e_var['USER_NOTIFY_TOPIC_ARN'] is not None:

                message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' ' + \
                                  _m_attr['instance_id'] + ' ' + 'instance not deleted'
                msg_body = utl.sns_msg_body_user_notify_topic('VM not getting deleted',
                                                              e_var['AutoScaleGrpName'],
                                                              _m_attr['instance_id'], details_of_the_device)
                sns.publish_to_topic(e_var['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
            # -------------
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return
    except KeyError as e:
        logger.error("Unable to get one of required parameter from SNS Message body: {}".format(repr(e)))
        utl.put_line_in_log('SNS Handler Finished', 'thin')
        return

    if (_m_attr['to_function'] == 'vm_ready' and int(_m_attr['counter']) == const.TO_FUN_RETRY_COUNT[0]) or \
            (_m_attr['to_function'] == 'vm_register' and int(_m_attr['counter']) == const.TO_FUN_RETRY_COUNT[1]) or \
            (_m_attr['to_function'] == 'vm_configure' and int(_m_attr['counter']) == const.TO_FUN_RETRY_COUNT[2]) or \
            (_m_attr['to_function'] == 'vm_deploy' and int(_m_attr['counter']) == const.TO_FUN_RETRY_COUNT[3]):
        logger.info("Fmc validation: " + fmc_configuration_validation(fmc, aws_grp))
        if fmc.configuration_status == 'UN-CONFIGURED':
            # Email to user
            details_of_the_device = json.dumps(ftd.get_instance_tags())
            logger.info(details_of_the_device)
            if e_var['USER_NOTIFY_TOPIC_ARN'] is not None:
                message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' ' + \
                                  _m_attr['instance_id'] + ' ' + 'unable to connect Fmc ' + \
                                  _m_attr['to_function']
                msg_body = utl.sns_msg_body_user_notify_topic("Unable to connect Fmc", e_var['AutoScaleGrpName'],
                                                              _m_attr['instance_id'], details_of_the_device)
                sns.publish_to_topic(e_var['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
            # -------------
            if not const.DISABLE_VM_DELETE_FUNC:
                logger.info("Terminating instance")
                message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' ' + 'instance delete' + ' ' + \
                                  _m_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_ftdv_topic('vm_delete', 'FIRST',
                                                                 _m_attr['instance_id'])
                sns.publish_to_topic(e_var['AutoScaleManagerTopic'], message_subject, msg_body)
            else:
                logger.info("Need to terminate the instance, but vm_delete function is disabled, check constant.py")
            return

    instance_state = ftd.get_instance_state()
    logger.info("Instance %s " % _m_attr['instance_id'] + "is in %s state" % instance_state)
    if _m_attr['to_function'] == 'vm_delete':
        pass
    elif instance_state == 'running' or instance_state == 'pending':
        pass
    else:
        logger.error("Device in %s state, can't be handled by %s function"
                     % (instance_state, _m_attr['to_function']))
        utl.put_line_in_log('SNS Handler Finished', 'thin')
        return

    logger.info("Continue to execute action of " + _m_attr['to_function'])

    if _m_attr['to_function'] == 'vm_ready':
        if const.DISABLE_VM_READY_FUNC is True:
            logger.info(_m_attr['to_function'] + " function is disabled! Check constant.py")
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return
        ftd.create_instance_tags('Name', ftd.vm_name)  # To put Name tag on instance
        if _m_attr['category'] == 'FIRST':
            if execute_vm_ready_first(ftd) == 'SUCCESS':
                ftd.create_instance_tags('NGFWvConnectionStatus', 'AVAILABLE')
                logger.info("SSH to NGFWv with instance_id is successful, Next action: Registration")
                if not const.DISABLE_VM_REGISTER_FUNC:
                    message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' ' + 'instance register' + ' ' + \
                                      _m_attr['instance_id']
                    msg_body = utl.sns_msg_body_configure_ftdv_topic('vm_register',  'FIRST',
                                                                     _m_attr['instance_id'])
                    sns.publish_to_topic(e_var['AutoScaleManagerTopic'], message_subject, msg_body)
                else:
                    logger.info(" vm_register function is disabled! Check constant.py")
            else:
                logger.warn("SSH to NGFWv with instance_id: %s is un-successful, Retrying..." %
                            _m_attr['instance_id'])
                message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' ' + 'instance poll' + ' ' + \
                                  _m_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_ftdv_topic('vm_ready', 'FIRST',
                                                                 _m_attr['instance_id'],
                                                                 str(int(_m_attr['counter']) - 1))
                sns.publish_to_topic(e_var['AutoScaleManagerTopic'], message_subject, msg_body)

    elif _m_attr['to_function'] == 'vm_register':
        if _m_attr['category'] == 'FIRST':
            if execute_vm_register_first(ftd) == 'SUCCESS':
                ftd.create_instance_tags('NGFWvRegistrationStatus', 'DONE')
                logger.info("Instance is registered to FMC, Next action: Configuration")
                if not const.DISABLE_VM_CONFIGURE_FUNC:
                    message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' ' + 'instance configure' + ' ' + \
                                      _m_attr['instance_id']
                    msg_body = utl.sns_msg_body_configure_ftdv_topic('vm_configure',  'FIRST',
                                                                     _m_attr['instance_id'])
                    sns.publish_to_topic(e_var['AutoScaleManagerTopic'], message_subject, msg_body)
                else:
                    logger.info(" vm_configure function is disabled! Check constant.py")
            else:
                logger.warn("Registration failed! trying again in next cycle...")
                message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' ' + 'instance register' + ' ' + \
                                  _m_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_ftdv_topic('vm_register', 'FIRST',
                                                                 _m_attr['instance_id'],
                                                                 str(int(_m_attr['counter']) - 1))
                sns.publish_to_topic(e_var['AutoScaleManagerTopic'], message_subject, msg_body)

    elif _m_attr['to_function'] == 'vm_configure':
        if _m_attr['category'] == 'FIRST':
            if execute_vm_configure_first(ftd) == 'SUCCESS':
                ftd.create_instance_tags('NGFWvConfigurationStatus', 'DONE')
                logger.info("Instance is configured in FMC, Next action: Deployment")
                if not const.DISABLE_VM_DEPLOY_FUNC:
                    message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' ' + 'instance deploy' + ' ' + \
                                      _m_attr['instance_id']
                    msg_body = utl.sns_msg_body_configure_ftdv_topic('vm_deploy',  'FIRST',
                                                                     _m_attr['instance_id'])
                    sns.publish_to_topic(e_var['AutoScaleManagerTopic'], message_subject, msg_body)
                else:
                    logger.info(" vm_deploy function is disabled! Check constant.py")
            else:
                logger.warn("Configuration failed! trying again in next cycle...")
                message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' ' + 'instance configure' + ' ' + \
                                  _m_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_ftdv_topic('vm_configure', 'FIRST',
                                                                 _m_attr['instance_id'],
                                                                 str(int(_m_attr['counter']) - 1))
                sns.publish_to_topic(e_var['AutoScaleManagerTopic'], message_subject, msg_body)

    elif _m_attr['to_function'] == 'vm_deploy':
        if _m_attr['category'] == 'FIRST':
            if execute_vm_deploy_first(ftd, fmc) == 'SUCCESS':
                ftd.create_instance_tags('NGFWvConfigDeployStatus', 'DONE')
                logger.info("Configuration is deployed, health status in TG needs to be checked")
                details_of_the_device = json.dumps(ftd.get_instance_tags())
                logger.info(details_of_the_device)
                if e_var['USER_NOTIFY_TOPIC_ARN'] is not None:
                    # Email to user
                    message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' ' + \
                                      _m_attr['instance_id'] + ' ' + 'instance deploy configuration successful'
                    msg_body = utl.sns_msg_body_user_notify_topic('VM Configuration Deployed',
                                                                  e_var['AutoScaleGrpName'],
                                                                  _m_attr['instance_id'], details_of_the_device)
                    sns.publish_to_topic(e_var['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
                    # -------------
            else:
                logger.warn("Deployment failed! trying again in next cycle...")
                message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' ' + 'instance deploy' + ' ' + \
                                  _m_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_ftdv_topic('vm_deploy', 'FIRST',
                                                                 _m_attr['instance_id'],
                                                                 str(int(_m_attr['counter']) - 1))
                sns.publish_to_topic(e_var['AutoScaleManagerTopic'], message_subject, msg_body)

    elif _m_attr['to_function'] == 'vm_delete':
        if _m_attr['category'] == 'FIRST':
            if execute_vm_delete_first(ftd, fmc) == 'SUCCESS':
                logger.info("Instance has been deleted")
            else:
                logger.critical("Unable to delete instance")
                message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' ' + 'instance delete' + ' ' + \
                                  _m_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_ftdv_topic('vm_delete', 'FIRST',
                                                                 _m_attr['instance_id'],
                                                                 str(int(_m_attr['counter']) - 1))
                sns.publish_to_topic(e_var['AutoScaleManagerTopic'], message_subject, msg_body)

    utl.put_line_in_log('SNS Handler Finished', 'thin')
    return


def handle_ec2_launch_event(instance_id):
    """
    Purpose:    Handler for EC2 launch event
    Parameters: Instance Id
    Returns:
    Raises:
    """
    utl.put_line_in_log('EC2 Launch Handler', 'thin')
    # SNS class initialization
    sns = SimpleNotificationService()
    if instance_id is not None:
        logger.info("Received EC2 launch notification for instance-id: " + str(instance_id))

        # Enable Health Doctor
        cw_event = CloudWatchEvent(e_var['A_CRON_JOB_NAME'])
        status = cw_event.cron_job_status()
        if status == 'DISABLED':
            cw_event.start_cron_job()
            logger.info("ENABLED CloudWatch Rule: " + cw_event.name)
        else:
            logger.info("CloudWatch Rule: " + cw_event.name + " is already ENABLED")

        # Initialize DerivedFMC & AutoScaleGroup
        fmc = fmc_cls_init()
        # FTD class initialization
        instance = ftd_cls_init(instance_id, fmc)

        instance_state = instance.get_instance_state()
        interfaces_ip = instance.get_instance_interfaces_ip()
        if interfaces_ip is None:
            logger.warn("Unable to get IPs of the instance" + instance_id)
            message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' ' + 'instance poll' + ' ' + instance_id
            msg_body = utl.sns_msg_body_configure_ftdv_topic('vm_ready', 'FIRST', instance_id)
            sns.publish_to_topic(e_var['AutoScaleManagerTopic'], message_subject, msg_body)
            utl.put_line_in_log('EC2 Launch Handler finished', 'thin')
            return

        if instance_state == 'running' or instance_state == 'pending':
            logger.info("Instance %s is in state: %s" % (instance_id, instance_state))
            message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' ' + 'instance poll' + ' ' + instance_id
            msg_body = utl.sns_msg_body_configure_ftdv_topic('vm_ready', 'FIRST', instance_id)
            sns.publish_to_topic(e_var['AutoScaleManagerTopic'], message_subject, msg_body)
        else:
            logger.warn("Instance %s is in state: %s" % (instance_id, instance_state))

        if e_var['USER_NOTIFY_TOPIC_ARN'] is not None:
            # Email to user
            details_of_the_device = None
            message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' ' + instance_id + ' ' + \
                              'instance is launched'
            msg_body = utl.sns_msg_body_user_notify_topic('VM Launched', e_var['AutoScaleGrpName'],
                                                          instance_id, details_of_the_device)
            sns.publish_to_topic(e_var['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
            # -------------
    else:
        logger.critical("Received instance_id None!")
    utl.put_line_in_log('EC2 Launch Handler finished', 'thin')
    return


def handle_ec2_terminate_event(instance_id):
    """
    Purpose:    Handler for EC2 terminate event
    Parameters: Instance Id
    Returns:
    Raises:
    """
    utl.put_line_in_log('EC2 Terminate Handler', 'thin')
    logger.info("Received EC2 termination notification for instance-id: " + str(instance_id))

    # SNS class initialization
    sns = SimpleNotificationService()

    if instance_id is not None:  # Since Instance termination initiated, delete entries
        logger.info("Instance termination has been initiated: " + instance_id)
        logger.info("Initiating vm_delete function via SNS")

        if not const.DISABLE_VM_DELETE_FUNC:
            message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' ' + 'instance delete' + ' ' + instance_id
            msg_body = utl.sns_msg_body_configure_ftdv_topic('vm_delete', 'FIRST',
                                                             instance_id)
            sns.publish_to_topic(e_var['AutoScaleManagerTopic'], message_subject, msg_body)

        if e_var['USER_NOTIFY_TOPIC_ARN'] is not None:
            # Email to user
            details_of_the_device = None
            message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' ' + instance_id + ' ' + \
                              'instance is terminated'
            msg_body = utl.sns_msg_body_user_notify_topic('VM Terminated', e_var['AutoScaleGrpName'],
                                                          instance_id, details_of_the_device)
            sns.publish_to_topic(e_var['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
            # -------------
    utl.put_line_in_log('EC2 Terminate Handler finished', 'thin')
    return


def handle_cron_event(event):
    """
    Purpose:    Handler for CloudWatch EC2 event
    Parameters:
    Returns:
    Raises:
    """
    # AutoScale Group class initialization
    asg = AutoScaleGroup(e_var['AutoScaleGrpName'])
    instances_list = asg.get_instance_list()
    if len(instances_list) <= 0:
        logger.info("No instance found in AWS AutoScale Group")
        logger.info("Will DISABLE Cron job for AutoScale Manager Health Doctor, gets ENABLED if new instance launches")
        # Initialize CloudWatchEvent class
        cw_event = CloudWatchEvent(e_var['A_CRON_JOB_NAME'])
        cw_event.stop_cron_job()
        return

    inform_user = False
    data = {
        "autoscale_group": e_var['AutoScaleGrpName']
    }
    if const.DISABLE_HEALTH_DOCTOR is True:
        logger.info("Health Doctor running is disabled, check constant.py")
        return

    try:
        l_kill_ftd, l_unhealthy_ip = execute_instance_tg_health_doctor()
        if l_kill_ftd != []:
            logger.debug("Not empty l_kill_ftd")
            inform_user = True
        item = {
            "health_doctor_data": {
                "unhealthy_ftdv_": l_kill_ftd,
                "unhealthy_ip": l_unhealthy_ip
            }
        }
    except Exception as e:
        logger.exception(e)
    else:
        data.update(item)

    try:
        # AutoScaleGroup
        aws_grp = aws_asg_cls_init()
        # Initialize DerivedFMC & AutoScaleGroup
        fmc = fmc_cls_init()
        status = fmc_configuration_validation(fmc, aws_grp)
        logger.info("Fmc validation status: " + status)
        if status == 'FAIL':
            inform_user = True
    except Exception as e:
        logger.exception(e)
    else:
        data.update({"fmc_config_validation": fmc.configuration})

    if inform_user:
        # SNS class initialization
        sns = SimpleNotificationService()
        # Email to user
        if e_var['USER_NOTIFY_TOPIC_ARN'] is not None:
            message_subject = 'Event: ' + e_var['AutoScaleGrpName'] + ' Health Doctor Report'
            msg_body = json.dumps(data, separators=(',', ':'))
            sns.publish_to_topic(e_var['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
        # -------------
    logger.info(json.dumps(data, sort_keys=True, separators=(',', ':')))
    return


# ----------------------------------------------------------------------------------------------------------------------
def execute_vm_ready_first(ftd):
    """
    Purpose:    This polls NGFW instance for it's SSH accessibility
    Parameters: ManagedDevice object
    Returns:    SUCCESS, FAIL
    Raises:
    """
    poll_ftdv = ftd.poll_ftdv_ssh(const.FTD_POLL_TIME_IN_MIN_VM_READY)  # 10 minutes polling
    if poll_ftdv == "SUCCESS":
        request_response = ftd.configure_hostname()
        if request_response != 'COMMAND_RAN':
            ftd.configure_hostname()
        return 'SUCCESS'
    return 'FAIL'


def execute_vm_register_first(ftd):
    """
    Purpose:    This registers the device to FMC
    Parameters: ManagedDevice object
    Returns:    SUCCESS, FAIL
    Raises:
    """
    ftd.create_instance_tags('NGFWvRegistrationStatus', 'ONGOING')
    try:
        # device_grp_id = fmc.get_device_grp_id_by_name(e_var['fmcDeviceGroupName'])
        # if device_grp_id is None:
        #     raise ValueError("Unable to find Device Group in FMC: %s " % e_var['fmcDeviceGroupName'])
        # else:
        #     logger.debug("Device Group: %s " % device_grp_id)
        reg_status = ftd.check_ftdv_reg_status()  # Check Device Registration state
        if reg_status == "COMPLETED":
            logger.info("Device is in registration successful ")
            return 'SUCCESS'
        elif reg_status == "PENDING":
            logger.info("Device is in registration pending status ")
            task_status = ftd.send_registration_request()  # Can return FAIL or SUCCESS
            time.sleep(1 * 60)  # Related to CSCvs17405
            if task_status == 'SUCCESS':
                return 'SUCCESS'
        elif reg_status == 'NO_MANAGER':
            logger.info("Device has no manager configured, sending: 'configure manager add'")
            request_response = ftd.configure_manager()
            if request_response == 'COMMAND_RAN':
                reg_status = ftd.check_ftdv_reg_status()
                if reg_status == 'PENDING':
                    logger.info("Device is in registration pending status ")
                    task_status = ftd.send_registration_request()  # Can return FAIL or SUCCESS
                    time.sleep(1 * 60)  # Related to CSCvs17405
                    if task_status == 'SUCCESS':
                        return 'SUCCESS'
        elif reg_status == 'TROUBLESHOOT':
            logger.info("Device has manager configuration related problem, sending: 'configure manager delete'")
            request_response = ftd.configure_manager_delete()
            if request_response != 'COMMAND_RAN':
                ftd.configure_manager_delete()  # Next iteration should fix it!
    except ValueError as e:
        logger.warn("Exception occurred {}".format(repr(e)))
    except Exception as e:
        logger.exception(e)
    ftd.create_instance_tags('NGFWvRegistrationStatus', 'FAIL')
    return 'FAIL'


def execute_vm_configure_first(ftd):
    """
    Purpose:    This configures Interfaces & Static Routes on the NGFW instance
    Parameters: ManagedDevice object
    Returns:    SUCCESS, FAIL
    Raises:
    """
    ftd.create_instance_tags('NGFWvConfigurationStatus', 'ONGOING')
    if ftd.device_id == '':
        ftd.update_device_configuration()
    if ftd.device_id != '':
        try:
            nic_status = ftd.check_and_configure_interface()
            if nic_status != 'SUCCESS':
                raise ValueError("Interface configuration failed")
			# Check env flag for geneve then add geneve support
            if e_var['GENEVE_SUPPORT'] == 'enable':
                logger.info("Geneve support enabled, Adding Geneve configuration")			
                geneve_status = ftd.configure_geneve()
                if geneve_status != 'SUCCESS':
                    raise ValueError("Geneve configuration failed")				
            routes_status = ftd.check_and_configure_routes()
            if routes_status != 'SUCCESS':
                raise ValueError("Route configuration failed")
            return 'SUCCESS'
        except ValueError as e:
            logger.info("Exception occurred {}".format(repr(e)))
        except Exception as e:
            logger.exception(e)
    ftd.create_instance_tags('NGFWvConfigurationStatus', 'FAIL')
    return 'FAIL'


def execute_vm_deploy_first(ftd, fmc):
    """
    Purpose:    This deploys policies on the device
    Parameters: ManagedDevice object, DerivedFMC Object
    Returns:    SUCCESS, FAIL
    Raises:
    """
    ftd.create_instance_tags('NGFWvConfigDeployStatus', 'ONGOING')
    try:
        deploy_status = fmc.check_deploy_status(ftd.vm_name)
        if deploy_status != 'DEPLOYED':
            if fmc.start_deployment(ftd.vm_name) is None:
                raise ValueError("Configuration deployment REST post failing")
        deploy_status = ftd.ftdv_deploy_polling(5)
        if deploy_status != "SUCCESS":
            raise ValueError("Configuration deployment failed")
        logger.info("Configuration is deployed, health status in TG needs to be checked")
        return 'SUCCESS'
    except ValueError as e:
        logger.info("Exception occurred {}".format(repr(e)))
    except Exception as e:
        logger.exception(e)
    ftd.create_instance_tags('NGFWvConfigDeployStatus', 'FAIL')
    return 'FAIL'


def execute_vm_delete_first(ftd, fmc):
    """
    Purpose:    This deletes the instance from Autoscale Group, de-registers from FMC
    Parameters: ManagedDevice object, DerivedFMC Object
    Returns:    SUCCESS, FAIL
    Raises:
    """
    result = 'SUCCESS'
    try:
        state = ftd.get_instance_state()
        if state != 'terminated':
            asg_removal_status = ftd.remove_from_asg(const.DECREMENT_CAP_IF_VM_DELETED)
            if asg_removal_status == 'FAILED':
                raise Exception("Unable to delete Instance from ASG")
    except Exception as e:
        logger.exception(e)
        result = 'FAIL'
    try:
        status_in_fmc = fmc.check_reg_status_from_fmc(ftd.vm_name)
        if status_in_fmc == 'FAILED':
            ftd.create_instance_tags('NGFWvRegistrationStatus', 'FAIL')
        else:
            fmc_removal_status = ftd.remove_from_fmc()
            if fmc_removal_status == "FAILED":
                raise Exception("Unable to delete NGFWv from FMC")
            ftd.create_instance_tags('NGFWvRegistrationStatus', 'PENDING')
    except Exception as e:
        logger.exception(e)
        result = 'FAIL'
    return result


def execute_instance_tg_health_doctor():
    """
    Purpose:    To remove un-healthy instances from TG if satisfies conditions
    Parameters:
    Returns:    SUCCESS, FAIL
    Raises:
    """
    # Initializing ElasticLoadBalancer
    elb_client = ElasticLoadBalancer()
    # Initialize EC2Instance with None
    ec2_client = EC2Instance('', e_var['AutoScaleGrpName'])

    utl.put_line_in_log('Instance Doctor', 'dot')
    asg_name = ''
    now = datetime.now(timezone.utc)
    killable_ftd_instance = []
    unhealthy_ip_targets = []
    try:
        _ip_targets = elb_client.get_unhealthy_ip_targets(e_var['LB_ARN_OUTSIDE'])
        for i in _ip_targets:
            unhealthy_ip_targets.append(i)
    except Exception as e:
        logger.debug("Exception occurred: {}".format(repr(e)))
        logger.info("Unable to get unhealthy IP targets!")
        return killable_ftd_instance, unhealthy_ip_targets

    try:
        logger.info("IPs: " + str(unhealthy_ip_targets) + " found unhealthy!")
        list_len = len(unhealthy_ip_targets)
        if list_len > 0:
            for i in range(0, list_len):
                try:
                    unhealthy_instance = ec2_client.get_describe_instance_from_private_ip(unhealthy_ip_targets[i])
                    instance = unhealthy_instance['Reservations'][0]['Instances'][0]
                    unhealthy_instance_id = instance['InstanceId']
                except IndexError as e:
                    logger.debug("{}".format(repr(e)))
                    logger.info("Removing IP: " + str(unhealthy_ip_targets[i]) + " as no associated Instance found!")
                    elb_client.deregister_ip_target_from_lb(e_var['LB_ARN_OUTSIDE'], unhealthy_ip_targets[i])
                    utl.put_line_in_log('Instance Doctor finished', 'dot')
                    return killable_ftd_instance, unhealthy_ip_targets
                for val in instance['Tags']:
                    if val['Key'] == "aws:autoscaling:groupName":
                        asg_name = str(val['Value'])
                if asg_name == e_var['AutoScaleGrpName']:
                    days = (now - instance['LaunchTime']).days
                    hours = (now - instance['LaunchTime']).seconds / 60 / 60
                    logger.info('%s, %s, %d days %d hours alive' %
                                (unhealthy_instance_id, instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S'),
                                 days, hours))
                    if days > const.UNHEALTHY_DAYS_THRESHOLD or hours > const.UNHEALTHY_HOURS_THRESHOLD:
                        killable_ftd_instance.append(unhealthy_instance_id)
                else:
                    logger.info(unhealthy_instance_id + " is not part of " + str(e_var['AutoScaleGrpName']))
                    logger.info("Removing IP: " + str(unhealthy_ip_targets[i]) + " as it is not of an NGFWv VM!")
                    elb_client.deregister_ip_target_from_lb(e_var['LB_ARN_OUTSIDE'], unhealthy_ip_targets[i])
                    utl.put_line_in_log('Instance Doctor finished', 'dot')
                    return killable_ftd_instance, unhealthy_ip_targets
    except Exception as e:
        logger.debug("{}".format(repr(e)))
        logger.info("Unable to get unhealthy Instances from IPs")
        utl.put_line_in_log('Instance Doctor finished', 'dot')
        return killable_ftd_instance, unhealthy_ip_targets

    try:
        logger.info("NGFWv instances: " + str(killable_ftd_instance) + " found unhealthy for more than threshold!")
        list_len = len(killable_ftd_instance)
        if list_len > 0:
            ec2_group = AutoScaleGroup(e_var['AutoScaleGrpName'])
            for i in range(0, list_len):
                response = ec2_group.remove_instance(killable_ftd_instance[i],
                                                     const.DECREMENT_CAP_IF_VM_REMOVED_BY_DOCTOR)
                if response is not None:
                    logger.info("Removing instance response: " + str(response))
                else:
                    logger.info("Unable to kill instance: " + str(killable_ftd_instance[i]))
    except Exception as e:
        logger.exception(e)
        logger.info("Unable to terminate unhealthy Instances")
        utl.put_line_in_log('Instance Doctor finished', 'dot')
        return killable_ftd_instance, unhealthy_ip_targets

    utl.put_line_in_log('Instance Doctor finished', 'dot')
    return killable_ftd_instance, unhealthy_ip_targets


def aws_asg_cls_init():
    """
    Purpose:    To instantiate AutoScaleGroup class
    Parameters:
    Returns:    Object
    Raises:
    """
    # AWS AutoScale Class initialization
    aws_grp = AutoScaleGroup(e_var['AutoScaleGrpName'])
    aws_grp.create_or_update_tags('FmcDeviceGroup', e_var['fmcDeviceGroupName'])
    return aws_grp


def fmc_cls_init():
    """
    Purpose:    To instantiate DerivedFMC class
    Parameters:
    Returns:    Object
    Raises:
    """
    # FMC class initialization
    fmc = DerivedFMC(e_var['FmcIp'], e_var['FmcUserName'], e_var['FmcPassword'], j_var['fmcAccessPolicyName'])
    # Gets Auth token & updates self.reachable variable
    fmc.reach_fmc_()
    if fmc.reachable == 'AVAILABLE':
        l_seczone_name = [j_var['fmcInsideZone'], j_var['fmcOutsideZone']]
        l_network_obj_name = []
        
        
        # Updates DerivedFMC object with appropriate user provided names
        if e_var['GENEVE_SUPPORT'] == "disable":
            l_host_obj_name = [j_var['MetadataServerObjectName']]
            fmc.update_fmc_config_user_input(e_var['fmcDeviceGroupName'], j_var['fmcAccessPolicyName'],
                                         l_seczone_name, l_network_obj_name, l_host_obj_name, j_var['fmcNatPolicyName'])
        else:
            fmc.update_fmc_config_user_input(e_var['fmcDeviceGroupName'], j_var['fmcAccessPolicyName'],
                                         l_seczone_name, l_network_obj_name)
        # Updates DerivedFMC object with appropriate ids from FMC
        fmc.set_fmc_configuration()
    return fmc


def ftd_cls_init(instance_id, fmc):
    """
    Purpose:    To instantiate ManagedDevice class
    Parameters: instance id, DerivedFMC object
    Returns:    ManagedDevice Object
    Raises:
    """
    # Managed FTD class initialization
    ftd = ManagedDevice(instance_id, fmc)

    ftd.public_ip = ftd.get_public_ip()
    ftd.private_ip = ftd.get_private_ip()

    ftd.port = const.FTDV_SSH_PORT
    ftd.username = e_var['NgfwUserName']
    ftd.password = e_var['NgfwPassword']
    ftd.performance_tier = e_var['fmcPerformanceLicenseTier']
    ftd.defaultPassword = const.DEFAULT_PASSWORD
    ftd.fmc_ip = j_var['fmcIpforDeviceReg']
    ftd.reg_id = j_var['RegistrationId']
    ftd.nat_id = j_var['NatId']

    ftd.l_caps = j_var['licenseCaps']
 
    ftd.traffic_routes = j_var['trafficRoutes']
    ftd.interface_config = j_var['interfaceConfig']
    ftd.in_nic = j_var['fmcInsideNic']
    ftd.out_nic = j_var['fmcOutsideNic']
    ftd.in_nic_name = j_var['fmcInsideNicName']
    ftd.out_nic_name = j_var['fmcOutsideNicName']

    # Updating device configuration
    ftd.update_device_configuration()

    return ftd


def fmc_configuration_validation(fmc, aws_grp):
    """
    Purpose:    To validate FMC configuration
    Parameters: DerivedFMC object, AutoScaleGroup object
    Returns:    PASS, FAIL
    Raises:
    """
    # Check if all needed/user-provided inputs have entries in FMC
    if fmc.check_fmc_configuration(e_var['GENEVE_SUPPORT']) == 'CONFIGURED':
        aws_grp.create_or_update_tags('FmcAvailabilityStatus', 'AVAILABLE')
        aws_grp.create_or_update_tags('FmcConfigurationStatus', 'CONFIGURED')
        return 'PASS'
    else:
        logger.critical("Fmc has configuration issues")
        aws_grp.create_or_update_tags('FmcAvailabilityStatus', 'UN-AVAILABLE')
        aws_grp.create_or_update_tags('FmcConfigurationStatus', 'UN-CONFIGURED')
        return 'FAIL'
