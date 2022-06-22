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

Name:       manager.py
Purpose:    This is the main Lambda handler file( autoscale_manager ).
            Takes AWS Lambda triggers & routes the request to appropriate function module.
"""

import json
import time
import utility as utl
from ngfw import NgfwInstance
from fmc import FirepowerManagementCenter
from aws import SimpleNotificationService

# Setup Logging
logger = utl.setup_logging(utl.e_var['DebugDisable'])


def lambda_handler(event, context):
    """
    Purpose:    Main Lambda functions of Autoscale Manager
    Parameters: AWS Events (cloudwatch, SNS)
    Returns:
    Raises:
    """
    utl.put_line_in_log('AutoScale Manager Lambda Handler started', 'thick')
    logger.info("Received event: " + json.dumps(event, separators=(',', ':')))

    # SNS Event
    try:
        if event["Records"][0]["EventSource"] == "aws:sns":
            sns_data = event["Records"][0]["Sns"]
            handle_sns_event(sns_data)
            utl.put_line_in_log('AutoScale Manager Lambda Handler finished', 'thick')
            return
    except Exception as e:
        logger.info("Received an event but not a SNS notification event")
        logger.debug(str(e))
        pass

    # EC2 CloudWatch Event
    try:
        if event["detail-type"] == "EC2 Instance Launch Successful":
            try:
                instance_id = event['detail']['EC2InstanceId']
                handle_ec2_launch_event(instance_id)
                utl.put_line_in_log('AutoScale Manager Lambda Handler finished', 'thick')
                return
            except Exception as e:
                logger.error("Unable to get instance ID from event!")
                logger.error("Error occurred {}".format(repr(e)))
                utl.put_line_in_log('AutoScale Manager Lambda Handler finished', 'thick')
                return

        elif event["detail-type"] == "EC2 Instance Terminate Successful":
            try:
                instance_id = event['detail']['EC2InstanceId']
                handle_ec2_terminate_event(instance_id)
                utl.put_line_in_log('AutoScale Manager Lambda Handler finished', 'thick')
                return
            except Exception as e:
                logger.error("Unable to get instance ID from event!")
                logger.error("Error occurred {}".format(repr(e)))
                utl.put_line_in_log('AutoScale Manager Lambda Handler finished', 'thick')
                return
    except Exception as e:
        logger.info("Received an event but not an EC2 CloudWatch event")
        logger.debug(str(e))
        pass

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

    sns_msg_attr = json.loads(sns_data['Message'])
    logger.info("SNS Message: " + json.dumps(sns_msg_attr, separators=(',', ':')))

    if sns_msg_attr is None:
        logger.critical("Unable to get required attributes from SNS message!")
        utl.put_line_in_log('SNS Handler Finished', 'thin')
        return
    try:
        if sns_msg_attr['instance_id'] is None:
            logger.critical("Received instance_id None!")
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return
        if int(sns_msg_attr['counter']) <= 0 and sns_msg_attr['to_function'] != 'vm_delete':
            message_subject = 'EVENT: ' + utl.e_var['AutoScaleGrpName'] + ' ' + 'instance delete' + ' ' + \
                              sns_msg_attr['instance_id']
            sns.publish_to_topic(utl.e_var['AutoScaleManagerTopic'], 'VM not accessible', message_subject, 'vm_delete',
                                 'FIRST', sns_msg_attr['instance_id'])
            logger.critical("Has ran out of retries! calling vm_delete...")
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return
        elif int(sns_msg_attr['counter']) <= 0 and sns_msg_attr['to_function'] == 'vm_delete':
            logger.critical("Unable to delete device %s" % sns_msg_attr['instance_id'])
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return
    except KeyError as e:
        logger.error("Unable to get one of required parameter from SNS Message body: {}".format(repr(e)))
        utl.put_line_in_log('SNS Handler Finished', 'thin')
        return

    # FMC class initialization
    fmc = FirepowerManagementCenter()
    fmc.get_auth_token()

    # FTD class initialization
    ftd = NgfwInstance(sns_msg_attr['instance_id'])
    instance_state = ftd.get_instance_state()
    logger.info("Instance %s " % sns_msg_attr['instance_id'] + "is in %s state" % instance_state)
    if sns_msg_attr['to_function'] == 'vm_delete':
        pass
    elif instance_state == 'running' or instance_state == 'pending':
        pass
    else:
        logger.error("Device in %s state, can't be handled by %s function"
                     % (instance_state, sns_msg_attr['to_function']))
        utl.put_line_in_log('SNS Handler Finished', 'thin')
        return

    logger.info("Continue to execute action of " + sns_msg_attr['to_function'])

    if sns_msg_attr['to_function'] == 'vm_ready':
        ftd.put_instance_name()
        if sns_msg_attr['category'] == 'FIRST':
            if execute_vm_ready_first(ftd) == 'SUCCESS':
                logger.info("SSH to NGFWv with instance_id is successful, Next action: Registration")
                message_subject = 'EVENT: ' + utl.e_var['AutoScaleGrpName'] + ' ' + 'instance register' + ' ' + \
                                  sns_msg_attr['instance_id']
                sns.publish_to_topic(utl.e_var['AutoScaleManagerTopic'], 'VM is ready', message_subject,
                                     'vm_register', 'FIRST', sns_msg_attr['instance_id'])
            else:
                logger.warn("SSH to NGFWv with instance_id: %s is un-successful, Retrying..." %
                            sns_msg_attr['instance_id'])
                message_subject = 'EVENT: ' + utl.e_var['AutoScaleGrpName'] + ' ' + 'instance poll' + ' ' + \
                                  sns_msg_attr['instance_id']
                sns.publish_to_topic(utl.e_var['AutoScaleManagerTopic'], 'Check VM is ready', message_subject, 'vm_ready',
                                     'FIRST', sns_msg_attr['instance_id'], str(int(sns_msg_attr['counter']) - 1))

    elif sns_msg_attr['to_function'] == 'vm_register':
        if sns_msg_attr['category'] == 'FIRST':
            if execute_vm_register_first(ftd, fmc) == 'SUCCESS':
                logger.info("Instance is registered to FMC, Next action: Configuration")
                message_subject = 'EVENT: ' + utl.e_var['AutoScaleGrpName'] + ' ' + 'instance configure' + ' ' + \
                                  sns_msg_attr['instance_id']
                sns.publish_to_topic(utl.e_var['AutoScaleManagerTopic'], 'VM registered', message_subject,
                                     'vm_configure', 'FIRST',
                                     sns_msg_attr['instance_id'])
            else:
                logger.warn("Registration failed! trying again in next cycle...")
                message_subject = 'EVENT: ' + utl.e_var['AutoScaleGrpName'] + ' ' + 'instance register' + ' ' + \
                                  sns_msg_attr['instance_id']
                sns.publish_to_topic(utl.e_var['AutoScaleManagerTopic'], 'VM not registered', message_subject,
                                     'vm_register', 'FIRST', sns_msg_attr['instance_id'],
                                     str(int(sns_msg_attr['counter']) - 1))

    elif sns_msg_attr['to_function'] == 'vm_configure':
        if sns_msg_attr['category'] == 'FIRST':
            if execute_vm_configure_first(ftd, fmc) == 'SUCCESS':
                logger.info("Instance is configured in FMC, Next action: Deployment")
                message_subject = 'EVENT: ' + utl.e_var['AutoScaleGrpName'] + ' ' + 'instance deploy' + ' ' + \
                                  sns_msg_attr['instance_id']
                sns.publish_to_topic(utl.e_var['AutoScaleManagerTopic'], 'VM is configured', message_subject, 'vm_deploy',
                                     'FIRST', sns_msg_attr['instance_id'])
            else:
                logger.warn("Configuration failed! trying again in next cycle...")
                message_subject = 'EVENT: ' + utl.e_var['AutoScaleGrpName'] + ' ' + 'instance configure' + ' ' + \
                                  sns_msg_attr['instance_id']
                sns.publish_to_topic(utl.e_var['AutoScaleManagerTopic'], 'VM not configured', message_subject,
                                     'vm_configure', 'FIRST', sns_msg_attr['instance_id'],
                                     str(int(sns_msg_attr['counter']) - 1))

    elif sns_msg_attr['to_function'] == 'vm_deploy':
        if sns_msg_attr['category'] == 'FIRST':
            if execute_vm_deploy_first(ftd, fmc) == 'SUCCESS':
                logger.info("Configuration is deployed, health status in TG needs to be checked")
            else:
                logger.warn("Deployment failed! trying again in next cycle...")
                message_subject = 'EVENT: ' + utl.e_var['AutoScaleGrpName'] + ' ' + 'instance deploy' + ' ' + \
                                  sns_msg_attr['instance_id']
                sns.publish_to_topic(utl.e_var['AutoScaleManagerTopic'], 'VM not deployed', message_subject, 'vm_deploy',
                                     'FIRST', sns_msg_attr['instance_id'], str(int(sns_msg_attr['counter']) - 1))

    elif sns_msg_attr['to_function'] == 'vm_delete':
        if sns_msg_attr['category'] == 'FIRST':
            if execute_vm_delete_first(ftd, fmc) == 'SUCCESS':
                logger.info("Instance has been deleted! ")
            else:
                logger.critical("Unable to delete instance!")
                message_subject = 'EVENT: ' + utl.e_var['AutoScaleGrpName'] + ' ' + 'instance delete' + ' ' + \
                                  sns_msg_attr['instance_id']
                sns.publish_to_topic(utl.e_var['AutoScaleManagerTopic'], 'VM not deleted from ASG', message_subject,
                                     'vm_delete', 'FIRST', sns_msg_attr['instance_id'],
                                     str(int(sns_msg_attr['counter']) - 1))

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
    if instance_id is not None:
        logger.info("Received EC2 launch notification for instance-id: " + str(instance_id))

        # SNS class initialization
        sns = SimpleNotificationService()

        # FTD class initialization
        instance = NgfwInstance(instance_id)
        instance_state = instance.get_instance_state()
        interfaces_ip = instance.get_instance_interfaces_ip()
        if interfaces_ip is None:
            logger.warn("Unable to get IPs of the instance" + instance_id)
            message_subject = 'EVENT: ' + utl.e_var['AutoScaleGrpName'] + ' ' + 'instance poll' + ' ' + instance_id
            sns.publish_to_topic(utl.e_var['AutoScaleManagerTopic'], 'Check VM is ready', message_subject, 'vm_ready', 'FIRST',
                                 instance_id)
            utl.put_line_in_log('EC2 Launch Handler finished', 'thin')
            return

        if instance_state == 'running' or instance_state == 'pending':
            logger.info("Instance %s is in state: %s" % (instance_id, instance_state))
            message_subject = 'EVENT: ' + utl.e_var['AutoScaleGrpName'] + ' ' + 'instance poll' + ' ' + instance_id
            sns.publish_to_topic(utl.e_var['AutoScaleManagerTopic'], 'Check VM is ready', message_subject, 'vm_ready', 'FIRST',
                                 instance_id)
        else:
            logger.warn("Instance %s is in state: %s" % (instance_id, instance_state))
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
        message_subject = 'EVENT: ' + utl.e_var['AutoScaleGrpName'] + ' ' + 'instance delete' + ' ' + instance_id
        sns.publish_to_topic(utl.e_var['AutoScaleManagerTopic'], 'VM not accessible', message_subject, 'vm_delete',
                             'FIRST', instance_id)
    utl.put_line_in_log('EC2 Terminate Handler finished', 'thin')
    return


# ----------------------------------------------------------------------------------------------------------------------
def execute_vm_ready_first(ftd):
    """
    Purpose:    This polls NGFW instance for it's SSH accessibility
    Parameters: Object of type NgfwInstance class
    Returns:    SUCCESS, FAIL
    Raises:
    """
    poll_ftdv = ftd.poll_ftdv_ssh(10)  # 10 minutes polling
    if poll_ftdv == "SUCCESS":
        request_response = ftd.configure_hostname()
        if request_response != 'COMMAND_RAN':
            ftd.configure_hostname()
        return 'SUCCESS'
    return 'FAIL'


def execute_vm_register_first(ftd, fmc):
    """
    Purpose:    This registers the device to FMC
    Parameters: Object of NgfwInstance class, Object of FirepowerManagementCenter class
    Returns:    SUCCESS, FAIL
    Raises:
    """
    try:
        device_grp_id = fmc.get_device_grp_id_by_name(utl.j_var['DeviceGroupName'])
        if device_grp_id is None:
            raise ValueError("Unable to find Device Group in FMC: %s " % utl.j_var['DeviceGroupName'])
        else:
            logger.debug("Device Group: %s " % device_grp_id)
        reg_status = ftd.check_ftdv_reg_status()  # Check Device Registration state
        if reg_status == "COMPLETED":
            logger.info("Device is in registration successful ")
            return 'SUCCESS'
        elif reg_status == "PENDING":
            logger.info("Device is in registration pending status ")
            task_status = ftd.send_registration_request(fmc, device_grp_id)  # Can return FAIL or SUCCESS
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
                    task_status = ftd.send_registration_request(fmc, device_grp_id)  # Can return FAIL or SUCCESS
                    time.sleep(1 * 60)  # Related to CSCvs17405
                    if task_status == 'SUCCESS':
                        return 'SUCCESS'
        elif reg_status == 'TROUBLESHOOT':
            logger.info("Device has manager configuration related problem, sending: 'configure manager delete'")
            request_response = ftd.configure_manager_delete()
            if request_response != 'COMMAND_RAN':
                ftd.configure_manager_delete()  # Next iteration should fix it!
    except ValueError as e:
        logger.warn("Exception(known) occurred {}".format(repr(e)))
    except Exception as e:
        logger.error("Exception(un-known) occurred {}".format(e))
    return 'FAIL'


def execute_vm_configure_first(ftd, fmc):
    """
    Purpose:    This configures Interfaces & Static Routes on the NGFW instance
    Parameters: Object of NgfwInstance class, Object of FirepowerManagementCenter class
    Returns:    SUCCESS, FAIL
    Raises:
    """
    try:
        nic_status = ftd.check_and_configure_interface(fmc)
        if nic_status != 'SUCCESS':
            raise ValueError("Interface configuration failed")
        routes_status = ftd.check_and_configure_routes(fmc)
        if routes_status != 'SUCCESS':
            raise ValueError("Route configuration failed")

        return 'SUCCESS'
    except ValueError as e:
        logger.info("Exception(known) occurred {}".format(repr(e)))
    except Exception as e:
        logger.error("Exception(un-known) occurred {}".format(e))
    return 'FAIL'


def execute_vm_deploy_first(ftd, fmc):
    """
    Purpose:    This deploys policies on the device
    Parameters: Object of NgfwInstance class, Object of FirepowerManagementCenter class
    Returns:    SUCCESS, FAIL
    Raises:
    """
    try:
        deploy_status = fmc.check_deploy_status(ftd.vm_name)
        if deploy_status != 'DEPLOYED':
            if fmc.start_deployment(ftd.vm_name) is None:
                raise ValueError("Configuration deployment REST post failing")
        deploy_status = ftd.ftdv_deploy_polling(fmc, 5)
        if deploy_status != "SUCCESS":
            raise ValueError("Configuration deployment failed")
        logger.info("Configuration is deployed, health status in TG needs to be checked")
        return 'SUCCESS'
    except ValueError as e:
        logger.info("Exception(known) occurred {}".format(repr(e)))
    except Exception as e:
        logger.error("Exception(un-known) occurred {}".format(e))
    return 'FAIL'


def execute_vm_delete_first(ftd, fmc):
    """
    Purpose:    This deletes the instance from Autoscale Group, de-registers from FMC
    Parameters: Object of NgfwInstance class, Object of FirepowerManagementCenter class
    Returns:    SUCCESS, FAIL
    Raises:
    """
    try:
        state = ftd.get_instance_state()
        if state != 'terminated':
            asg_removal_status = ftd.remove_from_asg(True)
            if asg_removal_status == 'FAILED':
                raise Exception("Unable to delete Instance from ASG ")
        fmc_removal_status = ftd.remove_from_fmc(fmc)
        if fmc_removal_status == "FAILED":
            raise Exception("Unable to delete NGFW from FMC")
        return 'SUCCESS'
    except Exception as e:
        logger.error("Exception occurred {}".format(e))
        return 'FAIL'
