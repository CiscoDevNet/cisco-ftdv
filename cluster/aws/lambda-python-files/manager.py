"""
Copyright (c) 2022 Cisco Systems Inc or its affiliates.

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
                            "Message": "{\"Description\": \"Check Instance is ready\", \"category\":\"FIRST\",\"counter\":\"3\",\"instance_id\":\"i-0a252104d2913eede\",\"to_function\":\"cluster_ready\"}"
                        }
                    }
                ]
            }
"""

import re
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
    Purpose:    Main Lambda functions of Cluster Manager
    Parameters: AWS Events (cloudwatch, SNS)
    Returns:
    Raises:
    """
    utl.put_line_in_log('Cluster Manager Lambda Handler started', 'thick')
    logger.info("Received event: " + json.dumps(event, separators=(',', ':')))

    if const.DISABLE_CLUSTER_MANAGER_LAMBDA is True:
        logger.info("Cluster manager Lambda running is disabled! Check constant.py")
        utl.put_line_in_log('Cluster manager Lambda Handler finished', 'thick')
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
            utl.put_line_in_log('Cluster Manager Lambda Handler finished', 'thick')
            return
        except Exception as e:
            logger.exception(e)
            utl.put_line_in_log('Cluster Manager Lambda Handler finished', 'thick')
            return

    logger.info("Received an event but not a SNS notification event")

    # EC2 CloudWatch Event

    try:
        if event["detail-type"] == "EC2 Instance Launch Successful":
            try:
                instance_id = event['detail']['EC2InstanceId']
            except Exception as e:
                logger.error("Unable to get instance ID from event!")
                logger.error("Error occurred {}".format(repr(e)))
                utl.put_line_in_log('Cluster Manager Lambda Handler finished', 'thick')
                return
            else:
                try:
                    handle_ec2_launch_event(instance_id)
                    utl.put_line_in_log('Cluster Manager Lambda Handler finished', 'thick')
                    return
                except Exception as e:
                    logger.exception(e)
                    utl.put_line_in_log('Cluster Manager Lambda Handler finished', 'thick')
                    return

        elif event["detail-type"] == "EC2 Instance Terminate Successful":
            try:
                instance_id = event['detail']['EC2InstanceId']
            except Exception as e:
                logger.error("Unable to get instance ID from event!")
                logger.error("Error occurred {}".format(repr(e)))
                utl.put_line_in_log('Cluster Manager Lambda Handler finished', 'thick')
                return
            else:
                try:
                    handle_ec2_terminate_event(instance_id)
                    utl.put_line_in_log('Cluster Manager Lambda Handler finished', 'thick')
                    return
                except Exception as e:
                    logger.exception(e)
                    utl.put_line_in_log('Cluster Manager Lambda Handler finished', 'thick')
                    return
    except Exception as e:
        logger.debug(str(e))
        pass
    logger.info("Received an event but not an EC2 CloudWatch event")
    utl.put_line_in_log('Cluster Manager Lambda Handler finished', 'thick')
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
        if int(_m_attr['counter']) <= 0 and _m_attr['to_function'] != 'cluster_delete':
            logger.critical("Lambda has ran out of retries..")
            # Email to user
            details_of_the_device = json.dumps(ftd.get_instance_tags())
            logger.info(details_of_the_device)
            if e_var['USER_NOTIFY_TOPIC_ARN'] != 'NA':

                message_subject = 'Event: ' + e_var['ClusterGrpName'] + ' ' + \
                                  _m_attr['instance_id'] + ' ' + 'Unable to complete ' + \
                                  _m_attr['to_function']
                msg_body = utl.sns_msg_body_user_notify_topic('Instance unable to complete ' + _m_attr['to_function'],
                                                              e_var['ClusterGrpName'],
                                                              _m_attr['instance_id'], details_of_the_device)
                sns.publish_to_topic(e_var['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
            const.DISABLE_CLUSTER_REGISTER_FUNC = True
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return
 
        elif int(_m_attr['counter']) <= 0 and _m_attr['to_function'] == 'cluster_delete':
            logger.critical("Unable to delete device %s" % _m_attr['instance_id'])
            # Email to user
            details_of_the_device = json.dumps(ftd.get_instance_tags())
            logger.info(details_of_the_device)
            if e_var['USER_NOTIFY_TOPIC_ARN'] != 'NA':

                message_subject = 'Event: ' + e_var['ClusterGrpName'] + ' ' + \
                                  _m_attr['instance_id'] + ' ' + 'instance not deleted'
                msg_body = utl.sns_msg_body_user_notify_topic('Instance not getting deleted',
                                                              e_var['ClusterGrpName'],
                                                              _m_attr['instance_id'], details_of_the_device)
                sns.publish_to_topic(e_var['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
            return
    except KeyError as e:
        logger.error("Unable to get one of required parameter from SNS Message body: {}".format(repr(e)))
        utl.put_line_in_log('SNS Handler Finished', 'thin')
        return

    if (_m_attr['to_function'] == 'cluster_ready' and int(_m_attr['counter']) == const.TO_FUN_RETRY_COUNT[0]) or \
            (_m_attr['to_function'] == 'cluster_status' and int(_m_attr['counter']) == const.TO_FUN_RETRY_COUNT[1]) or \
            (_m_attr['to_function'] == 'cluster_register' and int(_m_attr['counter']) == const.TO_FUN_RETRY_COUNT[2]):
        logger.info("Fmc validation: " + fmc_configuration_validation(fmc, aws_grp))
        if fmc.configuration_status == 'UN-CONFIGURED':
            # Email to user
            details_of_the_device = json.dumps(ftd.get_instance_tags())
            logger.info(details_of_the_device)
            if e_var['USER_NOTIFY_TOPIC_ARN'] != 'NA':
                message_subject = 'Event: ' + e_var['ClusterGrpName'] + ' ' + \
                                  _m_attr['instance_id'] + ' ' + 'Unable to connect FMC ' + \
                                  _m_attr['to_function']
                msg_body = utl.sns_msg_body_user_notify_topic("Verify FMC Configuration (FMC IP, AccessPolicy Name, API Username & Password)",
                                                              e_var['ClusterGrpName'],
                                                              _m_attr['instance_id'], details_of_the_device)
                sns.publish_to_topic(e_var['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
            return

    if _m_attr['to_function'] == 'cluster_ready':
        if const.DISABLE_CLUSTER_READY_FUNC is True:
            logger.info(_m_attr['to_function'] + " function is disabled! Check constant.py")
            utl.put_line_in_log('SNS Handler Finished', 'thin')
            return
        ftd.create_instance_tags('Name', ftd.vm_name)  # To put Name tag on instance
        if _m_attr['category'] == 'FIRST':
            if execute_cluster_ready_first(ftd) == 'SUCCESS':
                ftd.create_instance_tags('NGFWvConnectionStatus', 'AVAILABLE')
                logger.info("SSH to NGFWv with instance_id is successful, Next action: Cluster Status")
                if not const.DISABLE_CLUSTER_STATUS_FUNC:
                    message_subject = 'Event: ' + e_var['ClusterGrpName'] + ' ' + 'cluster formation status' + ' ' + \
                                      _m_attr['instance_id']
                    msg_body = utl.sns_msg_body_configure_ftdv_topic('cluster_status',  'FIRST',
                                                                     _m_attr['instance_id'])
                    sns.publish_to_topic(e_var['ClusterManagerTopic'], message_subject, msg_body)
                else:
                    logger.info("Cluster Status function is disabled! Check constant.py")
            else:
                logger.warn("SSH to NGFWv with instance_id: %s is un-successful, Retrying..." %
                            _m_attr['instance_id'])
                message_subject = 'Event: ' + e_var['ClusterGrpName'] + ' ' + 'instance poll' + ' ' + \
                                  _m_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_ftdv_topic('cluster_ready', 'FIRST',
                                                                 _m_attr['instance_id'],
                                                                 str(int(_m_attr['counter']) - 1))
                sns.publish_to_topic(e_var['ClusterManagerTopic'], message_subject, msg_body)

    elif _m_attr['to_function'] == 'cluster_status':
        logger.info("Checking ftdv version...")
        version = ftd.showVersion()
        if int(version) < 730:
            const.CONTROL_NODE = 'MASTER'
            const.DATA_NODE = 'SLAVE'
        else:
            const.CONTROL_NODE = 'CONTROL_NODE'
            const.DATA_NODE = 'DATA_NODE'
        if check_cluster_status(aws_grp,ftd) == 'SUCCESS':
            logger.info("Cluster is successfully formed..!!")
            logger.info("Checking device for Control Role..")
            status = ftd.connect_cluster()
            logger.info("Cluster Info: {}".format(status))
            found = re.search('This is .* state '+const.CONTROL_NODE, status)
            if found:
                const.DISABLE_CLUSTER_REGISTER_FUNC = False
            if not const.DISABLE_CLUSTER_REGISTER_FUNC:
                logger.info("Cluster is successfully formed, Next action: Registration")
                message_subject = 'Event: ' + e_var['ClusterGrpName'] + ' ' + 'instance register' + ' ' + \
                                  _m_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_ftdv_topic('cluster_register',  'FIRST',
                                                                 _m_attr['instance_id'])
                sns.publish_to_topic(e_var['ClusterManagerTopic'], message_subject, msg_body)
            else:
                logger.info(" cluster_register function is disabled! Check constant.py")
        else:
            logger.warn("Cluster formation is un-successful, Retrying...")
            message_subject = 'Event: ' + e_var['ClusterGrpName'] + ' ' + 'instance poll' + ' ' + \
                              _m_attr['instance_id']
            msg_body = utl.sns_msg_body_configure_ftdv_topic('cluster_status', 'FIRST',
                                                            _m_attr['instance_id'],
                                                            str(int(_m_attr['counter']) - 1))
            sns.publish_to_topic(e_var['ClusterManagerTopic'], message_subject, msg_body)
 
    elif _m_attr['to_function'] == 'cluster_register':
        if _m_attr['category'] == 'FIRST':
            if 'task_id' in _m_attr:
                const.REG_TASK_ID = _m_attr['task_id']
            if execute_cluster_register_first(ftd) == 'SUCCESS':
                cls_mem = None
                cls_id = fmc.get_cluster_id_by_name(e_var["fmcDeviceGroupName"])
                if cls_id:
                    cls_mem = fmc.get_cluster_members(cls_id)
                des, mins, maxs = aws_grp.get_asgroup_size()
                if cls_mem:
                    if mins is len(cls_mem):
                        logger.info("Cluster Members: {}".format(cls_mem))
                        if e_var['USER_NOTIFY_TOPIC_ARN'] != 'NA':
                            details_of_the_device = "Cluster Members "+str(cls_mem)
                            message_subject = 'Event: ' + e_var['ClusterGrpName'] + ' ' + \
                                              _m_attr['instance_id'] + ' ' + 'Cluster is registered to FMC.!! ' + \
                                              _m_attr['to_function']
                            msg_body = utl.sns_msg_body_user_notify_topic("Cisco NGFWv Cluster is successfully registered to FMC..!!",
                                                                         e_var['ClusterGrpName'],
                                                                         _m_attr['instance_id'], details_of_the_device)
                            sns.publish_to_topic(e_var['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
                    else:
                        logger.info("FMC is not able to discover all nodes..!!")
                        logger.info('Login to FMC and discover pending nodes using "Reconcile All"')
                        if e_var['USER_NOTIFY_TOPIC_ARN'] != 'NA':
                            details_of_the_device = "Login to FMC and discover pending nodes using 'Cluster Live Status -> Reconcile All'"
                            message_subject = 'Event: ' + e_var['ClusterGrpName'] + ' ' + \
                                              _m_attr['instance_id'] + ' ' + 'FMC Unable to discover all nodes ' + \
                                              _m_attr['to_function']
                            msg_body = utl.sns_msg_body_user_notify_topic("FMC is not able to discover all nodes..!!", e_var['ClusterGrpName'],
                                                                         _m_attr['instance_id'], details_of_the_device)
                            sns.publish_to_topic(e_var['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
                else:
                    logger.warn("Unable to list cluster members from FMC..!!")
                    if e_var['USER_NOTIFY_TOPIC_ARN'] != 'NA':
                        details_of_the_device = "Unable to list cluster members, Verify from FMC"
                        message_subject = 'Event: ' + e_var['ClusterGrpName'] + ' ' + \
                                          _m_attr['instance_id'] + ' ' + 'Unable to list cluster members.!! ' + \
                                          _m_attr['to_function']
                        msg_body = utl.sns_msg_body_user_notify_topic("Unable to list cluster members..!!", e_var['ClusterGrpName'],
                                                                     _m_attr['instance_id'], details_of_the_device)
                        sns.publish_to_topic(e_var['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
                ftd.create_instance_tags('NGFWvRegistrationStatus', 'DONE')
                const.DISABLE_CLUSTER_REGISTER_FUNC = True
                logger.info("Cluster is registered to FMC..!!")
            else:
                logger.warn("Registration failed! trying again in next cycle...")
                message_subject = 'Event: ' + e_var['ClusterGrpName'] + ' ' + 'cluster register' + ' ' + \
                                  _m_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_ftdv_topic('cluster_register', 'FIRST',
                                                                 _m_attr['instance_id'],
                                                                 str(int(_m_attr['counter']) - 1),
                                                                 const.REG_TASK_ID)
                sns.publish_to_topic(e_var['ClusterManagerTopic'], message_subject, msg_body)

    elif _m_attr['to_function'] == 'cluster_delete':
        if _m_attr['category'] == 'FIRST':
            if execute_cluster_delete_first(ftd, fmc) == 'SUCCESS':
                logger.info("Instance has been deleted")
            else:
                logger.critical("Unable to delete instance")
                message_subject = 'Event: ' + e_var['ClusterGrpName'] + ' ' + 'instance delete' + ' ' + \
                                  _m_attr['instance_id']
                msg_body = utl.sns_msg_body_configure_ftdv_topic('cluster_delete', 'FIRST',
                                                                 _m_attr['instance_id'],
                                                                 str(int(_m_attr['counter']) - 1))
                sns.publish_to_topic(e_var['ClusterManagerTopic'], message_subject, msg_body)

    utl.put_line_in_log('SNS Handler Finished', 'thin')
    return

def check_cluster_status(aws_grp,ftd):
    """
    Purpose:    Check Cluster formation status
    Parameters: Autoscale Group Object, Device Object
    Returns:    SUCCESS, FAILURE
    Raises:
    """
    des, mins, maxs = aws_grp.get_asgroup_size()
    logger.info("Cluster Group Size: {}".format(mins))

    if mins != 1:
        count=0
        while count<20:
            status = ftd.connect_cluster()
            data = status.count('in state '+const.DATA_NODE+'\r\n')
            if data is (mins - 1):
                break
            logger.info("Waiting for cluster to be formed..")
            logger.info("Number of data node joined: {}".format(data))
            time.sleep(30)
            count+=1
        control = status.count('in state '+const.CONTROL_NODE)
        data = status.count('in state '+const.DATA_NODE)
        if (control != 1 or data != (mins - 1)):
            logger.info('Cluster is not properly formed..!!')
            return 'FAILURE'
        logger.info("Control: {}".format(control))
        logger.info("Data: {}".format(data))
    else:
        count=0
        while count<10:
            status = ftd.connect_cluster()
            if "in state "+const.CONTROL_NODE+"\r\n" in status:
                break
            logger.info("Waiting for cluster to be formed..")
            time.sleep(20)
            count+=1
        if count == 10:
            logger.info('Cluster is not properly formed..!!')
            return 'FAILURE'
    return "SUCCESS"

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
        # Initialize DerivedFMC & ClusterGroup
        fmc = fmc_cls_init()
        # FTD class initialization
        instance = ftd_cls_init(instance_id, fmc)

        instance_state = instance.get_instance_state()
        if instance_state == 'running' or instance_state == 'pending':
            logger.info("Instance %s is in state: %s" % (instance_id, instance_state))
            message_subject = 'Event: ' + e_var['ClusterGrpName'] + ' ' + 'instance poll' + ' ' + instance_id
            msg_body = utl.sns_msg_body_configure_ftdv_topic('cluster_ready', 'FIRST', instance_id)
            sns.publish_to_topic(e_var['ClusterManagerTopic'], message_subject, msg_body)
        else:
            logger.warn("Instance %s is in state: %s" % (instance_id, instance_state))

        if e_var['USER_NOTIFY_TOPIC_ARN'] != 'NA':
            # Email to user
            details_of_the_device = None
            message_subject = 'Event: ' + e_var['ClusterGrpName'] + ' ' + instance_id + ' ' + \
                              'joining cluster'
            msg_body = utl.sns_msg_body_user_notify_topic('Instance joining cluster', e_var['ClusterGrpName'],
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
        logger.info("Initiating cluster_delete function via SNS")

        if not const.DISABLE_CLUSTER_DELETE_FUNC:
            message_subject = 'Event: ' + e_var['ClusterGrpName'] + ' ' + 'instance delete' + ' ' + instance_id
            msg_body = utl.sns_msg_body_configure_ftdv_topic('cluster_delete', 'FIRST',
                                                             instance_id)
            sns.publish_to_topic(e_var['ClusterManagerTopic'], message_subject, msg_body)

        if e_var['USER_NOTIFY_TOPIC_ARN'] != 'NA':
            # Email to user
            details_of_the_device = None
            message_subject = 'Event: ' + e_var['ClusterGrpName'] + ' ' + instance_id + ' ' + \
                              'instance is terminated'
            msg_body = utl.sns_msg_body_user_notify_topic('Instance Terminated', e_var['ClusterGrpName'],
                                                          instance_id, details_of_the_device)
            sns.publish_to_topic(e_var['USER_NOTIFY_TOPIC_ARN'], message_subject, msg_body)
            # -------------
    utl.put_line_in_log('EC2 Terminate Handler finished', 'thin')
    return

# ----------------------------------------------------------------------------------------------------------------------
def execute_cluster_ready_first(ftd):
    """
    Purpose:    This polls NGFW instance for it's SSH accessibility
    Parameters: ManagedDevice object
    Returns:    SUCCESS, FAIL
    Raises:
    """
    poll_ftdv = ftd.poll_ftdv_ssh(const.FTD_POLL_TIME_IN_MIN_CLUSTER_READY)  # 10 minutes polling
    if poll_ftdv == "SUCCESS":
        request_response = ftd.configure_hostname()
        if request_response != 'COMMAND_RAN':
            ftd.configure_hostname()
        return 'SUCCESS'
    return 'FAIL'


def execute_cluster_register_first(ftd):
    """
    Purpose:    This registers the device to FMC
    Parameters: ManagedDevice object
    Returns:    SUCCESS, FAIL
    Raises:
    """
    ftd.create_instance_tags('NGFWvRegistrationStatus', 'ONGOING')
    try:
        reg_status = ftd.check_ftdv_reg_status()  # Check Device Registration state
        if reg_status == "COMPLETED":
            logger.info("Device registration successful ")
            return 'SUCCESS'
        elif reg_status == "PENDING":
            logger.info("Device registration is in pending status ")
            task_status = ftd.send_registration_request()  # Can return FAIL or SUCCESS
            time.sleep(1 * 60)
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
                    time.sleep(1 * 60)
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


def execute_cluster_delete_first(ftd, fmc):
    """
    Purpose:    This deletes the instance from Cluster Group, de-registers from FMC
    Parameters: ManagedDevice object, DerivedFMC Object
    Returns:    SUCCESS, FAIL
    Raises:
    """
    result = 'SUCCESS'
    try:
        state = ftd.get_instance_state()
        if state != 'terminated':
            asg_removal_status = ftd.remove_from_asg(const.DECREMENT_CAP_IF_CLUSTER_DELETED)
            if asg_removal_status == 'FAILED':
                raise Exception("Unable to delete Instance from ASG")
    except Exception as e:
        logger.exception(e)
        result = 'FAIL'
    return result


def aws_asg_cls_init():
    """
    Purpose:    To instantiate ClusterGroup class
    Parameters:
    Returns:    Object
    Raises:
    """
    # AWS Cluster Class initialization
    aws_grp = AutoScaleGroup(e_var['ClusterGrpName'])
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
        # Updates DerivedFMC object with appropriate user provided names
        fmc.update_fmc_config_user_input(j_var['fmcAccessPolicyName'])
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
    ftd.defaultPassword = const.DEFAULT_PASSWORD
    ftd.fmc_ip = j_var['fmcIpforDeviceReg']
    ftd.reg_id = j_var['RegistrationId']
    ftd.nat_id = j_var['NatId']
    ftd.l_caps = j_var['licenseCaps']
    ftd.performanceTier = j_var['performanceTier']

    # Updating device configuration
    ftd.update_device_configuration()

    return ftd


def fmc_configuration_validation(fmc, aws_grp):
    """
    Purpose:    To validate FMC configuration
    Parameters: DerivedFMC object, ClusterGroup object
    Returns:    PASS, FAIL
    Raises:
    """
    # Check if all needed/user-provided inputs have entries in FMC
    if fmc.check_fmc_configuration() == 'CONFIGURED':
        aws_grp.create_or_update_tags('FmcAvailabilityStatus', 'AVAILABLE')
        aws_grp.create_or_update_tags('FmcConfigurationStatus', 'CONFIGURED')
        return 'PASS'
    else:
        logger.critical("Fmc has configuration issues")
        aws_grp.create_or_update_tags('FmcAvailabilityStatus', 'UN-AVAILABLE')
        aws_grp.create_or_update_tags('FmcConfigurationStatus', 'UN-CONFIGURED')
        return 'FAIL'
