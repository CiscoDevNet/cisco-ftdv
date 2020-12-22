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

Name:       lifecycle.py
Purpose:    This python file has Lambda handler for function LifeCycleLambda
Input:      Sample test event
            { "detail-type": "Scheduled Event" }
"""

import json
from aws import CloudWatchMetrics, AutoScaleGroup, CloudWatchEvent
from fmc import FirepowerManagementCenter
import constant as const
import utility as utl

logger = utl.setup_logging()
# Get User input
user_input = utl.get_user_input_custom_metric()


def lambda_handler(event, context):
    """
    Purpose:    Lambda Function for Custom Metric Publish
    Parameters: AWS Events (cloudwatch)
    Returns:
    Raises:
    """
    # utl.put_line_in_log('Custom Metric Publisher Lambda Handler started', 'thick')
    logger.info("Received event: " + json.dumps(event, separators=(',', ':')))

    if const.DISABLE_CUSTOM_METRIC_PUBLISH_LAMBDA is True:
        logger.info("Custom Metric Publisher Lambda running is disabled! Check constant.py")
        # utl.put_line_in_log('Custom Metric Publisher Lambda Handler finished', 'thick')
        return
    try:
        if event["detail-type"] == "Scheduled Event":
            handle_cron_event(event)
            # utl.put_line_in_log('Custom Metric Publisher Lambda Handler finished', 'thick')
            return
    except Exception as e:
        logger.debug(str(e))
        pass
    logger.info("Received an event but not a Scheduled Event")

    # EC2 CloudWatch Event
    try:
        if event["detail-type"] == "EC2 Instance Launch Successful":
            try:
                if event['detail']['EC2InstanceId']:
                    handle_ec2_launch_event()
                # utl.put_line_in_log('AutoScale Manager Lambda Handler finished', 'thick')
                return
            except Exception as e:
                logger.error("Unable to get instance ID from event, not a new instance launch event")
                logger.error("Error occurred {}".format(repr(e)))
                # utl.put_line_in_log('AutoScale Manager Lambda Handler finished', 'thick')
                return
    except Exception as e:
        logger.debug(str(e))
        pass
    logger.info("Received an event but not an EC2 launch CloudWatch event")

    # utl.put_line_in_log('Custom Metric Publisher Lambda Handler finished', 'thick')
    return


def handle_cron_event(event):
    """
    Purpose:    To handle cron CloudWatch Event
    Parameters: event
    Returns:
    Raises:
    """
    # utl.put_line_in_log('Cron Handler Started', 'thin')
    # AutoScale Group class initialization
    asg = AutoScaleGroup(user_input['AutoScaleGrpName'])
    instances_list = asg.get_instance_list()
    if len(instances_list) <= 0:
        logger.info("No instance found in AWS AutoScale Group")
        logger.info("Will DISABLE Cron job for Custom Metric Collection, gets ENABLED if new instance launches")
        # Initialize CloudWatchEvent class
        cw_event = CloudWatchEvent(user_input['cron_event_name'])
        cw_event.stop_cron_job()
        utl.put_line_in_log('Cron Handler Finished', 'thin')
        return

    # Update aws instance list as vm_name list
    append_str = user_input['AutoScaleGrpName'] + '-'
    aws_instance_name_list = [append_str + suf for suf in instances_list]

    # FMC class initialization
    fmc = FirepowerManagementCenter(user_input['FmcServer'], user_input['FmcMetUserName'], user_input['FmcMetPassword'])
    try:
        fmc.get_auth_token()
        device_grp_id = fmc.get_device_grp_id_by_name(user_input['fmcDeviceGroupName'])
        if device_grp_id is None:
            raise ValueError("Unable to find Device Group in FMC: %s " % user_input['fmcDeviceGroupName'])
        else:
            logger.debug("FMC Device group ID: %s " % device_grp_id)
    except Exception as e:
        logger.exception("Exception {}".format(e))
        logger.info("Will DISABLE Cron job for Custom Metric Collection"
                    "check if FMC is accessible & has mentioned device group")
        # Decided to not to disable Publisher if FMC is unreachable
        # Initialize CloudWatchEvent class
        # cw_event = CloudWatchEvent(user_input['cron_event_name'])
        # # cw_event.stop_cron_job()
    else:
        fmc_devices_list, device_id_list = fmc.get_member_list_in_device_grp(device_grp_id)
        query_device_dict = dict(zip(fmc_devices_list, device_id_list))
        intersection_list = utl.intersection(aws_instance_name_list, fmc_devices_list)
        pair_of_metric_name_value = []

        metric_name_value = {
                "unit": const.DEVICE_NO_UNIT,
                "metric_name": const.NO_DEV_IN_FMC_NOT_IN_AWS,
                "value": len(fmc_devices_list) - len(aws_instance_name_list)
            }
        pair_of_metric_name_value.append(metric_name_value)

        metric_name_value = {
                "unit": const.DEVICE_NO_UNIT,
                "metric_name": const.NO_DEV_IN_AWS_NOT_IN_FMC,
                "value": len(aws_instance_name_list) - len(fmc_devices_list)
            }
        pair_of_metric_name_value.append(metric_name_value)

        metric_name_value = {
                "unit": const.DEVICE_NO_UNIT,
                "metric_name": const.NO_DEV_IN_BOTH_FMC_AWS,
                "value": len(intersection_list)
            }
        pair_of_metric_name_value.append(metric_name_value)
        # Update list with memory metrics
        pair_of_metric_name_value, ftdv_memory_metric_dict = get_memory_metric_pair(fmc, pair_of_metric_name_value,
                                                                                    intersection_list,
                                                                                    query_device_dict)
        # Publish Metrics to CloudWatch
        update_cloudwatch_metric(pair_of_metric_name_value)

        logger.info("List of instance name in AWS AutoScale Group: {}".format(aws_instance_name_list))
        logger.info("List of members in FMC device group: {}".format(fmc_devices_list))
        logger.info("Memory Metric per FTDv: " + json.dumps(ftdv_memory_metric_dict, separators=(',', ': ')))
        logger.info("Metrics published: " + json.dumps(pair_of_metric_name_value, separators=(',', ': ')))

    utl.put_line_in_log('Cron Handler Finished', 'thin')
    return


def handle_ec2_launch_event():
    """
    Purpose:    Check if cron rule is DISABLED, if DISABLED then ENABLE it
    Parameters:
    Returns:
    Raises:
    """
    cw_event = CloudWatchEvent(user_input['cron_event_name'])
    status = cw_event.cron_job_status()
    if status == 'DISABLED':
        cw_event.start_cron_job()
        logger.info("ENABLED CloudWatch Rule: " + cw_event.name)
    else:
        logger.info("CloudWatch Rule: " + cw_event.name + " is already ENABLED")
    return


def update_cloudwatch_metric(pair_of_metric_name_value):
    """
    Purpose:    To update metric with list of metric data in one go
    Parameters: dict of metric name, unit, value
    Returns:    SUCCESS, None
    Raises:
    """
    cloud_watch = CloudWatchMetrics(user_input['AutoScaleGrpName'], user_input['fmcDeviceGroupName'])
    try:
        if cloud_watch.multiple_put_metric_data(pair_of_metric_name_value) is None:
            raise ValueError('Unable to publish metrics to CloudWatch')
        return 'SUCCESS'
    except ValueError as e:
        logger.error("{}".format(e))
    return None


def get_memory_metric_pair(fmc, pair_of_metric_name_value, intersection_list, query_device_dict):
    """
    Purpose:     To get Memory metric from FMC & update pair_of_metric_name_value
    Parameters:
    Returns:
    Raises:
    """
    ftdv_memory_metric_dict = {}

    count = 0
    sum_memory, max_memory, min_memory = (0 for i in range(3))
    for i in range(0, len(intersection_list)):
        device_name = intersection_list[i]
        device_id = query_device_dict[device_name]
        response = fmc.get_memory_metrics_from_fmc(device_id)
        if response is None:
            logger.error("Unable to get metrics for instance: " + device_name)
        try:
            metric_value = response["items"][0]["healthMonitorMetric"]["value"]
            ftdv_memory_metric_dict.update({device_name: metric_value})
            if i == 0:
                max_memory = metric_value
                min_memory = metric_value
            else:
                if metric_value > max_memory:
                    max_memory = metric_value
                if metric_value < min_memory:
                    min_memory = metric_value
            sum_memory += metric_value
        except Exception as e:
            logger.error("{}".format(e))
        count += 1

    if len(ftdv_memory_metric_dict) > 0:
        metric_name_value = {
            "unit": const.MEMORY_UNIT,
            "metric_name": const.GROUP_AVG_MEMORY,
            "value": sum_memory / count
        }
        pair_of_metric_name_value.append(metric_name_value)
        metric_name_value = {
            "unit": const.MEMORY_UNIT,
            "metric_name": const.GROUP_MAX_MEMORY,
            "value": max_memory
        }
        pair_of_metric_name_value.append(metric_name_value)
        metric_name_value = {
            "unit": const.MEMORY_UNIT,
            "metric_name": const.GROUP_MIN_MEMORY,
            "value": min_memory
        }
        pair_of_metric_name_value.append(metric_name_value)

    return pair_of_metric_name_value, ftdv_memory_metric_dict
