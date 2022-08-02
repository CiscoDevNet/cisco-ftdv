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
--------------------------------------------------------------------------------

Name:       utility.py
Purpose:    All static methods without class are written here
            It will be called in all NGFWv Cluster Group Lambda functions
"""

import os
import sys
import logging
import json
import re
import ipaddress
import boto3
import constant as const
from base64 import b64decode
import jsonschema
from jsonschema import validate


def get_decrypted_key(encrypted_key):
    """
    Purpose:    Decrypts encrypted data using KMS Key given to lambda function
    Parameters: Encrypted key
    Returns:    Decrypted key
    Raises:
    """
    response = boto3.client('kms').decrypt(CiphertextBlob=b64decode(encrypted_key))['Plaintext']
    decrypted_key = str(response, const.ENCODING)
    return decrypted_key


def setup_logging():
    """
    Purpose:    Sets up logging
    Parameters: User input to disable debug logs
    Returns:    logger object
    Raises:
    """
    try:
        debug_logs = os.environ['DEBUG_LOGS']
    except Exception as e:
        logging.exception(e)
        debug_logs = 'enable'
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.INFO)
    logger = logging.getLogger()
    for h in logger.handlers:
        logger.removeHandler(h)
    h = logging.StreamHandler(sys.stdout)
    format_ = '%(levelname)s [%(asctime)s] (%(funcName)s)# %(message)s'
    h.setFormatter(logging.Formatter(format_))
    logger.addHandler(h)
    logger.setLevel(logging.DEBUG)
    if debug_logs == "disable":
        logging.disable(logging.DEBUG)
    return logger


def put_line_in_log(var, line_type='dot'):
    """
    Purpose:    This is to help putting lines in logs
    Parameters: variable to print between lines
    Returns:
    Raises:
    """
    if line_type == 'thick':
        logging.info("======================================= < " + var + " > ========================================")
    if line_type == 'thin':
        logging.info("--------------------------------------- < " + var + " > ----------------------------------------")
    if line_type == 'dot':
        logging.info("....................................... < " + var + " > ........................................")
    return


def get_user_input_lifecycle_ftdv():
    """
    Purpose:    To get os.env for lifecycle lambda
    Parameters:
    Returns:
    Raises:
    """
    user_input = {
        "ClusterGrpName": "",
        "fmcDeviceGroupName": "",
        "max_number_of_interfaces": "5",
        "NO_OF_AZs": "",
        "SUBNET_ID_LIST_2": [],
        "SUBNET_ID_LIST_3": [],
        "SUBNET_ID_LIST_4": [],
        "GWLBSUPPORT": "",
        "SECURITY_GRP_2": "",
        "SECURITY_GRP_3": "",
        "SECURITY_GRP_4": "",
        "GWLB_ARN": "",
        "LB_DEREGISTRATION_DELAY": "",
        "USER_NOTIFY_TOPIC_ARN": "",
        "FTD_LICENSE_TYPE": ""
    }

    try:
        user_input['ClusterGrpName'] = os.environ['ASG_NAME']
        user_input['fmcDeviceGroupName'] = os.environ['FMC_DEVICE_GRP']
        if re.match(r'..*', user_input['fmcDeviceGroupName']) is None:
            raise ValueError("Unable to find valid FMC Device Group Name")
        user_input['max_number_of_interfaces'] = '5'
        user_input['NO_OF_AZs'] = os.environ['NO_OF_AZs']
        user_input['FTD_LICENSE_TYPE'] = os.environ['FTD_LICENSE_TYPE']
        user_input['SUBNET_ID_LIST_2'] = os.environ['INSIDE_SUBNET'].split('::')
        user_input['SECURITY_GRP_2'] = os.environ['SECURITY_GRP_2']
        try:
            user_input['SUBNET_ID_LIST_3'] = os.environ['OUTSIDE_SUBNET'].split('::')
        except KeyError as e:
            logger.debug("Exception occurred: {}".format(repr(e)))
            user_input['SUBNET_ID_LIST_3'] = None
        try:
            user_input['SECURITY_GRP_3'] = os.environ['SECURITY_GRP_3']
        except KeyError as e:
            logger.debug("Exception occurred: {}".format(repr(e))) 
            user_input['SECURITY_GRP_3'] = None
        user_input['SUBNET_ID_LIST_4'] = os.environ['CCL_SUBNET'].split('::')
        user_input['SECURITY_GRP_4'] = os.environ['SECURITY_GRP_4']
        user_input['GWLBSUPPORT'] = os.environ['GWLBSUPPORT']
        if user_input['GWLBSUPPORT'] == "Yes":
            user_input['GWLB_ARN'] = os.environ['GWLB_ARN']
        else:
            user_input['GWLB_ARN'] = None
        user_input['LB_DEREGISTRATION_DELAY'] = os.environ['LB_DEREGISTRATION_DELAY']
        try:
            user_input['USER_NOTIFY_TOPIC_ARN'] = os.environ['USER_NOTIFY_TOPIC_ARN']
        except KeyError as e:
            logger.debug("Exception occurred: {}".format(repr(e)))
            user_input['USER_NOTIFY_TOPIC_ARN'] = None
    except Exception as e:
        logger.error("Exception: {}".format(e))
        logger.error("Unable to find OS environment variables")

    logger.debug("Environment Variables: " + json.dumps(user_input, separators=(',', ':')))
    return user_input


def get_user_input_manager():
    """
    Purpose:    This evaluates & takes User inputs from OS env & JSON
    Parameters:
    Returns:    OS Environment & JSON variables as JSON object
    Raises:
    """
    env_var = {
        "ClusterGrpName": "",
        "fmcDeviceGroupName": "",
        "ClusterManagerTopic": "",
        "USER_NOTIFY_TOPIC_ARN": "",
        "GWLBSUPPORT" : "",
        "GWLB_ARN": "",
        "FmcIp": "",
        "FmcUserName": "",
        "FmcPassword": "",
        "NgfwUserName": "admin",
        "NgfwPassword": "",
        "TargetGrpHealthPort": ""
    }

    schema1 = {
        "type": "object",
        "properties": {
            "ClusterGrpName": {
                "type": "string",
                "pattern": "^...*$"
            },
            "fmcDeviceGroupName": {
                "type": "string",
                "pattern": "^...*$"
            },
            "ClusterManagerTopic": {
                "type": "string",
                "pattern": "^arn:aws:sns:.*:.*:.*$"
            },
            "USER_NOTIFY_TOPIC_ARN": {
                "type": "string",
                "pattern": "^...*$"
            },
            "GWLBSUPPORT": {
                "type": "string",
                "pattern": "^...*$"
            },
            "GWLB_ARN": {
                "type": "string",
                "pattern": "^...*$"
            },
            "FmcIp": {
                "type": "string",
                "pattern": "^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\\.(?!$)|$)){4}$"
            },
            "FmcUserName": {
                "type": "string",
                "pattern": "^...*$"
            },
            "FmcPassword": {
                "type": "string",
                "pattern": "^...*$"
            },
            "NgfwUserName": {
                "type": "string",
                "pattern": "^...*$"
            },
            "NgfwPassword": {
                "type": "string",
                "pattern": "^...*$"
            },
            "TargetGrpHealthPort": {
                "type": "string",
                "pattern": "^()([1-9]|[1-5]?[0-9]{2,4}|6[1-4][0-9]{3}|65[1-4][0-9]{2}|655[1-2][0-9]|6553[0-5])$"
            }
        },
        "required": [
            "ClusterGrpName",
            "fmcDeviceGroupName",
            "ClusterManagerTopic",
            "USER_NOTIFY_TOPIC_ARN",
            "GWLBSUPPORT",
            "GWLB_ARN",
            "FmcIp",
            "FmcUserName",
            "FmcPassword",
            "NgfwUserName",
            "NgfwPassword",
            "TargetGrpHealthPort"
        ]
    }

    schema2 = {
        "type": "object",
        "properties": {
            "licenseCaps": {
                "type": "array",
                "items": {
                    "type": "string",
                    "pattern": "^((BASE)|(MALWARE)|(THREAT)|(URLFilter)|(PROTECT)|(VPN)|(CONTROL))$"
                }
            },
            "performanceTier": {
                "type": "string",
                "pattern": "^...*$"
            },
            "fmcIpforDeviceReg": {
                "type": "string",
                "pattern": "^((DONTRESOLVE)|((?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\\.(?!$)|$)){4}))$"
            },
            "RegistrationId": {
                "type": "string",
                "pattern": "^...*$"
            },
            "NatId": {
                "type": "string",
                "pattern": "^...*$"
            },
            "fmcAccessPolicyName": {
                "type": "string",
                "pattern": "^...*$"
            }
        },
        "required": [
            "licenseCaps",
            "performanceTier",
            "fmcIpforDeviceReg",
            "RegistrationId",
            "NatId",
            "fmcAccessPolicyName"
        ]
    }

    try:
        env_var['ClusterGrpName'] = os.environ['ASG_NAME']
        env_var['fmcDeviceGroupName'] = os.environ['FMC_DEVICE_GRP']

        env_var['ClusterManagerTopic'] = os.environ['CLS_MANAGER_TOPIC']
        try:
            if os.environ['USER_NOTIFY_TOPIC_ARN'] and os.environ['USER_NOTIFY_TOPIC_ARN'] != '':
                env_var['USER_NOTIFY_TOPIC_ARN'] = os.environ['USER_NOTIFY_TOPIC_ARN']
        except Exception as e:
            logger.debug(e)
            env_var['USER_NOTIFY_TOPIC_ARN'] = 'NA'

        env_var['GWLBSUPPORT'] = os.environ['GWLBSUPPORT']
        if env_var['GWLBSUPPORT'] == "Yes":
            env_var['GWLB_ARN'] = os.environ['GWLB_ARN']
        else:
            env_var['GWLB_ARN'] = 'NA'
        env_var['FmcIp'] = os.environ['FMC_SERVER']
        env_var['FmcUserName'] = os.environ['FMC_USERNAME']
        env_var['FmcPassword'] = os.environ['FMC_PASSWORD']
        try:
            if os.environ['KMS_ENC'] is not None:
                env_var['FmcPassword'] = get_decrypted_key(env_var['FmcPassword'])
            else:
                logger.critical("Issue with KMS ARN in template")
                pass
        except KeyError:
            logger.debug("No KMS ARN found in os.env['KMS_ENC'], password should be in plain-text")
        except Exception as e:
            logger.exception(e)
        env_var['NgfwPassword'] = os.environ['FTD_PASSWORD']
        try:
            if os.environ['KMS_ENC'] is not None:
                env_var['NgfwPassword'] = get_decrypted_key(env_var['NgfwPassword'])
            else:
                logger.critical("Issue with KMS ARN in template")
                pass
        except KeyError:
            logger.debug("No KMS ARN found in os.env['KMS_ENC'], password should be in plain-text")
        except Exception as e:
            logger.exception(e)
        env_var['TargetGrpHealthPort'] = os.environ['TG_HEALTH_PORT']

    except ValueError as e:
        logger.exception(e)
        logger.error("Check if Lambda function os.env variables are valid")
        exit(1)
    except KeyError as e:
        logger.exception(e)
        logger.error("Please check If all Lambda function variables exist in variable section")
        exit(1)
    except Exception as e:
        logger.exception(e)

    try:
        validate(env_var, schema=schema1)
    except jsonschema.exceptions.ValidationError as e:
        logger.exception(e)
        logger.error("os.env has invalid values for keys")
    except Exception as e:
        logger.exception(e)

    try:
        with open(const.JSON_LOCAL_FILENAME) as json_file:
            json_var = json.load(json_file)
            logger.debug("User provided JSON Configuration: " + json.dumps(json_var, separators=(',', ':')))
            validate(json_var, schema=schema2)
    except jsonschema.exceptions.ValidationError as e:
        logger.exception(e)
        logger.error("JSON file validation failed against schema")
    except json.JSONDecodeError as e:
        logger.exception(e)
        logger.error("Configuration.json is not a valid JSON document")
    except Exception as e:
        logger.exception(e)

    return env_var, json_var


def sns_msg_body_configure_ftdv_topic(to_function, category, instance_id, counter='-1', task_id=''):
    """
    Purpose:    To prepare dict with correct values for manager lambda topic
    Parameters: to_function, category, instance id, counter
    Returns:    dict
    Raises:
    """
    if counter == '-1':
        if to_function == 'cluster_ready':
            counter = const.TO_FUN_RETRY_COUNT[0]
        elif to_function == 'cluster_status':
            counter = const.TO_FUN_RETRY_COUNT[1]
        elif to_function == 'cluster_register':
            counter = const.TO_FUN_RETRY_COUNT[2]
        elif to_function == 'cluster_delete':
            counter = const.TO_FUN_RETRY_COUNT[3]

    # Constructing a JSON object as per AWS SNS requirement
    if task_id != '':
        sns_message = {
            "to_function": to_function,
            "category": category,
            "instance_id": instance_id,
            "counter": str(counter),
            "task_id": task_id
            }
    else:
        sns_message = {
            "to_function": to_function,
            "category": category,
            "instance_id": instance_id,
            "counter": str(counter)
            }

    logger.debug("Prepared message body: " + json.dumps(sns_message, separators=(',', ':')))

    return sns_message


def sns_msg_body_user_notify_topic(message, autoscale_group, instance_id, details=None):
    """
    Purpose:    To prepare dict with correct values for user topic
    Parameters: message, group name, instance_id, details
    Returns:    dict
    Raises:
    """
    # Constructing a JSON object as per AWS SNS requirement
    sns_message = {
        "description": message,
        "autoscale_group": autoscale_group,
        "instance_id": instance_id,
        "details": details
    }

    logger.debug("Prepared message body: " + json.dumps(sns_message, separators=(',', ':')))

    return sns_message


def get_common_member_in_list(list1, list2):
    """
    Purpose:    To get common in two list
    Parameters: two list
    Returns:    common set if len is 1, else []
    Raises:
    """
    list1_set = set(list1)
    list2_set = set(list2)
    common_set = list1_set.intersection(list2_set)
    logger.info("Common subnet is: %s" % common_set)
    if len(common_set) == 1:
        return list(common_set)
    elif len(common_set) > 1:
        logger.error("More than one subnets from same Availability Zones")
        return []
    else:
        logger.error("No subnets from given Availability Zones")
        return []


def get_gateway_from_cidr(cidr):
    """
    Purpose:    To get Gateway from given cidr block
    Parameters: cidr
    Returns:    gateway
    Raises:
    """
    try:
        n = ipaddress.IPv4Network(cidr)
    except ValueError as e:
        logger.error("Exception occurred {}".format(repr(e)))
        logger.info("Looks like CIDR fetched from describe-subnet may not be correct!")
        exit(1)
    else:
        logger.info("Gateway for subnet cidr: %s" % str(cidr) + " is %s" % str(n[1]))
        return str(n[1])


def intersection(lst1, lst2):
    """
    Purpose:    To get intersection of two list
    Parameters: two list
    Returns:    common list
    Raises:
    """
    # Use of hybrid method
    temp = set(lst2)
    lst3 = [value for value in lst1 if value in temp]
    return lst3


def union(lst1, lst2):
    """
    Purpose:    To get union of lists
    Parameters: two lists
    Returns:    list
    Raises:
    """
    final_list = list(set().union(lst1, lst2))
    return final_list


def find_value_in_list(l_r, value):
    """
    Purpose:    To get value in a given list
    Parameters: list, value
    Returns:    True or False
    Raises:
    """
    result = False
    for item in l_r:
        if item['id'] == value:
            result = True
            break
    return result


# Run for this file too
logger = setup_logging()
