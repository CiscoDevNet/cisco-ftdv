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

Name:       utility.py
Purpose:    All static methods without class are written here
            It will be called in all NGFWv AutoScale Group Lambda functions
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
        "AutoScaleGrpName": "",
        "fmcDeviceGroupName": "",
        "fmcPerformanceLicenseTier": "",
        "max_number_of_interfaces": "4",
        "NO_OF_AZs": "",
        "SUBNET_ID_LIST_2": [],
        "SUBNET_ID_LIST_3": [],
        "SECURITY_GRP_2": "",
        "SECURITY_GRP_3": "",
        "LB_ARN_OUTSIDE": "",
        "LB_DEREGISTRATION_DELAY": "",
        "CONFIGURE_ASAV_TOPIC_ARN": "",
        "USER_NOTIFY_TOPIC_ARN": "",
        "FTD_LICENSE_TYPE": ""
    }

    try:
        user_input['AutoScaleGrpName'] = os.environ['ASG_NAME']
        user_input['fmcDeviceGroupName'] = os.environ['FMC_DEVICE_GRP']
        user_input['fmcPerformanceLicenseTier'] = os.environ['FMC_PERFORMANCE_TIER']
        if re.match(r'..*', user_input['fmcDeviceGroupName']) is None:
            raise ValueError("Unable to find valid FMC Device Group Name")
        user_input['max_number_of_interfaces'] = '4'
        user_input['NO_OF_AZs'] = os.environ['NO_OF_AZs']
        user_input['FTD_LICENSE_TYPE'] = os.environ['FTD_LICENSE_TYPE']
        user_input['SUBNET_ID_LIST_2'] = os.environ['INSIDE_SUBNET'].split('::')
        user_input['SECURITY_GRP_2'] = os.environ['SECURITY_GRP_2']
        user_input['SUBNET_ID_LIST_3'] = os.environ['OUTSIDE_SUBNET'].split('::')
        user_input['SECURITY_GRP_3'] = os.environ['SECURITY_GRP_3']
        user_input['LB_ARN_OUTSIDE'] = os.environ['LB_ARN_OUTSIDE']
        user_input['LB_DEREGISTRATION_DELAY'] = os.environ['LB_DEREGISTRATION_DELAY']
        user_input['CONFIGURE_ASAV_TOPIC_ARN'] = os.environ['CONFIGURE_ASAV_TOPIC_ARN']
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


def get_user_input_custom_metric():
    """
    Purpose:    To get user input for custom metric publisher
    Parameters:
    Returns:
    Raises:
    """
    user_input = {
        "AutoScaleGrpName": "",
        "fmcDeviceGroupName": "",
        "FmcServer": "",
        "FmcMetUserName": "",
        "FmcMetPassword": "",
        "cron_event_name": ""
    }

    try:
        user_input['AutoScaleGrpName'] = os.environ['ASG_NAME']
        if re.match(r'..*', user_input['AutoScaleGrpName']) is None:
            raise ValueError("Unable to find ASG_NAME in os.env")

        user_input['fmcDeviceGroupName'] = os.environ['FMC_DEVICE_GRP']
        if re.match(r'..*', user_input['fmcDeviceGroupName']) is None:
            raise ValueError("Unable to find FMC_DEVICE_GRP in os.env")

        user_input['FmcServer'] = os.environ['FMC_SERVER']
        if re.match(r'^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.(?!$)|$)){4}$',
                    user_input['FmcServer']) is None:
            raise ValueError("Unable to find valid FMC_SERVER in os.env, should be a valid IP")

        user_input['FmcMetUserName'] = os.environ['FMC_MET_USERNAME']
        if re.match(r'..*', user_input['FmcMetUserName']) is None:
            raise ValueError("Unable to find FMC_MET_USERNAME in os.env")

        user_input['cron_event_name'] = os.environ['CRON_JOB_NAME']
        if re.match(r'..*', user_input['cron_event_name']) is None:
            raise ValueError("Unable to find CRON_JOB_NAME in os.env")

        # Print collected values, later add Password to user_input JSON
        logger.debug("Environment Variables: " + json.dumps(user_input, separators=(',', ':')))

        user_input['FmcMetPassword'] = os.environ['FMC_MET_PASSWORD']
        if re.match(r'..*', user_input['FmcMetPassword']) is None:
            raise ValueError("Unable to find FMC_MET_PASSWORD in os.env")
        try:
            if os.environ['KMS_ENC'] is not None:
                user_input['FmcMetPassword'] = get_decrypted_key(user_input['FmcMetPassword'])
            else:
                logger.critical("Issue with KMS ARN in os.env")
                pass
        except KeyError:
            logger.debug("Looks like passwords may not be encrypted with KMS")
    except Exception as e:
        logger.error("Exception: {}".format(e))
        logger.error("Unable to find OS environment variables")

    return user_input


def get_user_input_manager():
    """
    Purpose:    This evaluates & takes User inputs from OS env & JSON
    Parameters:
    Returns:    OS Environment & JSON variables as JSON object
    Raises:
    """
    env_var = {
        "AutoScaleGrpName": "",
        "fmcDeviceGroupName": "",
        "fmcPerformanceLicenseTier": "",
        "AutoScaleManagerTopic": "",
        "USER_NOTIFY_TOPIC_ARN": "",
        "A_CRON_JOB_NAME": "",
        "LB_ARN_OUTSIDE": "",
        "FmcIp": "",
        "FmcUserName": "",
        "FmcPassword": "",
        "NgfwUserName": "admin",
        "NgfwPassword": "",
        "TargetGrpHealthPort": "",
		"GENEVE_SUPPORT": ""
    }

    try:
        geneve_support = os.environ["GENEVE_SUPPORT"]
    except:
        geneve_support = "disable"

    if geneve_support == "enable":
        schema1 = {
            "type": "object",
            "properties": {
                "AutoScaleGrpName": {
                    "type": "string",
                    "pattern": "^...*$"
                },
                "fmcDeviceGroupName": {
                    "type": "string",
                    "pattern": "^...*$"
                },
                "AutoScaleManagerTopic": {
                    "type": "string",
                    "pattern": "^arn:aws:sns:.*:.*:.*$"
                },
                "USER_NOTIFY_TOPIC_ARN": {
                    "type": "string",
                    "pattern": "(^$|^arn:aws:sns:.*:.*:.*)$"
                },
                "A_CRON_JOB_NAME": {
                    "type": "string",
                    "pattern": "^...*$"
                },
                "LB_ARN_OUTSIDE": {
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
                },
                "fmcPerformanceLicenseTier": {
                    "type": "string",
                    "pattern": "^((FTDv)|(FTDv20)|(FTDv30)|(FTDv50)|(FTDv100))$"
                }
            },
            "required": [
                "AutoScaleGrpName",
                "fmcDeviceGroupName",
                "fmcPerformanceLicenseTier",
                "AutoScaleManagerTopic",
                "USER_NOTIFY_TOPIC_ARN",
                "A_CRON_JOB_NAME",
                "LB_ARN_OUTSIDE",
                "FmcIp",
                "FmcUserName",
                "FmcPassword",
                "NgfwUserName",
                "NgfwPassword",
                "TargetGrpHealthPort"
            ]
        }
            
        schema2 = {
            "type":"object",
            "properties": {
                "licenseCaps":{
                    "type":"array",
                    "items":{
                        "type":"string",
                        "pattern":"^((BASE)|(MALWARE)|(THREAT)|(URLFilter)|(PROTECT)|(VPN)|(CONTROL))$"
                    }
                },
                "fmcIpforDeviceReg":{
                    "type":"string",
                    "pattern":"^((DONTRESOLVE)|((?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\\.(?!$)|$)){4}))$"
                },
                "RegistrationId":{
                    "type":"string",
                    "pattern":"^...*$"
                },
                "NatId":{
                    "type":"string",
                    "pattern":"^...*$"
                },
                "fmcAccessPolicyName":{
                    "type":"string",
                    "pattern":"^...*$"
                },
                "fmcInsideNicName":{
                    "type":"string",
                    "pattern":"^...*$"
                },
                "fmcOutsideNicName":{
                    "type":"string",
                    "pattern":"^...*$"
                },
                "fmcInsideNic":{
                    "type":"string",
                    "pattern":"^.*0/(0|1)$"
                },
                "fmcOutsideNic":{
                    "type":"string",
                    "pattern":"^.*0/(0|1)$"
                },
                "fmcOutsideZone":{
                    "type":"string",
                    "pattern":"^...*$"
                },
                "fmcInsideZone":{
                    "type":"string",
                    "pattern":"^...*$"
                },
                "MetadataServerObjectName": {
                    "type": "string",
                    "pattern": "^...*$"
                },
                "interfaceConfig":{
                    "type":"array",
                    "items":{
                        "type":"object",
                        "properties":{
                            "managementOnly": {
                                "type":"string",
                                "pattern":"^...*$"
                            },
                            "MTU":{
                                "type":"string",
                                "pattern":"^[1-9][0-9][0-9][0-9]$"
                            },
                            "securityZone":{
                                "type":"object",
                                "properties":{
                                    "name":{
                                        "type":"string",
                                        "pattern":"^...*$"
                                    }
                                },
                                "required":[
                                    "name"
                                ]
                            },
                            "mode":{
                                "type":"string",
                                "pattern":"^...*$"
                            },
                            "ifname":{
                                "type":"string",
                                "pattern":"^...*$"
                            },
                            "name":{
                                "type":"string",
                                "pattern":"^.*0/(0|1)$"
                            }
                        },
                        "required":[
                            "managementOnly",
                            "MTU",
                            "securityZone",
                            "mode",
                            "ifname",
                            "name"
                        ]
                    }
                },
                "trafficRoutes":{
                    "type":"array",
                    "items":{
                        "type":"object",
                        "properties":{
                            "interface":{
                                "type":"string",
                                "pattern":"^...*$"
                            },
                            "network":{
                                "type":"string",
                                "pattern":"^...*$"
                            },
                            "gateway":{
                                "type":"string",
                                "pattern":"(^$|^..*$|^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\\.(?!$)|$)){4}$)"
                            },
                            "metric":{
                                "type":"string",
                                "pattern":"^[1-9]\\d*$"
                            }
                        },
                        "required":[
                            "interface",
                            "network",
                            "gateway",
                            "metric"
                        ]
                    }
                }
            },
            "required":[
                "licenseCaps",
                "fmcIpforDeviceReg",
                "RegistrationId",
                "NatId",
                "fmcAccessPolicyName",
                "fmcInsideNicName",
                "fmcOutsideNicName",
                "fmcInsideNic",
                "fmcOutsideNic",
                "fmcOutsideZone",
                "fmcInsideZone",
                "MetadataServerObjectName",
                "interfaceConfig",
                "trafficRoutes"
            ]
        }
    else:
        schema1 = {
            "type": "object",
            "properties": {
                "AutoScaleGrpName": {
                    "type": "string",
                    "pattern": "^...*$"
                },
                "fmcDeviceGroupName": {
                    "type": "string",
                    "pattern": "^...*$"
                },
                "AutoScaleManagerTopic": {
                    "type": "string",
                    "pattern": "^arn:aws:sns:.*:.*:.*$"
                },
                "USER_NOTIFY_TOPIC_ARN": {
                    "type": "string",
                    "pattern": "(^$|^arn:aws:sns:.*:.*:.*)$"
                },
                "A_CRON_JOB_NAME": {
                    "type": "string",
                    "pattern": "^...*$"
                },
                "LB_ARN_OUTSIDE": {
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
                },
                "fmcPerformanceLicenseTier": {
                    "type": "string",
                    "pattern": "^((FTDv)|(FTDv5)|(FTDv10)|(FTDv20)|(FTDv30)|(FTDv50)|(FTDv100))$"
                }
            },
            "required": [
                "AutoScaleGrpName",
                "fmcDeviceGroupName",
                "fmcPerformanceLicenseTier",
                "AutoScaleManagerTopic",
                "USER_NOTIFY_TOPIC_ARN",
                "A_CRON_JOB_NAME",
                "LB_ARN_OUTSIDE",
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
                },
                "fmcNatPolicyName": {
                    "type": "string",
                    "pattern": "^...*$"
                },
                "fmcInsideNicName": {
                    "type": "string",
                    "pattern": "^...*$"
                },
                "fmcOutsideNicName": {
                    "type": "string",
                    "pattern": "^...*$"
                },
                "fmcInsideNic": {
                    "type": "string",
                    "pattern": "^.*0/(0|1)$"
                },
                "fmcOutsideNic": {
                    "type": "string",
                    "pattern": "^.*0/(0|1)$"
                },
                "fmcOutsideZone": {
                    "type": "string",
                    "pattern": "^...*$"
                },
                "fmcInsideZone": {
                    "type": "string",
                    "pattern": "^...*$"
                },
                "MetadataServerObjectName": {
                    "type": "string",
                    "pattern": "^...*$"
                },
                "interfaceConfig": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "managementOnly": {
                                "type": "string",
                                "pattern": "^...*$"
                            },
                            "MTU": {
                                "type": "string",
                                "pattern": "^[1-9][0-9][0-9][0-9]$"
                            },
                            "securityZone": {
                                "type": "object",
                                "properties": {
                                    "name": {
                                        "type": "string",
                                        "pattern": "^...*$"
                                    }
                                },
                                "required": [
                                    "name"
                                ]
                            },
                            "mode": {
                                "type": "string",
                                "pattern": "^...*$"
                            },
                            "ifname": {
                                "type": "string",
                                "pattern": "^...*$"
                            },
                            "name": {
                                "type": "string",
                                "pattern": "^.*0/(0|1)$"
                            }
                        },
                        "required": [
                            "managementOnly",
                            "MTU",
                            "securityZone",
                            "mode",
                            "ifname",
                            "name"
                        ]
                    }
                },
                "trafficRoutes": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "interface": {
                                "type": "string",
                                "pattern": "^...*$"
                            },
                            "network": {
                                "type": "string",
                                "pattern": "^...*$"
                            },
                            "gateway": {
                                "type": "string",
                                "pattern": "(^$|^..*$|^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\\.(?!$)|$)){4}$)"
                            },
                            "metric": {
                                "type": "string",
                                "pattern": "^[1-9]\\d*$"
                            }
                        },
                        "required": [
                            "interface",
                            "network",
                            "gateway",
                            "metric"
                        ]
                    }
                }
            },
            "required": [
                "licenseCaps",
                "fmcIpforDeviceReg",
                "RegistrationId",
                "NatId",
                "fmcAccessPolicyName",
                "fmcNatPolicyName",
                "fmcInsideNicName",
                "fmcOutsideNicName",
                "fmcInsideNic",
                "fmcOutsideNic",
                "fmcOutsideZone",
                "fmcInsideZone",
                "MetadataServerObjectName",
                "interfaceConfig",
                "trafficRoutes"
            ]
        }

    try:
        env_var['AutoScaleGrpName'] = os.environ['ASG_NAME']
        env_var['fmcDeviceGroupName'] = os.environ['FMC_DEVICE_GRP']
        env_var['fmcPerformanceLicenseTier'] = os.environ['FMC_PERFORMANCE_TIER']
        env_var['A_CRON_JOB_NAME'] = os.environ['A_CRON_JOB_NAME']
        env_var['AutoScaleManagerTopic'] = os.environ['AS_MANAGER_TOPIC']
        try:
            if os.environ['USER_NOTIFY_TOPIC_ARN'] and os.environ['USER_NOTIFY_TOPIC_ARN'] != '':
                env_var['USER_NOTIFY_TOPIC_ARN'] = os.environ['USER_NOTIFY_TOPIC_ARN']
        except Exception as e:
            logger.debug(e)
            env_var['USER_NOTIFY_TOPIC_ARN'] = ''

        env_var['LB_ARN_OUTSIDE'] = os.environ['LB_ARN_OUTSIDE']
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
	
    #read Geneve support flag	
    try:
        env_var['GENEVE_SUPPORT'] = os.environ['GENEVE_SUPPORT']
    except:
        env_var['GENEVE_SUPPORT'] = "disable"
		
    return env_var, json_var


def sns_msg_body_configure_ftdv_topic(to_function, category, instance_id, counter='-1'):
    """
    Purpose:    To prepare dict with correct values for manager lambda topic
    Parameters: to_function, category, instance id, counter
    Returns:    dict
    Raises:
    """
    if counter == '-1':
        if to_function == 'vm_ready':
            counter = const.TO_FUN_RETRY_COUNT[0]
        elif to_function == 'vm_register':
            counter = const.TO_FUN_RETRY_COUNT[1]
        elif to_function == 'vm_configure':
            counter = const.TO_FUN_RETRY_COUNT[2]
        elif to_function == 'vm_deploy':
            counter = const.TO_FUN_RETRY_COUNT[3]
        elif to_function == 'vm_delete':
            counter = const.TO_FUN_RETRY_COUNT[4]

    # Constructing a JSON object as per AWS SNS requirement
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
