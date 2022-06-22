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
import requests
import oci
import time
import ast
import base64
import jsonschema
from jsonschema import validate
from datetime import datetime
from dateutil.tz import tzutc

logging.basicConfig(force=True, level="INFO")
logger = logging.getLogger()

class TokenCaller:
    def __init__(self, compartmentId, appName):
        self.compartmentId = compartmentId
        self.appName = appName
        self.signer = oci.auth.signers.get_resource_principals_signer()
        self.functions_client = oci.functions.FunctionsManagementClient(config={}, signer = self.signer)
        self.funcName = "ftdv_token_manager"
        self.authTokenMaxAge = 30*60  # seconds - 30 minutes is the max without using refresh
        #self.functionId = self.get_function_id(self.funcName)
        
    def get_token(self, endpoint):
        try:
            get_function_response = self.functions_client.get_function(function_id = self.get_function_id(self.funcName)).data
            config = get_function_response.config
            if "TOKEN" in config:
                tokenDict = ast.literal_eval(get_function_response.config['TOKEN'])
                authTokenTimestamp = int(tokenDict['authTokenTimestamp'])
                if time.time() > self.authTokenMaxAge + authTokenTimestamp:
                    logger.info("UTILITY: Existing Token not Valid. Time since last token: {0:.2f}".format((int(time.time())- authTokenTimestamp)/60))
                    return self.invoke_token_manager(endpoint)
                else:
                    logger.info("UTILITY: Existing Token Valid")
                    return tokenDict
            else:
                logger.info("UTILITY: Token does not exist, Creating New One")
                return self.invoke_token_manager(endpoint)
        except Exception as e:
            logger.info("UTILITY: FTDv TOKEN MANAGER: ERROR IN GETTING EXISTING TOKEN, WILL CREATE NEW ONE "+repr(e))
            return self.invoke_token_manager(endpoint)

    def update_application_variables(self):
        try:
            appId = self.get_application_id()
            get_application_response = self.functions_client.get_application(application_id=appId).data
            app_config = get_application_response.config
            endpoint = self.get_function_invoke_endpoint()
            app_config['token_endpoint_url'] = endpoint
            
            update_application_response = self.functions_client.update_application(
                application_id = appId,
                update_application_details=oci.functions.models.UpdateApplicationDetails(config=app_config))
            
            logger.info("Application Variable updated successfully")
            return endpoint
        except Exception as e:
            logger.error("UNABLE TO UPDATE APPLICATION VARIABLE  "+repr(e))
            return None
            
    def get_application_id(self):
        try:
            list_applications_response = self.functions_client.list_applications(
                compartment_id = self.compartmentId,
                lifecycle_state = "ACTIVE",
                display_name = self.appName).data
            return list_applications_response[0].id
        except Exception as e:
            raise Exception("ERROR IN RETRIEVING APPLICATION ID  "+repr(e))

    def get_function_id(self, funcName):
        try:
            list_functions_response = self.functions_client.list_functions(
                application_id = self.get_application_id(),
                lifecycle_state = "ACTIVE",
                display_name = funcName).data

            return list_functions_response[0].id
        except Exception as e:
            raise Exception("ERROR IN RETRIEVING FUNCTION ID  "+repr(e))
    
    """
    def invoke_token_manager(self):
        try:
            invoke_function_response = self.functions_client.invoke_function(function_id = self.functionId).data
            #invoke_function_body=b"bVRE7d4xjGipODEvEcpA"
            logger.info("RESPONSE RECEIVED FROM TOKEN MANAGER")
            return invoke_function_response
        except Exception as e:
            logger.error("ERROR IN INVOKING FTDv TOKEN MANAGER")
            return None
    """
    def invoke_token_manager(self, endpoint):
        try:
            response = requests.post(endpoint, auth=self.signer)
            logger.info("RESPONSE RECEIVED FROM TOKEN MANAGER")
            #logger.info(response.json())
            response.raise_for_status()
            return ast.literal_eval(response.json()['TOKEN'])
        except Exception as e:
            raise Exception("ERROR IN INVOKING TOKEN MANAGER  "+repr(e))
        finally:
            if response:
                response.close()

    def get_function_invoke_endpoint(self):
        try:
            funcId = self.get_function_id(self.funcName)
            get_function_response = self.functions_client.get_function(function_id = funcId).data
            endpoint = str(get_function_response.invoke_endpoint)+"/20181201/functions/"+str(funcId)+"/actions/invoke"
            return endpoint
        except Exception as e:
            raise Exception("ERROR IN RETRIEVING FUNCTION ENDPOINT  "+repr(e))

def terminate_instance(instanceId):
    """
    Purpose:   To Terminate any Instance in the Instance Pool (Not Scale-In)
    Parameters: Instance OCID to delete.
    Returns:    Boolean
    Raises:
    """
    auth = oci.auth.signers.get_resource_principals_signer()
    computeClient = oci.core.ComputeClient(config={}, signer=auth)

    for i in range(0,3):
        try:
            terminate_instance_response = computeClient.terminate_instance(instance_id = instanceId, preserve_boot_volume=False)
            logger.info(f"FTDv {instanceId[-5:]}:  INSTANCE HAS BEEN TERMINATED ")
            return True
        
        except Exception as e:
            logger.info("FTDv: ERROR OCCURRED WHILE TERMINATING INSTANCE {}, RETRY COUNT:{}, REASON:{}".format(instanceId, str(i+1), repr(e)))
            continue
    return False

def get_time_since_creation(instanceId):
    """
    Purpose:   To calculate time since instance was created.
    Parameters: 
    Returns:    int (Minutes)
    Raises:
    """
    try:
        auth = oci.auth.signers.get_resource_principals_signer()
        core_client = oci.core.ComputeClient(config={}, signer=auth)
        get_instance_response = core_client.get_instance(instance_id=instanceId).data
        instance_creation_time = get_instance_response.time_created
        logger.debug(f"FTDv: Time since creation {instance_creation_time}")

        current_time_in_utc = datetime.now(tzutc())
        time_difference = current_time_in_utc - instance_creation_time
        minutes = time_difference.seconds/60
        return minutes
    except Exception as e:
        logger.error(f"ERROR IN GETTING \"TIME SINCE CREATION\" FOR INSTANCE {instanceId}")
        return 31

def decrypt_cipher(cipherText, cryptEndpoint, keyId):
    """
    Purpose:   To decrypt encrypted password.
    Parameters: Encrypted Password, Cryptographic Endpoint, Master Key OCID
    Returns:    Password in plaintext (str)
    Raises:
    """
    for i in range(0,3):
        try:
            auth = oci.auth.signers.get_resource_principals_signer()
            key_management_client = oci.key_management.KmsCryptoClient(config={}, signer=auth, service_endpoint = cryptEndpoint)

            decrypt_response = key_management_client.decrypt(
                decrypt_data_details=oci.key_management.models.DecryptDataDetails(
                    ciphertext = cipherText,
                    key_id = keyId)).data

            return str(base64.b64decode(decrypt_response.plaintext).decode('utf-8'))
        except Exception as e:
            logger.error("POST LAUNCH ACTION: ERROR IN DECRYPTING PASSWORD ERROR: {}".format(e))
            continue
    return None

def get_fmc_configuration_input(ftdv_configuration_json_url):
    """
    Purpose:    This evaluates & takes User inputs from OS env & JSON
    Parameters:
    Returns:    OS Environment & JSON variables as JSON object
    Raises:
    """

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
                "pattern": "^((FTDv5)|(FTDv10)|(FTDv20)|(FTDv30)|(FTDv50)|(FTDv100))$"
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
            "performanceTier",
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
        r = requests.get(ftdv_configuration_json_url)
        temp = (r.content).decode('utf-8')
        json_var = json.loads(temp)
        r.raise_for_status()
    except Exception as e:
        raise Exception("CONFIGURE FTDv: ERROR IN LOADING FTDv CONFIGURATION.JSON  "+repr(e))
    try:    
        validate(json_var, schema=schema2)
    except jsonschema.exceptions.ValidationError as e:
        raise Exception("CONFIGURE FTDv: JSON file validation failed against schema "+repr(e))
    except json.JSONDecodeError as e:
        raise Exception("CONFIGURE FTDv: Configuration.json is not a valid JSON document  "+repr(e))
    except Exception as e:
        raise Exception("ERRON IN VALIDATION OF CONFIGURATION JSON "+repr(e))

    return json_var

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
        logger.error("CONFIGURE FTDv: CIDR fetched from describe-subnet may not be correct! {}".format(repr(e)))
        return
    else:
        logger.debug("CONFIGURE FTDv: Gateway for subnet cidr: %s" % str(cidr) + " is %s" % str(n[1]))
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


