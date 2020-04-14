"""
Name:       utility.py
Purpose:    This is contains utility functions
            All non-class methods are available here
            This gets called in all project files except constant.py
"""
import os
import sys
import json
import re
import logging
import constant as const
import boto3
import ipaddress
from base64 import b64decode


def get_variables():
    """
    Purpose:    This evaluates & takes User inputs from OS env & JSON
    Parameters:
    Returns:    OS Environment & JSON variables as JSON object
    Raises:
    """
    environment_variables = {
        "DebugDisable": False,
        "AutoScaleGrpName": "",
        "AutoScaleManagerTopic": "",
        "FmcIp": "",
        "FmcUserName": "",
        "FmcPassword": "",
        "NgfwUserName": "admin",
        "NgfwPassword": "",
        "TargetGrpHealthPort": ""
    }

    json_variables = {
        "LicenseCaps": ["BASE"],
        "NGFWvNamePrefix": "CiscoNGFW",
        "NgfwDefaultPassword": "Cisco123789!",
        "DeviceRegFmcIp": "DONTRESOLVE",
        "AccessPolicyName": "",
        "DeviceGroupName": "",
        "RegistrationId": "",
        "NatId": "",
        "InsideNicName": "inside",
        "OutsideNicName": "outside",
        "InsideNic": "GigabitEthernet0/0",
        "OutsideNic": "GigabitEthernet0/1",
        "OutsideZone": "",
        "InsideZone": "",
        "Objects": [],
        "InterfaceConfig": [],
        "TrafficRoutes": [],
        "NgfwSshPort": 22
    }

    try:
        if os.environ['DEBUG_DISABLED'] is not None:
            if os.environ['DEBUG_DISABLED'].lower() == 'true':
                environment_variables['DebugDisable'] = True
    except (KeyError, Exception) as e:
        logging.debug("Error occurred: {}".format(repr(e)))
        pass

    try:
        environment_variables['AutoScaleGrpName'] = os.environ['ASG_NAME']
        if re.match(r'^.{1,24}$', environment_variables['AutoScaleGrpName']) is None:
            raise ValueError("Unable to find valid AutoScale Group Name in os.env, len should be less than 24")

        environment_variables['AutoScaleManagerTopic'] = os.environ['AS_MANAGER_TOPIC']
        if re.match(r'^arn:aws:sns:.*:.*:.*$', environment_variables['AutoScaleManagerTopic']) is None:
            raise ValueError("Unable to find valid Topic ARN in os.env")

        environment_variables['FmcIp'] = os.environ['FMC_SERVER']
        if re.match(r'^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.(?!$)|$)){4}$',
                    environment_variables['FmcIp']) is None:
            raise ValueError("Unable to find valid FMC IP in os.env, len should be less than 24")

        environment_variables['FmcUserName'] = os.environ['FMC_USERNAME']
        if re.match(r'..*', environment_variables['FmcUserName']) is None:
            raise ValueError("Unable to find FMC Username in os.env")

        environment_variables['FmcPassword'] = os.environ['FMC_PASSWORD']
        if re.match(r'..*', environment_variables['FmcPassword']) is None:
            raise ValueError("Unable to find FMC Password in os.env")
        try:
            if os.environ['KMS_ENC'] is not None:
                environment_variables['FmcPassword'] = get_decrypted_key(environment_variables['FmcPassword'])
            else:
                logger.critical("Issue with KMS ARN in template")
                pass
        except Exception as e:
            logger.debug("Exception occurred {}".format(repr(e)))
            logger.debug("Looks like passwords may not be encrypted!")

        environment_variables['NgfwPassword'] = os.environ['FTD_PASSWORD']
        if re.match(r'..*', environment_variables['NgfwPassword']) is None:
            raise ValueError("Unable to valid NGFWv Password in os.env")
        try:
            if os.environ['KMS_ENC'] is not None:
                environment_variables['NgfwPassword'] = get_decrypted_key(environment_variables['NgfwPassword'])
            else:
                logger.critical("Issue with KMS ARN in template")
                pass
        except Exception as e:
            logger.debug("Exception occurred {}".format(repr(e)))
            logger.debug("Looks like passwords may not be encrypted!")

        environment_variables['TargetGrpHealthPort'] = os.environ['TG_HEALTH_PORT']
        if re.match(r'^()([1-9]|[1-5]?[0-9]{2,4}|6[1-4][0-9]{3}|65[1-4][0-9]{2}|655[1-2][0-9]|6553[1-5])$',
                    environment_variables['TargetGrpHealthPort']) is None:
            raise ValueError("Unable to find Valid TCP port for health probe in os.env")

    except ValueError as e:
        logger.error("Error occurred: {}".format(repr(e)))
        logger.info("Check if Lambda function variables are valid!")
        exit(1)
    except KeyError as e:
        logger.error("Error occurred: {}".format(repr(e)))
        logger.info("Please check If all Lambda function variables exist in variable section!")
        exit(1)
    except Exception as e:
        logger.critical("Unhandled error occurred: {}".format(repr(e)))
    else:

        with open(const.JSON_LOCAL_FILENAME) as json_file:
            data = json.load(json_file)
            logger.debug("User provided JSON Configuration: " + json.dumps(data, separators=(',', ':')))
            # Required JSON entries
            try:
                json_variables['NGFWvNamePrefix'] = data['vmNamePrefix']
                if re.match(r'^[a-zA-Z0-9-]+$', json_variables['NGFWvNamePrefix']) is None:
                    raise ValueError("Unable to find valid VM name Prefix name in JSON, Should Match: ^[a-zA-Z0-9-]+$ ")

                json_variables['AccessPolicyName'] = data['fmcAccessPolicyName']
                if re.match(r'..*', json_variables['AccessPolicyName']) is None:
                    raise ValueError("Unable to find valid Access Policy name in JSON")

                json_variables['DeviceGroupName'] = data['fmcDeviceGroupName']
                if re.match(r'..*', json_variables['DeviceGroupName']) is None:
                    raise ValueError("Unable to find valid Device Group Name")

                json_variables['InterfaceConfig'] = data['interfaceConfig']
                for fmcObject in json_variables['InterfaceConfig']:
                    managementOnly = fmcObject['managementOnly']
                    MTU = fmcObject['MTU']
                    mode = fmcObject['mode']
                    ifname = fmcObject['ifname']
                    securityZoneName = fmcObject['securityZone']['name']
                    name = fmcObject['name']

            except KeyError as e:
                logger.error("Error occurred while checking JSON file: {}".format(repr(e)))
                exit(1)
            except ValueError as e:
                logger.error("Error occurred while retrieving info from JSON file: {}".format(repr(e)))
                exit(1)

            for key in data:
                if key == 'DefaultPassword' and data['DefaultPassword']['password'] != '':
                    json_variables['NgfwDefaultPassword'] = data['DefaultPassword']['password']
                if key == 'licenseCaps' and data['licenseCaps'] != '':
                    json_variables['LicenseCaps'] = data['licenseCaps']
                if key == 'ngfwSSHport' and data['ngfwSSHport'] != '':
                    json_variables['NgfwSshPort'] = data['ngfwSSHport']
                if key == 'fmcIpforDeviceReg' and data['fmcIpforDeviceReg'] != '':
                    json_variables['DeviceRegFmcIp'] = data['fmcIpforDeviceReg']
                if key == 'RegistrationId' and data['RegistrationId'] != '':
                    json_variables['RegistrationId'] = data['RegistrationId']
                if key == 'NatId' and data['NatId'] != '':
                    json_variables['NatId'] = data['NatId']
                if key == 'fmcInsideNic' and data['fmcInsideNic'] != '':
                    json_variables['InsideNic'] = data['fmcInsideNic']
                if key == 'fmcOutsideNic' and data['fmcOutsideNic'] != '':
                    json_variables['OutsideNic'] = data['fmcOutsideNic']
                if key == 'fmcInsideZone' and data['fmcInsideZone'] != '':
                    json_variables['InsideZone'] = data['fmcInsideZone']
                if key == 'fmcOutsideZone' and data['fmcOutsideZone'] != '':
                    json_variables['OutsideZone'] = data['fmcOutsideZone']
                if key == 'fmcInsideNicName' and data['fmcInsideNicName'] != '':
                    json_variables['InsideNicName'] = data['fmcInsideNicName']
                if key == 'fmcOutsideNicName' and data['fmcOutsideNicName'] != '':
                    json_variables['OutsideNicName'] = data['fmcOutsideNicName']
                if key == 'MetadataServerObjectName' and data['MetadataServerObjectName'] != '':
                    json_variables['MetadataServerObjectName'] = data['MetadataServerObjectName']
                if key == 'trafficRoutes' and data['trafficRoutes'] != '':
                    for item in data['trafficRoutes']:
                        json_variables['TrafficRoutes'].append(item)

    return environment_variables, json_variables


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


def setup_logging(debug_disabled):
    """
    Purpose:    Sets up logging behavior for the Autoscale Manager
    Parameters: User input to disable debug logs
    Returns:    logger object
    Raises:
    """
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.INFO)
    logger = logging.getLogger()
    for h in logger.handlers:
        logger.removeHandler(h)
    h = logging.StreamHandler(sys.stdout)
    log_format = '%(levelname)s [%(asctime)s] (%(funcName)s)# %(message)s'
    h.setFormatter(logging.Formatter(log_format))
    logger.addHandler(h)
    logger.setLevel(logging.DEBUG)
    if debug_disabled:
        logging.disable(logging.DEBUG)
    return logger


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


def put_line_in_log(var, line_type='dot'):
    """
    Purpose:    This is to help putting lines in logs
    Parameters:
    Returns:
    Raises:
    """
    if line_type == 'thick':
        logger.info("======================================== < " + var + " > ========================================")
    if line_type == 'thin':
        logger.info("---------------------------------------- < " + var + " > ----------------------------------------")
    if line_type == 'dot':
        logger.info("........................................ < " + var + " > ........................................")
    return


# Setup Logging
debug_disable = False
try:
    if os.environ['DEBUG_DISABLED'] is not None:
        if os.environ['DEBUG_DISABLED'].lower() == 'true':
            debug_disable = True
except (KeyError, Exception) as e:
    logging.debug("Error occurred: {}".format(repr(e)))
logger = setup_logging(debug_disable)
# Get Variables
e_var, j_var = get_variables()
