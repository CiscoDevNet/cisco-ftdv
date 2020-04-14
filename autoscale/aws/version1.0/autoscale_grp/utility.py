"""
Name:       utility.py
Purpose:    This is contains utility functions
            All non-class methods are available here
            This gets called in all project files except constant.py
"""
import os
import sys
import logging
import json


def setup_logging(debug_disabled):
    """
    Purpose:    Sets up logging behavior for the Autoscale Manager
    Parameters: User input to disable debug logs
    Returns:    logger object
    Raises:
    """
    logging.getLogger("botocore").setLevel(logging.INFO)
    logger = logging.getLogger()
    for h in logger.handlers:
        logger.removeHandler(h)
    h = logging.StreamHandler(sys.stdout)
    FORMAT = '%(levelname)s [%(asctime)s] (%(funcName)s)# %(message)s'
    h.setFormatter(logging.Formatter(FORMAT))
    logger.addHandler(h)
    logger.setLevel(logging.DEBUG)
    if debug_disabled:
        logging.disable(logging.DEBUG)
    return logger


def get_common_member_in_list(list1, list2):
    """
    Purpose:
    Parameters:
    Returns:
    Raises:
    """
    list1_set = set(list1)
    list2_set = set(list2)
    common_set = list1_set.intersection(list2_set)
    logger.info("Common subnet(If more than one subnet found then it's user input error) is: ")
    logger.info(common_set)
    if len(common_set) == 1:
        return list(common_set)
    elif len(common_set) > 1:
        logger.error("More than one subnets from same Availability Zones")
        return []
    else:
        logger.error("No subnets from given Availability Zones")
        return []


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


user_input = {
    "DEBUG_DISABLED": False,
    "ASG_NAME": "",
    "NO_OF_AZs": "",
    "INSIDE_SUBNET_ID_LIST": [],
    "OUTSIDE_SUBNET_ID_LIST": [],
    "DEREGISTRATION_DELAY": ""
}

try:
    if os.environ['DEBUG_DISABLED'] is not None:
        if os.environ['DEBUG_DISABLED'].lower() == 'true':
            user_input['DEBUG_DISABLED'] = True
except (KeyError, Exception) as e:
    pass
finally:
    logger = setup_logging(user_input['DEBUG_DISABLED'])

logger.info("=================================< Constant.py  started >=================================")


# Get Autoscale Group Name
try:
    user_input['ASG_NAME'] = os.environ['ASG_NAME']
except Exception as e:
    logger.error("Env variable 'ASG_NAME' isn't available")
    logger.debug(str(e))
    exit(0)
else:

    try:
        user_input['NO_OF_AZs'] = os.environ['NO_OF_AZs']
        logger.info("Number of availability zones: " + user_input['NO_OF_AZs'])
    except Exception as e:
        logger.error("Env variable 'NO_OF_AZs' isn't available")
        logger.debug(str(e))
        exit(0)
    else:
        if int(user_input['NO_OF_AZs']) > 3:
            logger.info("Un-supported number of AZs!")
            exit(1)
        try:
            for i in range(int(user_input['NO_OF_AZs'])):
                in_subnet_id_var = 'INSIDE_SUBNET' + str(i)
                user_input['INSIDE_SUBNET_ID_LIST'].append(os.environ[in_subnet_id_var])
                out_subnet_id_var = 'OUTSIDE_SUBNET' + str(i)
                user_input['OUTSIDE_SUBNET_ID_LIST'].append(os.environ[out_subnet_id_var])
        except KeyError as e:
            logger.error("Error occurred: {}".format(repr(e)))
            logger.error("Unable to get Subnet ID from os.env")
            exit(1)
        except Exception as e:
            logger.critical("Error occurred: {}".format(repr(e)))
            logger.critical("Unhandled error occurred!")

    # Get Load Balancer ARN
    try:
        user_input['LB_ARN_OUTSIDE'] = os.environ['LB_ARN_OUTSIDE']
    except Exception as e:
        logger.error("Error occurred: {}".format(repr(e)))
        logger.error("Env variable 'LB_ARN_OUTSIDE' isn't available")
        exit(0)

    # User Input De-registration delay - 10 seconds
    try:
        user_input['DEREGISTRATION_DELAY'] = int(os.environ['LB_DEREGISTRATION_DELAY']) - 10
    except Exception as e:
        logger.error("Error occurred: {}".format(repr(e)))
        logger.error("Env variable 'LB_DEREGISTRATION_DELAY' isn't available")
        exit(0)

logger.info("OS Environment variables: " + json.dumps(user_input, separators=(',', ':')))
logger.info("=================================< Constant.py finished >=================================")
