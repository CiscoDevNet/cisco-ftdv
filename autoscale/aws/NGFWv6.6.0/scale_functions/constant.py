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
"""
import os
import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# Debug logs
try:
    if os.environ['DEBUG_DISABLED'].lower() == 'true':
        DEBUG_DISABLED = True
    else:
        DEBUG_DISABLED = False
    if DEBUG_DISABLED:
        logging.disable(logging.DEBUG)  # If DebugLogEnabled is False, logging.disable(logging.DEBUG) is run
except Exception as e:
    logger.error("Env variable 'DEBUG_DISABLED' may not available")
    logger.debug(str(e))
    exit(0)

# Get Autoscale Group Name
try:
    ASG_NAME = os.environ['ASG_NAME']
except Exception as e:
    logger.error("Env variable 'ASG_NAME' isn't available")
    logger.debug(str(e))
    exit(0)

# Get Function Name
try:
    FUNC_NAME = os.environ['FUNC_NAME']
except Exception as e:
    logger.error("Env variable 'FUNC_NAME' isn't available")
    logger.debug(str(e))
    exit(0)
else:
    # Collect Environment variables for FUNC_NAME == 'CreateENI'
    if FUNC_NAME == 'CreateENI':

        DIAG_ENI_NAME = "-diag-eni"
        INSIDE_ENI_NAME = "-inside-eni"
        OUTSIDE_ENI_NAME = "-outside-eni"

        INSIDE_SUBNET_ID_LIST = []
        OUTSIDE_SUBNET_ID_LIST = []

        try:
            NO_OF_AZs = os.environ['NO_OF_AZs']
            logger.info("Number of availability zones: " + str(NO_OF_AZs))
            pass
        except Exception as e:
            logger.error("Env variable 'NO_OF_AZs' isn't available")
            logger.debug(str(e))
            exit(0)
        else:
            if int(NO_OF_AZs) == 1:
                try:
                    INSIDE_SUBNET_ID0 = os.environ['INSIDE_SUBNET0']
                    INSIDE_SUBNET_ID_LIST.append(INSIDE_SUBNET_ID0)
                except Exception as e:
                    logger.error("Env variable 'INSIDE_SUBNET0' isn't available")
                    logger.debug(str(e))
                    exit(0)
                try:
                    OUTSIDE_SUBNET_ID0 = os.environ['OUTSIDE_SUBNET0']
                    OUTSIDE_SUBNET_ID_LIST.append(OUTSIDE_SUBNET_ID0)
                except Exception as e:
                    logger.error("Env variable 'OUTSIDE_SUBNET0' isn't available")
                    logger.debug(str(e))
                    exit(0)
                logger.info("List of subnet came from User Input: ")
                logger.info(INSIDE_SUBNET_ID_LIST)
                logger.info(OUTSIDE_SUBNET_ID_LIST)
            elif int(NO_OF_AZs) == 2:
                try:
                    INSIDE_SUBNET_ID0 = os.environ['INSIDE_SUBNET0']
                    INSIDE_SUBNET_ID_LIST.append(INSIDE_SUBNET_ID0)
                except Exception as e:
                    logger.error("Env variable 'INSIDE_SUBNET0' isn't available")
                    logger.debug(str(e))
                    exit(0)
                try:
                    OUTSIDE_SUBNET_ID0 = os.environ['OUTSIDE_SUBNET0']
                    OUTSIDE_SUBNET_ID_LIST.append(OUTSIDE_SUBNET_ID0)
                except Exception as e:
                    logger.error("Env variable 'OUTSIDE_SUBNET0' isn't available")
                    logger.debug(str(e))
                    exit(0)
                try:
                    INSIDE_SUBNET_ID1 = os.environ['INSIDE_SUBNET1']
                    INSIDE_SUBNET_ID_LIST.append(INSIDE_SUBNET_ID1)
                except Exception as e:
                    logger.error("Env variable 'INSIDE_SUBNET1' isn't available")
                    logger.debug(str(e))
                    exit(0)
                try:
                    OUTSIDE_SUBNET_ID1 = os.environ['OUTSIDE_SUBNET1']
                    OUTSIDE_SUBNET_ID_LIST.append(OUTSIDE_SUBNET_ID1)
                except Exception as e:
                    logger.error("Env variable 'OUTSIDE_SUBNET1' isn't available")
                    logger.debug(str(e))
                    exit(0)
                logger.info("List of subnet came from User Input: ")
                logger.info(INSIDE_SUBNET_ID_LIST)
                logger.info(OUTSIDE_SUBNET_ID_LIST)
            elif int(NO_OF_AZs) == 3:
                try:
                    INSIDE_SUBNET_ID0 = os.environ['INSIDE_SUBNET0']
                    INSIDE_SUBNET_ID_LIST.append(INSIDE_SUBNET_ID0)
                except Exception as e:
                    logger.error("Env variable 'INSIDE_SUBNET0' isn't available")
                    logger.debug(str(e))
                    exit(0)
                try:
                    OUTSIDE_SUBNET_ID0 = os.environ['OUTSIDE_SUBNET0']
                    OUTSIDE_SUBNET_ID_LIST.append(OUTSIDE_SUBNET_ID0)
                except Exception as e:
                    logger.error("Env variable 'OUTSIDE_SUBNET0' isn't available")
                    logger.debug(str(e))
                    exit(0)
                try:
                    INSIDE_SUBNET_ID1 = os.environ['INSIDE_SUBNET1']
                    INSIDE_SUBNET_ID_LIST.append(INSIDE_SUBNET_ID1)
                except Exception as e:
                    logger.error("Env variable 'INSIDE_SUBNET1' isn't available")
                    logger.debug(str(e))
                    exit(0)
                try:
                    OUTSIDE_SUBNET_ID1 = os.environ['OUTSIDE_SUBNET1']
                    OUTSIDE_SUBNET_ID_LIST.append(OUTSIDE_SUBNET_ID1)
                except Exception as e:
                    logger.error("Env variable 'OUTSIDE_SUBNET1' isn't available")
                    logger.debug(str(e))
                    exit(0)
                try:
                    INSIDE_SUBNET_ID2 = os.environ['INSIDE_SUBNET2']
                    INSIDE_SUBNET_ID_LIST.append(INSIDE_SUBNET_ID2)
                except Exception as e:
                    logger.error("Env variable 'INSIDE_SUBNET2' isn't available")
                    logger.debug(str(e))
                    exit(0)
                try:
                    OUTSIDE_SUBNET_ID2 = os.environ['OUTSIDE_SUBNET2']
                    OUTSIDE_SUBNET_ID_LIST.append(OUTSIDE_SUBNET_ID2)
                except Exception as e:
                    logger.error("Env variable 'OUTSIDE_SUBNET2' isn't available")
                    logger.debug(str(e))
                    exit(0)
                logger.info("List of subnet came from User Input: ")
                logger.info(INSIDE_SUBNET_ID_LIST)
                logger.info(OUTSIDE_SUBNET_ID_LIST)
            else:
                logger.error("Un-supported number of Availability zones")
                exit(0)
    # Collect Environment variables for FUNC_NAME == 'CreateENI' or FUNC_NAME == 'DeregTarget'
    if FUNC_NAME == 'CreateENI' or FUNC_NAME == 'DeregTarget':
        # Get Load Balancer ARN
        try:
            LB_ARN_OUTSIDE = os.environ['LB_ARN_OUTSIDE']
        except Exception as e:
            logger.error("Env variable 'LB_ARN_OUTSIDE' isn't available")
            logger.debug(str(e))
            exit(0)

        # User Input De-registration delay - 10 seconds
        try:
            DEREGISTRATION_DELAY = int(os.environ['LB_DEREGISTRATION_DELAY']) - 10
        except Exception as e:
            logger.error("Env variable 'LB_DEREGISTRATION_DELAY' isn't available")
            logger.debug(str(e))
            exit(0)
