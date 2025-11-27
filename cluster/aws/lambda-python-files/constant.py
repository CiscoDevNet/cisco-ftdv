"""
Copyright (c) 2023 Cisco Systems Inc or its affiliates.

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

Name:       constant.py
Purpose:    This is python file for Constant variables
            It will be called in all NGFWv Cluster Lambda functions
"""

# Encoding constant for password decryption function
ENCODING = "utf-8"

# NIC Configuration method, DHCP/STATIC
# NIC_CONFIGURE = "STATIC"
NIC_CONFIGURE = "DHCP"

# Lifecycle hook constants
# ------------------------------------------------------------------------------
ENI_NAME_PREFIX = "-data-interface-"
SUBNET_ID_LIST_PREFIX = "SUBNET_ID_LIST_"
SECURITY_GROUP_PREFIX = 'SECURITY_GRP_'
ENI_NAME_OF_DIAG_INTERFACE = "-diag-interface-"

ENI_NAME_OF_INTERFACE_2 = "-data-interface-2"
ENI_NAME_OF_INTERFACE_3 = "-data-interface-3"

FTDV_SSH_PORT = 22

DEFAULT_PASSWORD = "FtDv_ClU3TeR44"
USE_PUBLIC_IP_FOR_SSH = False
USE_PUBLIC_IP_FOR_FMC_CONN = True


# LifeCycleLambda Constants
# ------------------------------------------------------------------------------
# Disables or Enables execution of  business logic in LifeCycle Lambda
DISABLE_LIFECYCLE_LAMBDA = False
DISABLE_CREATE_ATTACH_INT = False
DISABLE_REGISTER_TARGET = False


# Cluster Manager Constants
# ------------------------------------------------------------------------------
# Disables or Enables execution of  business logic in ConfigureASAv Lambda
DISABLE_CLUSTER_MANAGER_LAMBDA = False

DECREMENT_CAP_IF_CLUSTER_DELETED = True
FTD_POLL_TIME_IN_MIN_CLUSTER_READY = 10

DISABLE_CLUSTER_READY_FUNC = False
DISABLE_CLUSTER_REGISTER_FUNC = True # This will be enabled by the lambda function for Master Node.
DISABLE_CLUSTER_STATUS_FUNC = False
DISABLE_CLUSTER_DELETE_FUNC = False

CONTROL_NODE = ""
DATA_NODE = ""

TO_FUN_RETRY_COUNT = [3, 5, 5, 3]
REG_TASK_ID = ""
# Configuration File Name
JSON_LOCAL_FILENAME = 'Configuration.json'

# Custom Metric Publisher Constants
# ------------------------------------------------------------------------------
DISABLE_CUSTOM_METRIC_PUBLISH_LAMBDA = False
DELETE_JUNK_NODES_FROM_FMC = True # Set to False if you don't want Lambda to delete nodes from FMC even after they are deleted from AWS.

# Below values are used in CloudFormation Stack..
# Also do change it on AWS resources or CloudFormation
METRIC_NAME_SPACE = 'Cisco-NGFWv-Cluster-Group'
NO_DEV_IN_FMC_NOT_IN_AWS = 'DevicesOnlyInFmc'
NO_DEV_IN_AWS_NOT_IN_FMC = 'DevicesOnlyInAws'
NO_DEV_IN_BOTH_FMC_AWS = 'DevicesInBothFmcAndAws'
DEVICE_NO_UNIT = 'Count'
FMC_METRICS = ['memory']
MEMORY_UNIT = 'Percent'
GROUP_AVG_MEMORY = 'GroupAvgMem'
GROUP_MAX_MEMORY = 'GroupMaxMem'
GROUP_MIN_MEMORY = 'GroupMinMem'
