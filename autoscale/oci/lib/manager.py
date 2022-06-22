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

Name:       manager.py
Purpose:    This is the main Lambda handler file( autoscale_manager ).
            Takes AWS Lambda triggers & routes the request to appropriate function module.
Input:      A sample SNS test Event
            {
                "Records": [
                    {
                        "EventSource": "aws:sns",
                        "Sns": {
                            "Message": "{\"Description\": \"Check VM is ready\", \"category\":\"FIRST\",\"counter\":\"3\",\"instance_id\":\"i-0a252104d2913eede\",\"to_function\":\"vm_ready\"}"
                        }
                    }
                ]
            }
"""

import json
import time
import logging
from datetime import datetime, timezone

import utility as utl
from ngfw import ManagedDevice
from fmc import DerivedFMC

logging.basicConfig(force=True, level="INFO")
logging.getLogger("paramiko").setLevel(logging.WARNING)
logger = logging.getLogger()

def fmc_cls_init(e_var, j_var, token):
    """
    Purpose:    To instantiate DerivedFMC class
    Parameters:
    Returns:    Object
    Raises:
    """
    try: 
        # FMC class initialization
        fmc = DerivedFMC(e_var["fmc_ip"], e_var["fmc_username"], e_var["fmc_password"], j_var['fmcAccessPolicyName'])
        # Gets Auth token & updates self.reachable variable
        fmc.compartmentId = e_var["compartment_id"]
        fmc.appName = e_var["autoscale_group_prefix"]+"_application"
        fmc.tokenEndpoint = e_var['token_endpoint_url']
        fmc.reach_fmc_with_manual_token(token)
        
        if fmc.reachable == 'AVAILABLE':
            l_seczone_name = [j_var['fmcInsideZone'], j_var['fmcOutsideZone']]
            l_network_obj_name = ["any-ipv4"]
            l_host_obj_name = [j_var['MetadataServerObjectName']]
            # Updates DerivedFMC object with appropriate user provided names
            fmc.update_fmc_config_user_input(e_var["fmc_device_group_name"], j_var['fmcAccessPolicyName'], j_var['fmcNatPolicyName'], l_seczone_name, l_network_obj_name, l_host_obj_name)
            # Updates DerivedFMC object with appropriate ids from FMC
            fmc.set_fmc_configuration()
        return fmc
    except Exception as e: 
        raise Exception("FMC: Exception"+repr(e))
    

def ftd_cls_init(compartment_id, instance_id, e_var, j_var, fmc):
    """
    Purpose:    To instantiate ManagedDevice class
    Parameters: instance id, DerivedFMC object
    Returns:    ManagedDevice Object
    Raises:
    """
    # Managed FTD class initialization
    ftd = ManagedDevice(compartment_id, instance_id, fmc)
    ftd.begin_time = int(e_var["begin_time"])
    ftd.public_ip, ftd.private_ip = ftd.get_management_public_private_ip()
    
    ftd.port = 22
    ftd.username = e_var["ftdv_username"]
    ftd.password = e_var["ftdv_password"]
    ftd.defaultPassword = 'FtDv_AuT0Scale'
    ftd.fmc_ip = j_var['fmcIpforDeviceReg']
    ftd.reg_id = j_var['RegistrationId']
    ftd.nat_id = j_var['NatId']
    ftd.vm_name = e_var["autoscale_group_prefix"] +"_"+ str(instance_id[-12:])
    
    ftd.USE_PUBLIC_IP_FOR_SSH = e_var["use_public_ip_for_ssh"]
    ftd.USE_PUBLIC_IP_FOR_FMC_CONN = e_var["use_ftdv_public_ip_to_connect_fmc"]

    ftd.l_caps = j_var['licenseCaps']
    ftd.performance_tier = j_var['performanceTier']
    ftd.traffic_routes = j_var['trafficRoutes']
    ftd.interface_config = j_var['interfaceConfig']
    ftd.in_nic = j_var['fmcInsideNic']
    ftd.out_nic = j_var['fmcOutsideNic']
    ftd.in_nic_name = j_var['fmcInsideNicName']
    ftd.out_nic_name = j_var['fmcOutsideNicName']

    # Updating device configuration
    ftd.update_device_configuration()

    return ftd

def execute_vm_ready_first(ftd, poll_time):
    """
    Purpose:    This polls NGFW instance for it's SSH accessibility
    Parameters: ManagedDevice object
    Returns:    SUCCESS, FAIL
    Raises:
    """
    poll_ftdv_response = ftd.poll_ftdv_ssh(poll_time)
    if poll_ftdv_response == "SUCCESS":
        request_response = ftd.configure_hostname()
        if request_response != 'COMMAND_RAN':
            ftd.configure_hostname()
        return 'SUCCESS'
    return 'FAIL'

def execute_vm_register_first(ftd):
    """
    Purpose:    This registers the device to FMC
    Parameters: ManagedDevice object
    Returns:    SUCCESS, FAIL
    Raises:
    """
    try:
        # device_grp_id = fmc.get_device_grp_id_by_name(e_var['fmcDeviceGroupName'])
        # if device_grp_id is None:
        #     raise ValueError("Unable to find Device Group in FMC: %s " % e_var['fmcDeviceGroupName'])
        # else:
        #     logger.debug("Device Group: %s " % device_grp_id)
        reg_status = ftd.check_ftdv_reg_status()  # Check Device Registration state
        if reg_status == "COMPLETED":
            logger.info("CONFIGURE FTDv: Device registration successful ")
            return 'SUCCESS'
        elif reg_status == "PENDING":
            logger.info("CONFIGURE FTDv: Device is in registration pending status ")
            task_status = ftd.send_registration_request()  # Can return FAIL or SUCCESS
            #time.sleep(1 * 60)  # Related to CSCvs17405
            if task_status == 'SUCCESS':
                return 'SUCCESS'
        elif reg_status == 'NO_MANAGER':
            logger.info("CONFIGURE FTDv: Device has no manager configured, sending: 'configure manager add'")
            request_response = ftd.configure_manager()
            if request_response == 'COMMAND_RAN':
                reg_status = ftd.check_ftdv_reg_status()
                if reg_status == 'PENDING':
                    logger.info("CONFIGURE FTDv: Device is in registration pending status ")
                    task_status = ftd.send_registration_request()  # Can return FAIL or SUCCESS
                    #time.sleep(1 * 60)  # Related to CSCvs17405
                    if task_status == 'SUCCESS':
                        return 'SUCCESS'
        elif reg_status == 'TROUBLESHOOT':
            logger.info("CONFIGURE FTDv: Device has manager configuration related problem, sending: 'configure manager delete'")
            request_response = ftd.configure_manager_delete()
            if request_response != 'COMMAND_RAN':
                ftd.configure_manager_delete()  # Next iteration should fix it!
    except ValueError as e:
        logger.error("CONFIGURE FTDv: Exception occurred in VM Register {}".format(repr(e)))
    except Exception as e:
        logger.error("CONFIGURE FTDv: Exception occurred in VM Register {}".format(repr(e)))
    return 'FAIL'

def execute_vm_configure_first(ftd):
    """
    Purpose:    This configures Interfaces & Static Routes on the NGFW instance
    Parameters: ManagedDevice object
    Returns:    SUCCESS, FAIL
    Raises:
    """
    if ftd.device_id == '':
        ftd.update_device_configuration()
    if ftd.device_id != '':
        try:
            nic_status = ftd.check_and_configure_interface()
            if nic_status != 'SUCCESS':
                raise ValueError("Interface configuration failed")
            routes_status = ftd.check_and_configure_routes()
            if routes_status != 'SUCCESS':
                raise ValueError("Route configuration failed")
            return 'SUCCESS'
        except ValueError as e:
            logger.error("Exception occurred {}".format(repr(e)))
        except Exception as e:
            logger.exception("CONFIGURE FTDv: "+repr(e))
    return 'FAIL'

def execute_vm_deploy_first(ftd, fmc):
    """
    Purpose:    This deploys policies on the device
    Parameters: ManagedDevice object, DerivedFMC Object
    Returns:    SUCCESS, FAIL
    Raises:
    """
    try:
        deploy_status = fmc.check_deploy_status(ftd.vm_name)
        if deploy_status != 'DEPLOYED':
            if fmc.start_deployment(ftd.vm_name) is None:
                raise ValueError("Configuration deployment REST post failing")
        deploy_status = ftd.ftdv_deploy_polling(5)
        if deploy_status != "SUCCESS":
            raise ValueError("Configuration deployment failed")
        logger.info("Configuration is deployed, health status in TG needs to be checked")
        return 'SUCCESS'
    except ValueError as e:
        logger.error("CONFIGURE FTDv: Exception occurred in VM deploy {}".format(repr(e)))
    except Exception as e:
        logger.exception(e)
    return 'FAIL'
