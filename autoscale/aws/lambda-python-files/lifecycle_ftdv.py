"""
Copyright (c) 2024 Cisco Systems Inc or its affiliates.

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
"""

import time
import os
from aws import *
import constant as const

logger = utl.setup_logging()
# Get User input
user_input = utl.get_user_input_lifecycle_ftdv()


# LifeCycle Hook Handler
def lambda_handler(event, context):
    """
    Purpose:    Life Cycle Lambda, to attach interfaces to FTDv
    Parameters: AWS Events (CloudWatch)
    Returns:
    Raises:
    """
    utl.put_line_in_log('LifeCycle Lambda Handler started', 'thick')
    logger.info("Received event: " + json.dumps(event, separators=(',', ':')))

    if const.DISABLE_LIFECYCLE_LAMBDA is True:
        logger.info("LifeCycleFTDvLambda running is disabled! Check constant.py")
        utl.put_line_in_log('LifeCycle Lambda Handler finished', 'thick')
        return

    life_cycle_action = 'FAIL'

    # EC2 Lifecycle Action
    try:
        instance_id = event['detail']['EC2InstanceId']
        # Initialize class CiscoEc2Instance
        ec2_instance = CiscoEc2Instance(instance_id)

        lifecycle_hookname = event['detail']['LifecycleHookName']
        autoscaling_group_name = event['detail']['AutoScalingGroupName']
        logger.info("Cloud Watch Event Triggered for group {}".format(autoscaling_group_name))
        if autoscaling_group_name != user_input['AutoScaleGrpName']:
            raise ValueError("AutoScale Group name from event & user input doesn't match!")
    except KeyError as e:
        logger.debug("Error occurred: {}".format(repr(e)))
        logger.info("Not an EC2 Lifecycle CloudWatch event!")
        pass
    except ValueError as e:
        logger.error("Error occurred: {}".format(repr(e)))
        pass
    else:
        if event["detail-type"] == "EC2 Instance-launch Lifecycle Action":
            if const.DISABLE_CREATE_ATTACH_INT is False:
                create_tags_with_default_values(ec2_instance)  # Create Default Tags on Instance
                ec2_instance.disable_src_dst_check_on_primary_int() # Modify src/dst check
                if create_interface_and_attach(ec2_instance) == 'SUCCESS':
                    if const.DISABLE_REGISTER_TARGET is False:
                        if register_instance(ec2_instance) == 'SUCCESS':
                            ec2_instance.lb.modify_target_groups_deregistration_delay(
                                user_input['LB_ARN'], user_input['LB_DEREGISTRATION_DELAY'])
                            life_cycle_action = 'SUCCESS'
                    else:
                        logger.info("register_instance function is disabled! Check constant.py")
            else:
                logger.info("create_interface_and_attach function is disabled! Check constant.py")

        elif event["detail-type"] == "EC2 Instance-terminate Lifecycle Action":
            state = ec2_instance.get_instance_state()
            if state != 'terminated' or state is not None:
                if deregister_instance(ec2_instance) == 'SUCCESS':
                    time.sleep(int(user_input['LB_DEREGISTRATION_DELAY']))
                    if user_input['PROXY_TYPE'] == 'DUAL_ARM':
                        if disassociate_and_release_eip(ec2_instance) != 'SUCCESS':
                            life_cycle_action = 'FAIL'
                    life_cycle_action = 'SUCCESS'
                else:
                    life_cycle_action = 'FAIL'
            else:
                logger.info("Instance is already Terminated or No valid State found")
                life_cycle_action = 'SUCCESS'

        else:
            logger.error("Not an EC2 Instance Lifecycle Action")

        if life_cycle_action == 'SUCCESS':
            ec2_instance.asg.complete_lifecycle_action_success(lifecycle_hookname, instance_id)
        else:
            ec2_instance.asg.complete_lifecycle_action_failure(lifecycle_hookname, instance_id)

    utl.put_line_in_log('LifeCycle Lambda Handler finished', 'thick')
    return


def create_interface_and_attach(ec2_instance):
    """
    Purpose:    This creates, attaches interfaces to FTDv
    Parameters: Instance Id
    Returns:    SUCCESS, FAIL
    Raises:
    """
    # Get Availability zone & Subnet
    instance_az = ec2_instance.get_instance_az()
    logger.info("EC2 instance has been launched in AZ: " + instance_az)
    subnets_list_in_az = ec2_instance.get_subnet_list_in_az(instance_az)
    logger.debug("List of subnets in %s is: %s" % (instance_az, subnets_list_in_az))

    # Get the security group ID of this instance
    sec_grp_id = ec2_instance.get_security_group_id()
    logger.info("Security group id found for instance management interface: " + sec_grp_id)

    # Create and Attach interfaces from respective subnet
    utl.put_line_in_log('Attaching Diagnostic and Data Interfaces', 'dot')

    # Attach Diag interface
    eni_name = ec2_instance.instance_id + const.ENI_NAME_OF_DIAG_INTERFACE + str(1)
    interface_id = ec2_instance.create_interface(ec2_instance.get_mgmt_subnet_id(), sec_grp_id, eni_name)
    if interface_id:
        # Attach interface to instance with device index
        attachment, err = ec2_instance.attach_interface(interface_id, 1)
        if not attachment:
            ec2_instance.delete_interface(interface_id)
            if len(re.findall('already has an interface attached at', str(err))) >= 1:
                logger.warn("Already has an attached network interface at device index: %s" % str(1))
                pass
            utl.put_line_in_log('Attaching Diagnostic Interface: FAILED', 'dot')
            return 'FAIL'
    else:
        utl.put_line_in_log('Attaching Diagnostic Interface: FAILED', 'dot')
        return 'FAIL'

    # Attach Data interfaces
    for dev_index in range(2, int(user_input['max_number_of_interfaces'])):
        eni_name = ec2_instance.instance_id + const.ENI_NAME_PREFIX + str(dev_index)
        # Get security group for respective data interface (inside / outside) 
        sec_grp_id = user_input[const.SECURITY_GROUP_PREFIX + str(dev_index)]
        subnet_id_list = const.SUBNET_ID_LIST_PREFIX + str(dev_index)
        # User should have given only one subnet id from this availability zone
        subnet_id = utl.get_common_member_in_list(subnets_list_in_az, user_input[subnet_id_list])
        if len(subnet_id) > 1:
            logger.error("For interface %s, more than one subnet found from an availability zone!" % eni_name)
            logger.error(subnet_id)
            return 'FAIL'
        elif len(subnet_id) < 1:
            logger.error("For interface %s, less than one subnet found from an availability zone!" % eni_name)
            logger.error(subnet_id)
            return 'FAIL'

        # Create interface in the subnet with its respective security group
        logger.info("sec_grp_id is: %s" % (sec_grp_id))
        interface_id = ec2_instance.create_interface(str(subnet_id[0]), sec_grp_id, eni_name)

        if interface_id:
            # Attach interface to instance with device index
            attachment, err = ec2_instance.attach_interface(interface_id, dev_index)
            if not attachment:
                ec2_instance.delete_interface(interface_id)
                if len(re.findall('already has an interface attached at', str(err))) >= 1:
                    logger.warn("Already has an attached network interface at device index: %s" % str(dev_index))
                    pass
                utl.put_line_in_log('Attaching Data Interface: FAILED', 'dot')
                return 'FAIL'
        else:
            utl.put_line_in_log('Attaching Data Interface: FAILED', 'dot')
            return 'FAIL'
    return 'SUCCESS'


def register_instance(ec2_instance):
    """
    Purpose:    To register Gig0/0 IP to Load Balancer's Target Group 
                [Gig0/1 IP for NLB case]
    Parameters: Object
    Returns:    SUCCESS, FAIL
    Raises:
    """

    ## If GENEVE_SUPPORT is enabled (GWLB case), register inside interface to Target Group
    ## Else (NLB case) register outside interface to Target Group
    interface_data = {
    'enable': ('inside', 2),
    'disable': ('outside', 3) 
    }
    interface_name, interface_index = interface_data.get(user_input['GENEVE_SUPPORT'], ('inside', 2))
    
    utl.put_line_in_log('Registering %s interface to Target Group' %interface_name, 'dot')
    eni_name = ec2_instance.instance_id + const.ENI_NAME_PREFIX + str(interface_index)
    if ec2_instance.register_instance_to_lb(user_input['LB_ARN'], eni_name) == 'FAIL':
        utl.put_line_in_log('Registering %s interface to Target Group: FAILED' %interface_name, 'dot')
        return 'FAIL'
    utl.put_line_in_log('Registering %s interface to Target Group: SUCCESS' %interface_name, 'dot')
    return 'SUCCESS'


def deregister_instance(ec2_instance):
    """
    Purpose:    To de-register Gig0/0 IP from Target Group 
                [Gig0/1 IP for NLB case]
    Parameters: Instance Id
    Returns:    SUCCESS, FAIL
    Raises:
    """

    ## If GENEVE_SUPPORT is enabled (GWLB case), deregister inside interface from Target Group
    ## Else (NLB case) deregister outside interface form Target Group
    interface_data = {
    'enable': ('inside', 2),
    'disable': ('outside', 3) 
    }
    interface_name, interface_index = interface_data.get(user_input['GENEVE_SUPPORT'], ('inside', 2))
    
    utl.put_line_in_log('De-registering FTDv %s interface from Target Group' %interface_name, 'dot')
    eni_name = ec2_instance.instance_id + const.ENI_NAME_PREFIX + str(interface_index)

    if ec2_instance.deregister_instance_from_lb(user_input['LB_ARN'], eni_name) == 'FAIL':
        utl.put_line_in_log('De-registering %s interface from Target Group finished: FAIL' %interface_name, 'dot')
        return 'FAIL'
    utl.put_line_in_log('De-registering %s interface from Target Group finished: SUCCESS' %interface_name, 'dot')
    return 'SUCCESS'


def disassociate_and_release_eip(ec2_instance):
    """
    Purpose:    [GWLB DUAL-ARM case] To disassociate and release EIP associated with Gig0/1 interface 
    Parameters: Object
    Returns:    SUCCESS, FAIL
    Raises:
    """
    utl.put_line_in_log('Disassociating and Releasing Elastic IP for outside interface', 'dot')
    if ec2_instance.disassociate_from_instance_and_release_eip() == 'FAIL':
        utl.put_line_in_log('Disassociating and Releasing Elastic IP for outside interface: FAIL', 'dot')
        return 'FAIL'
    utl.put_line_in_log('Disassociating and Releasing Elastic IP for outside interface: SUCCESS', 'dot')
    return 'SUCCESS'


def create_tags_with_default_values(ec2_instance):
    """
    Purpose:    To create tags on EC2 instance
    Parameters: EC2Instance object
    Returns:    SUCCESS
    Raises:
    """
    ec2_instance.create_instance_tags('NGFWvConfigDeployStatus', 'PENDING')
    ec2_instance.create_instance_tags('NGFWvConfigurationStatus', 'PENDING')
    ec2_instance.create_instance_tags('NGFWvRegistrationStatus', 'PENDING')
    ec2_instance.create_instance_tags('NGFWvConnectionStatus', 'UN-AVAILABLE')
    ec2_instance.create_instance_tags('NGFWvFMCDeviceGrp', user_input['fmcDeviceGroupName'])

    if user_input['FTD_LICENSE_TYPE'] == 'PAYG':
        ec2_instance.create_instance_tags('NGFWvLicenseType', 'PAYG')
    elif user_input['FTD_LICENSE_TYPE'] == 'BYOL':
        ec2_instance.create_instance_tags('NGFWvLicenseType', 'BYOL')
    else:
        ec2_instance.create_instance_tags('NGFWvLicenseType', 'IN-VALID')
    return 'SUCCESS'
