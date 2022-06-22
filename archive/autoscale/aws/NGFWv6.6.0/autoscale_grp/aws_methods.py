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

Name:       aws_methods.py
Purpose:    This is contains aws resources related methods
"""

import boto3
import botocore
import re
from utility import *
from botocore.exceptions import ClientError
import constant as const


class ASG:
    def __init__(self):
        self.asg_client = boto3.client('autoscaling')

    def remove_instance_asg(self, instance_id, decrement_cap=False):
        """
        Purpose:    To remove instance from AutoScale Group
        Parameters: Instance id, DecrementCapacity
        Returns:    Boto3 response
        Raises:
        """
        try:
            response = self.asg_client.terminate_instance_in_auto_scaling_group(
                InstanceId=instance_id,
                ShouldDecrementDesiredCapacity=decrement_cap
            )
        except botocore.exceptions.ClientError as e:
            logger.error("Botocore Error removing the instance: {}".format(e.response['Error']))
            return None
        except Exception as e:
            logger.error("General Error removing the instance" + str(e))
            return None
        return response

    def complete_lifecycle_action_success(self, hookname, groupname, instance_id):
        """
        Purpose:    This will complete lifecycle hook, SUCCESS case
        Parameters: Hookname, Group Name, Instance Id
        Returns:
        Raises:
        """
        try:
            self.asg_client.complete_lifecycle_action(
                    LifecycleHookName=hookname,
                    AutoScalingGroupName=groupname,
                    InstanceId=instance_id,
                    LifecycleActionResult='CONTINUE'
            )
            logger.info("Lifecycle hook CONTINUEd for: {}".format(instance_id))
        except botocore.exceptions.ClientError as e:
            logger.error("Error completing life cycle hook for instance {}: {}".format(instance_id, e.response['Error']))
            if re.findall('No active Lifecycle Action found', str(e)):
                logger.info("Lifecycle hook has already been CONTINUEd")

    def complete_lifecycle_action_failure(self, hookname, groupname, instance_id):
        """
        Purpose:    This will complete lifecycle hook, FAIL case
        Parameters: Hookname, Group Name, Instance Id
        Returns:
        Raises:
        """
        try:
            self.asg_client.complete_lifecycle_action(
                    LifecycleHookName=hookname,
                    AutoScalingGroupName=groupname,
                    InstanceId=instance_id,
                    LifecycleActionResult='ABANDON'
            )
            logger.info("Lifecycle hook ABANDONed for: {}".format(instance_id))
        except botocore.exceptions.ClientError as e:
            logger.error("Error completing life cycle hook for instance {}: {}".format(instance_id, e.response['Error']))
            if re.findall('No active Lifecycle Action found', str(e)):
                logger.info("Lifecycle hook has already been CONTINUEd")


class EC2:
    def __init__(self):
        self.ec2_client = boto3.client('ec2')
        self.ec2_elb_client = boto3.client('elbv2')

    def get_mgmt_subnet_id(self, instance_id):
        """
        Purpose:    To get mgmt Subnet Id
        Parameters: Instance Id
        Returns:    Subnet Id
        Raises:
        """
        try:
            result = self.ec2_client.describe_instances(InstanceIds=[instance_id])
            vpc_subnet_id = result['Reservations'][0]['Instances'][0]['SubnetId']
            logger.info("Mgmt Subnet id: {}".format(vpc_subnet_id))

        except botocore.exceptions.ClientError as e:
            logger.error("Error describing the instance {}: {}".format(instance_id, e.response['Error']))
            vpc_subnet_id = None
        return vpc_subnet_id

    def create_interface(self, subnet_id, sec_grp_id, eni_name):
        """
        Purpose:    To create interface in a specified subnet id
        Parameters: Subnet Id, Security Group, ENI name
        Returns:    Interface Id
        Raises:
        """
        network_interface_id = None
        if subnet_id:
            try:
                network_interface = self.ec2_client.create_network_interface(SubnetId=subnet_id, Groups=[sec_grp_id])
                network_interface_id = network_interface['NetworkInterface']['NetworkInterfaceId']
                logger.info("Created network interface: {}".format(network_interface_id))

                self.ec2_client.create_tags(Resources=[network_interface_id], Tags=[{'Key': 'Name', 'Value': eni_name}])
                logger.info("Added tag {} to network interface".format(eni_name))
            except botocore.exceptions.ClientError as e:
                logger.error("Error creating network interface: {}".format(e.response['Error']))
        return network_interface_id

    def attach_interface(self, network_interface_id, instance_id, device_index):
        """
        Purpose:    To attach interface to device
        Parameters: Network interface id, Instance id, Device index
        Returns:    Attachment
        Raises:
        """
        attachment = None
        if network_interface_id and instance_id:
            try:
                attach_interface = self.ec2_client.attach_network_interface(
                    NetworkInterfaceId=network_interface_id,
                    InstanceId=instance_id,
                    DeviceIndex=device_index
                )
                attachment = attach_interface['AttachmentId']
                logger.info("Created network attachment: {}".format(attachment))
                try:
                    modify_attachment = self.ec2_client.modify_network_interface_attribute(
                        Attachment={
                            'AttachmentId': attachment,
                            'DeleteOnTermination': True
                        },
                        # Description={
                        # 	'Value': 'string'
                        # },
                        # DryRun=True|False,
                        # Groups=[
                        # 	'string',
                        # ],
                        NetworkInterfaceId=network_interface_id,
                        # SourceDestCheck={
                        # 	'Value': True|False
                        # }
                    )
                except botocore.exceptions.ClientError as e:
                    logger.error("Error modifying network interface: {}".format(e.response['Error']))
                    return attachment, e.response['Error']
            except botocore.exceptions.ClientError as e:
                logger.error("Error attaching network interface: {}".format(e.response['Error']))
                return attachment, e.response['Error']
        return attachment, ''

    def delete_interface(self, network_interface_id):
        """
        Purpose:    To delete interface
        Parameters: Interface Id
        Returns:
        Raises:
        """
        try:
            self.ec2_client.delete_network_interface(
                NetworkInterfaceId=network_interface_id
            )
            logger.info("Deleted network interface: {}".format(network_interface_id))
            return True
        except botocore.exceptions.ClientError as e:
            logger.error("Error deleting interface {}: {}".format(network_interface_id, e.response['Error']))

    def get_security_group_id(self, instance_id):
        """
        Purpose:    To get Security group Id
        Parameters: Instance Id
        Returns:
        Raises:
        """
        try:
            result = self.ec2_client.describe_instances(InstanceIds=[instance_id])
            sec_grp_id = result['Reservations'][0]['Instances'][0]['SecurityGroups'][0]['GroupId']
            logger.info("Security Group id: {}".format(sec_grp_id))
        except botocore.exceptions.ClientError as e:
            logger.error("Error describing the instance {}: {}".format(instance_id, e.response['Error']))
            sec_grp_id = None
        return sec_grp_id

    def register_target_outside(self, instance_id, tgARN, port):
        """
        Purpose:    To register target to TG
        Parameters: Instance Id, TG ARN, Port
        Returns:    Target
        Raises:
        """
        target = None
        if instance_id and tgARN:
            try:
                # Getting outside interface ip
                outside_eni_name = instance_id + const.OUTSIDE_ENI_NAME
                result = self.ec2_client.describe_network_interfaces(Filters=[{'Name': 'tag:Name', 'Values': [outside_eni_name]}])
                outside_ip = result['NetworkInterfaces'][0]['PrivateIpAddress']
                logger.info("Outside Interface IP : {}".format(outside_ip))
                logger.info("Target Group Name {}".format(tgARN))
                # Adding ip to TG
                target = self.ec2_elb_client.register_targets(TargetGroupArn=tgARN, Targets=[{'Id': outside_ip, 'Port': port}])
                target_attribute_response = self.modify_target_group(tgARN)
            except botocore.exceptions.ClientError as e:
                logger.error("Error registering the target: {}".format(e.response['Error']))
        return target

    def deregister_target_instance_outside(self, instance_id, tgARN, port):
        """
        Purpose:    To de-register instance target from TG
        Parameters: Instance Id, TG ARN, Port
        Returns:    Target
        Raises:
        """
        target = None
        if instance_id and tgARN:
            try:
                # Getting outside interface ip
                outside_eni_name = instance_id + const.OUTSIDE_ENI_NAME
                result = self.ec2_client.describe_network_interfaces(Filters=[{'Name': 'tag:Name', 'Values': [outside_eni_name]}])
                try:
                    outside_ip = result['NetworkInterfaces'][0]['PrivateIpAddress']
                except Exception as e:
                    logger.error("Unable to get outside private IP describe_network_interfaces")
                    logger.debug(str(e))

                    return target
                logger.info("Outside Interface IP : {}".format(outside_ip))
                # Removing ip from TG
                target = self.deregister_target_ip_outside(outside_ip, tgARN, port)
            except botocore.exceptions.ClientError as e:
                logger.error("Error de-registering the target: {}".format(e.response['Error']))
        return target

    def deregister_target_ip_outside(self, ip, tgARN, port):
        """
        Purpose:    To de-register ip target from TG
        Parameters: Ip, TG ARN, Port
        Returns:    Target
        Raises:
        """
        target = None
        if ip and tgARN:
            try:
                logger.info("Removing IP : {}".format(ip))
                logger.info("Target Group Name {}".format(tgARN))
                # Removing ip from TG
                target = self.ec2_elb_client.deregister_targets(TargetGroupArn=tgARN, Targets=[{'Id': ip, 'Port': port}])
            except botocore.exceptions.ClientError as e:
                logger.error("Error de-registering the target: {}".format(e.response['Error']))
        return target

    def modify_target_group(self, tgARN):
        """
        Purpose:    To Modify deregistration_delay.timeout_seconds field in TG
        Parameters: TG ARN
        Returns:    Response
        Raises:
        """
        if tgARN:
            try:
                response = self.ec2_elb_client.modify_target_group_attributes(
                    TargetGroupArn=tgARN,
                    Attributes=[
                        {
                            'Key': 'deregistration_delay.timeout_seconds',
                            'Value': str(user_input['DEREGISTRATION_DELAY']),
                        },
                    ]
                )
            except botocore.exceptions.ClientError as e:
                logger.error("Error modifying target group attributes: {}".format(e.response['Error']))
                return None
            else:
                return response
        return None

    def get_tgARN_port_from_lb(self, lbARN):
        """
        Purpose:    To get TGs' ARNs and Ports associated to them in give LB
        Parameters: LB ARN
        Returns:    TG's ARN list, Ports list
        Raises:
        """
        tgARN = []
        ports = []
        if lbARN:
            try:
                response = self.ec2_elb_client.describe_target_groups(
                    LoadBalancerArn=lbARN,
                )
            except botocore.exceptions.ClientError as e:
                logger.error("Error describing target group attributes: {}".format(e.response['Error']))
                return None
            else:
                list_len = len(response['TargetGroups'])
                for i in range(0, list_len):
                    tgARN.append(response['TargetGroups'][i]['TargetGroupArn'])
                    ports.append(response['TargetGroups'][i]['Port'])
                return tgARN, ports
        return None

    def get_describe_instance(self, instance_id):
        """
        Purpose:    To get EC2 Describe Instance output
        Parameters: Instance Id
        Returns: Response
        Raises:
        """
        try:
            response = self.ec2_client.describe_instances(
                InstanceIds=[
                    instance_id,
                ]
            )
        except ClientError as e:
            logger.info("Unable find describe-instances for instance: " + instance_id)
            logger.debug(str(e))
            return None
        else:
            return response

    def get_describe_instance_private_ip(self, private_ip):
        """
        Purpose:    To get EC2 instance details from a private Ip
        Parameters: Private Ip
        Returns:    Describe Instance response
        Raises:
        """
        response = None
        try:
            response = self.ec2_client.describe_instances(
                Filters=[{'Name': 'network-interface.addresses.private-ip-address', 'Values': [private_ip]}]
            )
        except ClientError as e:
            logger.info("Unable find describe-instances for ip: " + private_ip)
            logger.debug(str(e))
            return None
        else:
            return response

    def get_instance_az(self, instance_id):
        """
        Purpose:    To get AZ of an EC2 Instance
        Parameters: Instance Id
        Returns:    AZ
        Raises:
        """
        r = self.get_describe_instance(instance_id)
        if r is not None:
            availability_zone = r['Reservations'][0]['Instances'][0]['Placement']['AvailabilityZone']
            return availability_zone
        else:
            return None

    def get_describe_subnet(self, instance_az):
        """
        Purpose:    To get Describe Subnet result in a given Availability zone
        Parameters: Availability Zone
        Returns:    Describe Subnet Response
        Raises:
        """
        try:
            response = self.ec2_client.describe_subnets(
                Filters=[
                    {
                        'Name': 'availability-zone',
                        'Values': [
                            instance_az,
                        ]
                    },
                ]
            )
        except ClientError as e:
            logger.info("Unable find describe-instances for subnet with filter AZ: " + instance_az)
            logger.debug(str(e))
            return None
        else:
            return response

    def get_subnet_list_in_az(self, instance_az):
        """
        Purpose:    To get list of subnets in given AZ
        Parameters: AZ
        Returns:    List of subnets
        Raises:
        """
        subnet_list = []
        r = self.get_describe_subnet(instance_az)
        if r is not None:
            for item in r['Subnets']:
                subnet_list.append(item['SubnetId'])
            return subnet_list
        else:
            return subnet_list

    def get_instance_state(self, instance_id):
        """
        Purpose:    To get EC2 instance state
        Parameters: Instance Id
        Returns:    State
        Raises:
        """
        response = self.get_describe_instance(instance_id)
        try:
            state = response['Reservations'][0]['Instances'][0]['State']['Name']
            if state != 'running':
                logger.info("Instance %s is %s " % instance_id % str(state))
                # fixme: we can try giving the reason for the instance state
                return state
            else:
                return state
        except Exception as e:
            logger.error("Unable to get state of %s " % instance_id)
            logger.error(str(e))
            return None

    def get_target_health(self, tg_arn):
        """
        Purpose:    To get targets' health from a TG
        Parameters: TG ARN
        Returns:    Response with Targets Health
        Raises:
        """
        response = self.ec2_elb_client.describe_target_health(
            TargetGroupArn=tg_arn,
        )

        return response


def set_alarm_state(alarm_name, state='INSUFFICIENT_DATA'):
    """
    Purpose:    To set alarm state
    Parameters: Alarm Name, state of alarm to be set
    Returns:    Response
    Raises:
    """
    logger.info("Setting alarm %s state to %s " % (alarm_name, state))

    client = boto3.client('cloudwatch')
    response = client.set_alarm_state(
        AlarmName=alarm_name,
        StateValue=state,
        StateReason='Setting state from Lambda',
    )
    return response
