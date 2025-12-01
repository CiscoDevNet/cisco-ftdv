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

Name:       aws.py
Purpose:    This python file has AWS related class & methods
            These classes will be initialized in Lambda function as needed
"""

import boto3
import botocore
import json
import re
from botocore.exceptions import ClientError
import constant as const
import utility as utl

logger = utl.setup_logging()


class SimpleNotificationService:
    """
        SimpleNotificationService class contains methods for AWS SNS service
    """
    def __init__(self):
        self.sns_client = boto3.client('sns')

    def publish_to_topic(self, topic_arn, subject, sns_message):
        """
        Purpose:    Publish message to SNS Topic
        Parameters: Topic ARN, Message Body, Subject, to_function, category, instance_id, counter
        Returns:    Response of Message publish
        Raises:     None
        """
        sns_message_default = json.dumps(sns_message, sort_keys=True, indent=4, separators=(',', ': '))
        sns_message_email = json.dumps(sns_message, sort_keys=True, indent=4, separators=(',', ': '))

        message = {
            "default": sns_message_default,
            "email": sns_message_email
        }

        logger.debug("Publishing Message: " + json.dumps(message, separators=(',', ':')))

        try:
            response = self.sns_client.publish(
                TopicArn=topic_arn,
                Message=json.dumps(message),
                MessageStructure='json',
                Subject=subject
                )
            return response
        except Exception as e:
            logger.critical("Error occurred: {}".format(repr(e)))
            logger.error("Unable to publish message to SNS Topic: %s" % topic_arn)


class AutoScaleGroup:
    """
        AutoScaleGroup class contains methods for AWS AutoScale Group
    """
    def __init__(self, groupname):
        self.groupname = groupname
        self.asg_client = boto3.client('autoscaling')

    def create_or_update_tags(self, key, value):
        """
        Purpose:        To create/update tags on AutoScaling group in AWS
        Parameters:     Tag Key & Value
        Returns:        Response or None
        Raises:
        """
        try:
            response = self.asg_client.create_or_update_tags(
                Tags=[
                    {
                        'Key': key,
                        'PropagateAtLaunch': False,
                        'Value': value,
                        'ResourceType': 'auto-scaling-group',
                        'ResourceId': self.groupname
                    },
                ],
            )
            logger.info("Update tag: %s and assigned value: %s for %s " % (key, value, self.groupname))
        except botocore.exceptions.ClientError as e:
            logger.error("Botocore Error create/update tags: {}".format(e.response['Error']))
            return None
        except Exception as e:
            logger.error("General Error for create/update tags" + str(e))
            return None
        return response

    def describe_tags(self, asg_grp):
        """
        Purpose:        To describe tags on AutoScaling group in AWS
        Parameters:     AutoScale Group name
        Returns:        Response or None
            {
                'Tags': [
                    {
                        'Key': 'Dept',
                        'PropagateAtLaunch': True,
                        'ResourceId': 'my-auto-scaling-group',
                        'ResourceType': 'auto-scaling-group',
                        'Value': 'Research',
                    },
                    {
                        'Key': 'Role',
                        'PropagateAtLaunch': True,
                        'ResourceId': 'my-auto-scaling-group',
                        'ResourceType': 'auto-scaling-group',
                        'Value': 'WebServer',
                    },
                ],
                'ResponseMetadata': {
                    '...': '...',
                },
            }
        """
        try:
            response = self.asg_client.describe_tags(
                Filters=[
                    {
                        'Name': 'auto-scaling-group',
                        'Values': [
                            asg_grp,
                        ]
                    },
                ],
            )
        except botocore.exceptions.ClientError as e:
            logger.error("Botocore Error in describing instance tags: {}".format(e.response['Error']))
            return None
        except Exception as e:
            logger.error("General Error in describing instance tags" + str(e))
            return None
        return response

    def remove_instance(self, instance_id, decrement_cap=True):
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

    def get_instance_list(self):
        """
        Purpose:        To describe AutoScale Group & get instance list
        Parameters:
        Returns:        list of instances in AutoScale Group
        Raises:
        """
        instance_list = []
        try:
            response = self.asg_client.describe_auto_scaling_groups(
                AutoScalingGroupNames=[
                    self.groupname
                ]
            )
            instances = response["AutoScalingGroups"][0]["Instances"]
            for i in instances:
                instance_list.append(i["InstanceId"])
        except botocore.exceptions.ClientError as e:
            logger.error("Botocore Error: {}".format(e.response['Error']))
            return None
        except Exception as e:
            logger.error("General Error in getting instance details" + str(e))
            return None
        return instance_list
    
    def get_asgroup_size(self):
        """
        Purpose:        To get Desired, Min and Max AutoScale Group size.
        Parameters:
        Returns:        Desired, Min and Max group size.
        Raises:
        """
        instance_list = []
        try:
            response = self.asg_client.describe_auto_scaling_groups(
                AutoScalingGroupNames=[
                    self.groupname
                ]
            )
            DesiredCapacity = response["AutoScalingGroups"][0]["DesiredCapacity"]
            MinSize = response["AutoScalingGroups"][0]["MinSize"]
            MaxSize = response["AutoScalingGroups"][0]["MaxSize"]
        except botocore.exceptions.ClientError as e:
            logger.error("Botocore Error: {}".format(e.response['Error']))
            return None
        except Exception as e:
            logger.error("General Error getting group size" + str(e))
            return None
        return DesiredCapacity, MinSize, MaxSize

    def complete_lifecycle_action_success(self, hookname, instance_id):
        """
        Purpose:        To complete lifecycle hook successfully
        Parameters:     Hookname, Group Name, Instance Id
        Returns:
        Raises:
        """
        try:
            self.asg_client.complete_lifecycle_action(
                    LifecycleHookName=hookname,
                    AutoScalingGroupName=self.groupname,
                    InstanceId=instance_id,
                    LifecycleActionResult='CONTINUE'
            )
            logger.info("Lifecycle hook CONTINUEd for: {}".format(instance_id))
        except botocore.exceptions.ClientError as e:
            logger.error("Error completing life cycle hook for instance {}: {}".format(instance_id,
                                                                                       e.response['Error']))
            if re.findall('No active Lifecycle Action found', str(e)):
                logger.info("Lifecycle hook has already been CONTINUEd")

    def complete_lifecycle_action_failure(self, hookname, instance_id):
        """
        Purpose:        To complete lifecycle hook un-successfully
        Parameters:     Hookname, Group Name, Instance Id
        Returns:
        Raises:
        """
        try:
            self.asg_client.complete_lifecycle_action(
                    LifecycleHookName=hookname,
                    AutoScalingGroupName=self.groupname,
                    InstanceId=instance_id,
                    LifecycleActionResult='ABANDON'
            )
            logger.info("Lifecycle hook ABANDONed for: {}".format(instance_id))
        except botocore.exceptions.ClientError as e:
            logger.error("Error completing life cycle hook for instance {}: {}".format(instance_id,
                                                                                       e.response['Error']))
            if re.findall('No active Lifecycle Action found', str(e)):
                logger.info("Lifecycle hook has already been CONTINUEd")


class CloudWatch:
    """
        CloudWatch class for AWS CloudWatc methods
    """
    def __init__(self):
        self.client = boto3.client('cloudwatch')
        self.event = boto3.client('events')

    def set_alarm_state(self, alarm_name, state='INSUFFICIENT_DATA'):
        """
        Purpose:    To set alarm state
        Parameters: Alarm Name, state of alarm to be set
        Returns:    Response
        Raises:
        """
        logger.info("Setting alarm %s state to %s " % (alarm_name, state))
        response = self.client.set_alarm_state(
            AlarmName=alarm_name,
            StateValue=state,
            StateReason='Setting state from Lambda',
        )
        return response

    def put_metric_data(self, metric_data, name_space):
        """
        Purpose:        To put metric data on CloudWatch Metric
        Parameters:     metric data, name space
        Returns:        Response
        Raises:
        """
        logger.debug(json.dumps(metric_data, separators=(',', ': ')))
        response = None
        try:
            response = self.client.put_metric_data(
                MetricData=metric_data,
                Namespace=name_space
            )
        except Exception as e:
            logger.error("{}".format(repr(e)))
            logger.error("Unable to publish metric")

        return response


class CloudWatchEvent(CloudWatch):
    """
        CloudWatchEvent class is child class of CloudWatch
    """
    def __init__(self, name):
        super().__init__()
        self.name = name

    def describe_event_rule(self):
        """
        Purpose:        To describe event rule
        Parameters:
        Returns:        Response
                        {
                            'Name': 'string',
                            'Arn': 'string',
                            'EventPattern': 'string',
                            'ScheduleExpression': 'string',
                            'State': 'ENABLED' | 'DISABLED',
                            'Description': 'string',
                            'RoleArn': 'string',
                            'ManagedBy': 'string',
                            'EventBusName': 'string'
                        }
        """
        response = None
        try:
            response = self.event.describe_rule(
                Name=self.name
            )
        except Exception as e:
            logger.error("{}".format(repr(e)))

        return response

    def enable_event_rule(self):
        """
        Purpose:        To Enable CloudWatch Event
        Parameters:
        Returns:        Response or None
        """
        response = None
        try:
            response = self.event.enable_rule(
                Name=self.name
            )
        except Exception as e:
            logger.error("{}".format(repr(e)))

        return response

    def disable_event_rule(self):
        """
        Purpose:        To Disable CloudWatch Event
        Parameters:
        Returns:        Response or None
        """
        response = None
        try:
            response = self.event.disable_rule(
                Name=self.name
            )
        except Exception as e:
            logger.error("{}".format(repr(e)))
        return response

    def cron_job_status(self):
        """
        Purpose:
        Parameters:
        Returns:
        Raises:
        """
        response = self.describe_event_rule()
        if response is not None:
            try:
                return response['State']
            except Exception as e:
                logger.exception(e)
        return response

    def start_cron_job(self):
        self.enable_event_rule()
        return

    def stop_cron_job(self):
        self.disable_event_rule()
        return


class CloudWatchMetrics(CloudWatch):
    """
        CloudWatchMetrics is child class of CloudWatch
    """
    def __init__(self, grp_name, fmc_device_grp):
        super().__init__()
        self.autoscale_grp = grp_name
        self.fmc_device_grp = fmc_device_grp
        self.name_space = const.METRIC_NAME_SPACE

    def multiple_put_metric_data(self, pair_of_metric_name_value):
        """
        Purpose:        To put metrics, setting up variables for method: put_metric_data
        Parameters:     Dict of metric_name, metric_unit & value
        Returns:        Responses or None
        Raises:
        """
        try:
            dimensions_list = [
                            {
                                'Name': 'AutoScalingGroupName',
                                'Value': self.autoscale_grp
                            },
                            {
                                'Name': 'fmcDeviceGroupName',
                                'Value': self.fmc_device_grp
                            },
                        ]
            metric_data = []
            for i in range(0, len(pair_of_metric_name_value)):
                item = {
                    'Dimensions': dimensions_list,
                    'Unit': pair_of_metric_name_value[i]["unit"],
                    'MetricName': pair_of_metric_name_value[i]['metric_name'],
                    'Value': pair_of_metric_name_value[i]['value'],
                }
                metric_data.append(item)
            return self.put_metric_data(metric_data, self.name_space)
        except Exception as e:
            logger.error("{}".format(repr(e)))
        return None


class EC2Instance:
    """
        EC2Instance class is for AWS EC2 methods
    """
    def __init__(self, instance_id, group=None):
        self.ec2 = boto3.client('ec2')
        self.instance_id = instance_id
        if group is None:
            group = self.get_instance_asg_name()
        self.asg = AutoScaleGroup(group)
        self.vm_name = group + '-' + self.instance_id

    def __get_describe_instance(self):
        """
        Purpose:        To describe EC2 instance
        Parameters:
        Returns:        Response or None
        Raises:
        """
        try:
            response = self.ec2.describe_instances(
                InstanceIds=[
                    self.instance_id,
                ]
            )
        except ClientError as e:
            logger.error("Unable find describe-instances for instance: " + self.instance_id)
            logger.error(str(e))
            return None
        else:
            return response

    def get_describe_instance_from_private_ip(self, private_ip):
        """
        Purpose:        To get EC2 instance describe with private Ip filter
        Parameters:     Private Ip
        Returns:        Response or None
        Raises:
        """
        try:
            response = self.ec2.describe_instances(
                Filters=[{'Name': 'network-interface.addresses.private-ip-address', 'Values': [private_ip]}]
            )
        except ClientError as e:
            logger.info("Unable find describe-instances for ip: " + private_ip)
            logger.debug(str(e))
            return None
        else:
            return response

    def get_instance_interfaces_ip(self):
        """
        Purpose:        To get all 4 interfaces IPs
        Parameters:
        Returns:        Dict of IPs or None
                        Example: {'public_ip': '54.88.96.211', 'private_ip': '10.0.250.88', 'inside_ip': '10.0.100.139',
                                    'outside_ip': '10.0.200.116'}
        Raises:
        """
        interfaces_ip = {}
        response = self.__get_describe_instance()
        try:
            r = response['Reservations'][0]['Instances'][0]['PublicIpAddress']
        except Exception as e:
            logger.debug(str(e))
            interfaces_ip.update({'public_ip': None})
            pass
        else:
            interfaces_ip.update({'public_ip': r})
        try:
            r = response['Reservations'][0]['Instances'][0]['PrivateIpAddress']
        except Exception as e:
            logger.debug(str(e))
        else:
            interfaces_ip.update({'private_ip': r})

        r = self.get_private_ip_of_interface(const.ENI_NAME_OF_INTERFACE_2)
        if r is not None:
            interfaces_ip.update({'inside_ip': r})
        else:
            return None
        r = self.get_private_ip_of_interface(const.ENI_NAME_OF_INTERFACE_3)
        if r is not None:
            interfaces_ip.update({'outside_ip': r})
        else:
            return None

        logger.debug("Retrieved Interfaces IP " + str(interfaces_ip))
        return interfaces_ip

    def get_public_ip(self):
        """
        Purpose:        To get public ip of the instance
        Parameters:
        Returns:        Public Ip or None
        Raises:
        """
        response = self.__get_describe_instance()
        try:
            r = response['Reservations'][0]['Instances'][0]['PublicIpAddress']
        except Exception as e:
            logger.debug(str(e))
            return 'error retrieving public ip'
        return r

    def get_private_ip(self):
        """
        Purpose:        To get private ip of the instance
        Parameters:
        Returns:        Private Ip or None
        Raises:
        """
        response = self.__get_describe_instance()
        try:
            r = response['Reservations'][0]['Instances'][0]['PrivateIpAddress']
        except Exception as e:
            logger.debug(str(e))
            return 'error retrieving private ip'
        return r

    def get_instance_state(self):
        """
        Purpose:        To get instance state
        Parameters:
        Returns:        state (running, stopping, stopped, terminated, shutting-down, pending) or None
        Raises:
        """
        response = self.__get_describe_instance()
        try:
            state = response['Reservations'][0]['Instances'][0]['State']['Name']
            return state
        except Exception as e:
            logger.debug("Unable to get state of %s " % self.instance_id)
            logger.debug("Error occurred: {}".format(repr(e)))
            return None

    def get_mgmt_subnet_id(self):
        """
        Purpose:        To get mgmt Subnet Id
        Parameters:
        Returns:        Subnet Id or None
        Raises:
        """
        try:
            result = self.__get_describe_instance()
            vpc_subnet_id = result['Reservations'][0]['Instances'][0]['SubnetId']
            logger.info("Management Subnet id: {}".format(vpc_subnet_id))
        except botocore.exceptions.ClientError as e:
            logger.error("Error describing the instance {}: {}".format(self.instance_id, e.response['Error']))
            vpc_subnet_id = None
        return vpc_subnet_id

    def get_instance_asg_name(self):
        """
        Purpose:        To get instance Autoscale Group name
        Parameters:
        Returns:        Autoscale Group name or None
        Raises:
        """
        asg_name = None
        response = self.__get_describe_instance()
        if response is not None:
            for val in response['Reservations'][0]['Instances'][0]['Tags']:
                if val['Key'] == "aws:autoscaling:groupName":
                    asg_name = str(val['Value'])
                    return asg_name
        else:
            logger.error("Unable to get autoscale group from describe_instance ")
            return asg_name

    def get_instance_tags(self):
        """
        Purpose:        To get instance tags
        Parameters:
        Returns:        Tags in dict list
        Raises:
        """
        response = self.__get_describe_instance()
        if response is not None:
            return response['Reservations'][0]['Instances'][0]['Tags']
        else:
            logger.error("Unable to get autoscale group from describe_instance ")
            return None

    def get_security_group_id(self):
        """
        Purpose:        To get Security group Id
        Parameters:
        Returns:        Security group ID list
        Raises:
        """
        sec_grp_id = []
        try:
            result = self.__get_describe_instance()
            sec_grp_id = result['Reservations'][0]['Instances'][0]['SecurityGroups'][0]['GroupId']
            logger.info("Security Group id: {}".format(sec_grp_id))
        except botocore.exceptions.ClientError as e:
            logger.error("Error describing the instance {}: {}".format(self.instance_id, e.response['Error']))
            sec_grp_id = None
        except Exception as e:
            logger.exception(e)
        return sec_grp_id

    def get_cidr_describe_subnet(self, subnet_id):
        """
        Purpose:        To get cidr from describe subnet
        Parameters:     subnet id
        Returns:        cidr or None
        Raises:
        """
        try:
            response = self.ec2.describe_subnets(
                Filters=[
                    {
                        'Name': 'subnet-id',
                        'Values': [
                            subnet_id,
                        ]
                    },
                ]
            )
        except ClientError as e:
            logger.debug(str(e))
            logger.info("Unable find describe-subnets for subnet with filter subnet-id: " + subnet_id)
            return None
        else:
            cidr = response['Subnets'][0]['CidrBlock']
            return cidr

    def get_subnet_mask_from_subnet_id(self, subnet_id):
        """
        Purpose:        To get subnet mask from describe subnet  # Related to CSCvs17405
        Parameters:     subnet id
        Returns:        subnet mask
        Raises:
        """
        cidr = self.get_cidr_describe_subnet(subnet_id)
        try:
            if cidr is not None:
                logger.debug("Received: cidr %s from subnet id: %s" % (cidr, subnet_id))
                split_cidr = cidr.split("/")
                logger.debug("Found subnet mask: %s for subnet: %s with cidr block: %s" % (split_cidr[1],
                                                                                           subnet_id, cidr))
                return str(split_cidr[1])
        except Exception as e:
            logger.debug("{}".format(e))
            logger.error("Unable to split CIDR block to get subnet mask")
            return None

    def get_cidr_describe_security_group(self, group_id):
        """
        Purpose:    To get cidr from describe security group
        Parameters: security group id
        Returns:    cidr
        Raises:
        """
        cidr = None
        try:
            response = self.ec2.describe_security_groups(
                GroupIds=[
                    group_id,
                ]
            )
        except ClientError as e:
            logger.info("Unable find describe-security group for subnet with filter sec_grp_id-id: " + group_id)
            logger.debug(str(e))
            return None
        else:
            security_group = response['SecurityGroups'][0]
            for permission in security_group.get('IpPermissions', []):
                if permission['IpProtocol'] == 'tcp':
                    for ip_range in permission.get('IpRanges', []):
                        cidr = ip_range['CidrIp']
            return cidr

    def get_instance_az(self):
        """
        Purpose:        To get AZ of an EC2 Instance
        Parameters:
        Returns:        AZ
        Raises:
        """
        r = self.__get_describe_instance()
        if r is not None:
            availability_zone = r['Reservations'][0]['Instances'][0]['Placement']['AvailabilityZone']
            return availability_zone
        else:
            return None

    def get_subnet_list_in_az(self, instance_az):
        """
        Purpose:        To get list of subnets in given AZ
        Parameters:     AZ
        Returns:        List of subnets
        Raises:
        """
        subnet_list = []
        r = self.get_describe_subnets_of_az(instance_az)
        if r is not None:
            for item in r['Subnets']:
                subnet_list.append(item['SubnetId'])
            return subnet_list
        else:
            return subnet_list

    def get_describe_subnets_of_az(self, instance_az):
        """
        Purpose:        To get Describe Subnet result in a given Availability zone
        Parameters:     Availability Zone
        Returns:        Describe Subnet Response
        Raises:
        """
        try:
            response = self.ec2.describe_subnets(
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

    def get_private_ip_of_interface(self, interface_suffix):
        """
        Purpose:        To get private ip of a specified interface
        Parameters:     Interface suffix
        Returns:        Private Ip or None
        Raises:
        """
        eni_name = self.instance_id + interface_suffix
        try:
            result = self.ec2.describe_network_interfaces(Filters=[{'Name': 'tag:Name', 'Values': [eni_name]}])
        except Exception as e:
            logger.error("Unable find describe_network_interfaces for instance %s" % self.instance_id)
            logger.error(str(e))
            return
        else:
            try:
                ip = result['NetworkInterfaces'][0]['PrivateIpAddress']
                logger.debug("Private IP of " + eni_name + " interface is {}".format(ip))
                return ip
            except Exception as e:
                logger.error("Unable to get IP from describe_network_interfaces response for interface %s" % eni_name)
                logger.error(str(e))
                return None

    def get_subnet_id_of_interface(self, interface_suffix):
        """
        Purpose:        To get subnet id of interface whose suffix is given
        Parameters:     Interface name suffix
        Returns:        subnet id
        Raises:
        """
        eni_name = self.instance_id + interface_suffix
        try:
            result = self.ec2.describe_network_interfaces(Filters=[{'Name': 'tag:Name', 'Values': [eni_name]}])
        except Exception as e:
            logger.error("Unable find describe_network_interfaces for interface %s" % eni_name)
            logger.error(str(e))
            return
        else:
            try:
                subnet_id = result['NetworkInterfaces'][0]['SubnetId']
                logger.debug(subnet_id)
                logger.info("Subnet ID of " + eni_name + " interface is {}".format(subnet_id))
                return subnet_id
            except Exception as e:
                logger.error(
                    "Unable to get subnet_id from describe_network_interfaces response for interface %s" % eni_name)
                logger.error(str(e))
                return None

    def create_interface(self, subnet_id, sec_grp_id, eni_name):
        """
        Purpose:        To create interface in a specified subnet id
        Parameters:     Subnet Id, Security Group, ENI name
        Returns:        Interface Id
        Raises:
        """
        network_interface_id = None
        if subnet_id:
            try:
                network_interface = self.ec2.create_network_interface(SubnetId=subnet_id, Groups=[sec_grp_id])
                network_interface_id = network_interface['NetworkInterface']['NetworkInterfaceId']
                logger.info("Created network interface: {}".format(network_interface_id))

                self.ec2.create_tags(Resources=[network_interface_id], Tags=[{'Key': 'Name', 'Value': eni_name}])
                logger.info("Added tag {} to network interface".format(eni_name))
            except botocore.exceptions.ClientError as e:
                logger.error("Error creating network interface: {}".format(e.response['Error']))
        return network_interface_id

    def delete_interface(self, network_interface_id):
        """
        Purpose:        To delete interface
        Parameters:     Interface Id
        Returns:
        Raises:
        """
        try:
            self.ec2.delete_network_interface(
                NetworkInterfaceId=network_interface_id
            )
            logger.info("Deleted network interface: {}".format(network_interface_id))
            return True
        except botocore.exceptions.ClientError as e:
            logger.error("Error deleting interface {}: {}".format(network_interface_id, e.response['Error']))

    def attach_interface(self, network_interface_id, device_index):
        """
        Purpose:        To attach interface to device
        Parameters:     Network interface id, Instance id, Device index
        Returns:        Attachment
        Raises:
        """
        attachment = None
        if network_interface_id:
            try:
                attach_interface = self.ec2.attach_network_interface(
                    NetworkInterfaceId=network_interface_id,
                    InstanceId=self.instance_id,
                    DeviceIndex=device_index
                )
                attachment = attach_interface['AttachmentId']
                logger.info("Created network attachment: {}".format(attachment))
                try:
                    modify_attachment = self.ec2.modify_network_interface_attribute(
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
                    logger.debug("Response of modify_network_interface_attribute: %s" % str(modify_attachment))
                    # both "Attachment" and "SourceDestCheck" doesn't go together in same function call
                    # hence we need to call "modify_network_interface_attribute" again with "SourceDestCheck"
                    modify_attachment = self.ec2.modify_network_interface_attribute(
                        NetworkInterfaceId=network_interface_id,
                        SourceDestCheck={
                            'Value': False
                        }
                    )
                    logger.debug("Response of modify_network_interface_attribute: %s" % str(modify_attachment))
                except botocore.exceptions.ClientError as e:
                    logger.error("Error modifying network interface: {}".format(e.response['Error']))
                    return attachment, e.response['Error']
            except botocore.exceptions.ClientError as e:
                logger.error("Error attaching network interface: {}".format(e.response['Error']))
                return attachment, e.response['Error']
        return attachment, ''

    def get_private_ip_of_specific_interface(self, eni_name):
        """
        Purpose:        To get private IP for a given interface name
        Parameters:     Interface name
        Returns:        IP or None
        Raises:
        """
        try:
            result = self.ec2.describe_network_interfaces(Filters=[{'Name': 'tag:Name', 'Values': [eni_name]}])
            logger.debug(result)
            private_ip = result['NetworkInterfaces'][0]['PrivateIpAddress']
        except ClientError as e:
            logger.info("Unable find private IP for eni: %s " % eni_name)
            logger.debug(str(e))
            return None
        except Exception as e:
            logger.debug("Exception {}".format(repr(e)))
            return None
        else:
            return private_ip

    def create_instance_tags(self, tag_name, tag_value):
        """
        Purpose:        To create tag on EC2 instance
        Parameters:
        Returns:        Response
        Raises:
        """
        try:
            response = self.ec2.create_tags(
                Resources=[
                    self.instance_id,
                ],
                Tags=[
                    {
                        'Key': tag_name,
                        'Value': tag_value
                    },
                ]
            )
            logger.info("Created tag: %s and assigned value: %s for %s " % (tag_name, tag_value, self.instance_id))
            logger.debug(response)
            return response
        except Exception as e:
            logger.error("Unable to create tag: %s with value: %s for %s " % (tag_name, tag_value, self.instance_id))
            logger.debug(str(e))
            return None

    def disable_src_dst_check_on_primary_int(self):
        """
        Purpose:    To modify source/destination check on primary interface
        Parameters:
        Returns:    None
        Raises:
        """
        try:
            response = self.ec2.modify_instance_attribute(
                SourceDestCheck={
                    'Value': False
                },
                InstanceId=self.instance_id
            )
            logger.info("Disabled source and destination check on primary interface")
            logger.debug(response)
            return response
        except Exception as e:
            logger.error("Unable to disable source and destination check on primary interface ")
            logger.debug(str(e))
            return None

    def remove_from_asg(self, decrement_cap=False):
        """
        Purpose:    To remove device from Autoscale Group
        Parameters: ShouldCapacityDecrement parameter
        Returns:    SUCCESS, FAILED
        Raises:
        """
        r = self.asg.remove_instance(self.instance_id, decrement_cap)
        if r is None:
            logger.info("Unable to terminate the instance")
            return "FAILED"
        logger.info("Instance termination has been initiated: " + self.instance_id)
        return "SUCCESS"


class ElasticLoadBalancer:
    def __init__(self):
        self.ec2_elb_client = boto3.client('elbv2')

    def __get_targets_health(self, lb_arn):
        """
        Purpose:        To get describe of target groups
        Parameters:     LB ARN
        Returns:
        Raises:
        """
        tg_arn, ports = self.__get_tg_arn_and_port_list(lb_arn)
        try:
            response = self.ec2_elb_client.describe_target_health(
                TargetGroupArn=tg_arn,
            )
        except botocore.exceptions.ClientError as e:
            logger.error("Error describe_target_health: {}".format(e.response['Error']))
            return None
        else:
            return response

    def __get_tg_arn_and_port_list(self, lb_arn):
        """
        Purpose:        To get TGs' ARNs and Ports associated to them in give LB
        Parameters:     LB ARN
        Returns:        TG's ARN list, Ports list
        Raises:
        """
        tg_arn = []
        ports = []
        if lb_arn:
            try:
                response = self.ec2_elb_client.describe_target_groups(
                    LoadBalancerArn=lb_arn,
                )
            except botocore.exceptions.ClientError as e:
                logger.error("Error describing target group attributes: {}".format(e.response['Error']))
                return None
            else:
                list_len = len(response['TargetGroups'])
                for i in range(0, list_len):
                    tg_arn.append(response['TargetGroups'][i]['TargetGroupArn'])
                    ports.append(response['TargetGroups'][i]['Port'])
                return tg_arn, ports
        return None

    def register_ip_target_to_lb(self, lb_arn, ip):
        """
        Purpose:        To register IP to target groups of given LB
        Parameters:     LB Arn, Ip
        Returns:        TG Arns list or None
        Raises:
        """
        tg_arns, ports = self.__get_tg_arn_and_port_list(lb_arn)
        if tg_arns is not None:
            list_len = len(tg_arns)
            for i in range(0, list_len):
                try:
                    response = self.ec2_elb_client.register_targets(
                        TargetGroupArn=tg_arns[i],
                        Targets=[
                            {
                                'Id': ip,
                                'Port': ports[i]
                            }
                        ]
                    )
                except botocore.exceptions.ClientError as e:
                    logger.error("Error describe_target_health: {}".format(e.response['Error']))
                    return None
                else:
                    logger.debug(response)
            return tg_arns
        return None

    def deregister_ip_target_from_lb(self, lb_arn, ip):
        """
        Purpose:        To de-register IP from LB Target groups
        Parameters:     LB Arn, Ip
        Returns:        TG Arn list
        Raises:
        """
        tg_arns, ports = self.__get_tg_arn_and_port_list(lb_arn)
        if tg_arns is not None:
            list_len = len(tg_arns)
            for i in range(0, list_len):
                try:
                    response = self.ec2_elb_client.deregister_targets(
                        TargetGroupArn=tg_arns[i],
                        Targets=[
                            {
                                'Id': ip,
                                'Port': ports[i]
                            }

                        ]
                    )
                except botocore.exceptions.ClientError as e:
                    logger.error("Error de-registering the target: {}".format(e.response['Error']))
                else:
                    logger.debug(response)
            return tg_arns
        return None

    def get_unhealthy_ip_targets(self, lb_arn):
        """
        Purpose:        To get list of un-healthy IPs in all Target Groups of given LB
        Parameters:     LB Arn
        Returns:        List of IPs
        Raises:
        """
        unhealthy_ip_targets = []
        tg_arns, ports = self.__get_tg_arn_and_port_list(lb_arn)
        if tg_arns is not None:
            list_len = len(tg_arns)
            for i in range(0, list_len):
                try:
                    response = self.ec2_elb_client.describe_target_health(
                        TargetGroupArn=tg_arns[i],
                    )
                except botocore.exceptions.ClientError as e:
                    logger.error("Error describe_target_health: {}".format(e.response['Error']))
                    return None
                list_len = len(response['TargetHealthDescriptions'])
                if list_len > 0:
                    for j in range(0, list_len):
                        target = response['TargetHealthDescriptions'][j]
                        if target['TargetHealth']['State'] == 'unhealthy':
                            # Remove duplicate entries
                            if target['Target']['Id'] not in unhealthy_ip_targets:
                                unhealthy_ip_targets.append(target['Target']['Id'])
            return unhealthy_ip_targets
        return None

    def modify_target_groups_deregistration_delay(self, lb_arn, dereg_delay):
        """
        Purpose:        To add draining time while de-registering IP
        Parameters:     LB ARn, De-reg time
        Returns:        TG Arns list, None
        Raises:
        """
        tg_arns, ports = self.__get_tg_arn_and_port_list(lb_arn)
        if tg_arns is not None:
            list_len = len(tg_arns)
            for i in range(0, list_len):
                try:
                    response = self.ec2_elb_client.modify_target_group_attributes(
                        TargetGroupArn=tg_arns[i],
                        Attributes=[
                            {
                                'Key': 'deregistration_delay.timeout_seconds',
                                'Value': str(dereg_delay),
                            },
                        ]
                    )
                except botocore.exceptions.ClientError as e:
                    logger.error("Error modifying target group attributes: {}".format(e.response['Error']))
                    return None
                else:
                    logger.debug("Modifying TG: %s deregistration delay" % tg_arns[i])
                    logger.debug(response)
            return tg_arns
        return None


class CiscoEc2Instance(EC2Instance):
    """
        CiscoEc2Instance is child class of EC2Instance class, enabling interface to LB connections
    """
    def __init__(self, instance_id):
        super().__init__(instance_id)
        self.lb = ElasticLoadBalancer()
        self.SUCCESS = 'SUCCESS'
        self.FAIL = 'FAIL'

    def register_instance_to_lb(self, lb_arn, eni_name):
        """
        Purpose:        To register a specific interface to LB
        Parameters:     LB Arn, Interface name
        Returns:        SUCCESS, FAIL
        Raises:
        """
        try:
            private_ip = self.get_private_ip_of_specific_interface(eni_name)
            if private_ip is None:
                logger.error("Unable to find private IP address for interface")
                return self.FAIL
            logger.info("Private IP of interface: {}".format(private_ip))
            if self.lb.register_ip_target_to_lb(lb_arn, private_ip) is None:
                logger.error("Unable to register %s to Load Balancer" % private_ip)
        except botocore.exceptions.ClientError as e:
            logger.error("Error registering the target: {}".format(e.response['Error']))
            return self.FAIL
        else:
            return self.SUCCESS

    def deregister_instance_from_lb(self, lb_arn, eni_name):
        """
        Purpose:        To de-register a specific interface from LB
        Parameters:     LB Arn, Interface name
        Returns:        SUCCESS, FAIL
        Raises:
        """
        try:
            private_ip = self.get_private_ip_of_specific_interface(eni_name)
            if private_ip is None:
                logger.error("Unable to find private IP address for interface")
                return self.FAIL
            logger.info("Private IP of interface: {}".format(private_ip))
            if self.lb.deregister_ip_target_from_lb(lb_arn, private_ip) is None:
                logger.error("Unable to deregister %s from Load Balancer" % private_ip)
        except botocore.exceptions.ClientError as e:
            logger.error("Error de-registering the target: {}".format(e.response['Error']))
            return self.FAIL
        else:
            return self.SUCCESS