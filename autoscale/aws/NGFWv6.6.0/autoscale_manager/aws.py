"""
Name:       aws.py
Purpose:    This is contains aws resources related methods
"""
import boto3
import botocore
import json
from botocore.exceptions import ClientError
import constant as const
import utility as utl

# Setup Logging
logger = utl.setup_logging(utl.e_var['DebugDisable'])


# AWS EC2 related class
class Ec2Instance:
    def __init__(self, instance_id):
        self.ec2 = boto3.client('ec2')
        self.instance_id = instance_id
        self.vm_name = utl.e_var['AutoScaleGrpName'] + '-' + self.instance_id

    def get_describe_instance(self):
        """
        Purpose:    Describe EC2 instance
        Parameters:
        Returns:    Describe response
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

    def get_instance_interfaces_ip(self):
        """
        Purpose:    To get all 4 interfaces IPs
        Parameters:
        Returns:    Dict
                    Example: {'public_ip': '54.88.96.211', 'private_ip': '10.0.250.88', 'inside_ip': '10.0.100.139',
                    'outside_ip': '10.0.200.116'}
        Raises:
        """
        interfaces_ip = {}
        response = self.get_describe_instance()
        try:
            r = response['Reservations'][0]['Instances'][0]['PublicIpAddress']
        except Exception as e:
            logger.debug(str(e))
            return None
        else:
            interfaces_ip.update({'public_ip': r})
        try:
            r = response['Reservations'][0]['Instances'][0]['PrivateIpAddress']
        except Exception as e:
            logger.debug(str(e))
        else:
            interfaces_ip.update({'private_ip': r})

        r = self.get_private_ip_of_interface(const.INSIDE_ENI_NAME)
        if r is not None:
            interfaces_ip.update({'inside_ip': r})
        else:
            return None
        r = self.get_private_ip_of_interface(const.OUTSIDE_ENI_NAME)
        if r is not None:
            interfaces_ip.update({'outside_ip': r})
        else:
            return None

        logger.debug("Retrieved Interfaces IP " + str(interfaces_ip))
        return interfaces_ip

    def get_private_ip_of_interface(self, interface_suffix):
        """
        Purpose:    To get private ip of a specified interface
        Parameters: Interface suffix
        Returns:    Private Ip
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

    def get_public_ip(self):
        """
        Purpose:    To get public ip of the host
        Parameters:
        Returns:    Public Ip
        Raises:
        """
        try:
            interfaces_ip = self.get_instance_interfaces_ip()
            return interfaces_ip['public_ip']
        except Exception as e:
            logger.debug("Error occurred: {}".format(repr(e)))
            return None

    def get_subnet_id_of_interface(self, interface_suffix):
        """
        Purpose:    To get subnet id of interface whose suffix is given
        Parameters: Interface name suffix
        Returns:    subnet id
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
                logger.error("Unable to get subnet_id from describe_network_interfaces response for interface %s" % eni_name)
                logger.error(str(e))
                return None

    def get_instance_state(self):
        """
        Purpose:    To get instance state
        Parameters:
        Returns:    state (running, stopping, stopped, terminated, shutting-down, pending)
        Raises:
        """
        response = self.get_describe_instance()
        try:
            state = response['Reservations'][0]['Instances'][0]['State']['Name']
            return state
        except Exception as e:
            logger.debug("Unable to get state of %s " % self.instance_id)
            logger.debug("Error occurred: {}".format(repr(e)))
            return None

    def get_instance_asg_name(self):
        """
        Purpose:    To get instance Autoscale Group name
        Parameters:
        Returns:    Autoscale Group name
        Raises:
        """
        asg_name = None
        response = self.get_describe_instance()
        if response is not None:
            for val in response['Reservations'][0]['Instances'][0]['Tags']:
                if val['Key'] == "aws:autoscaling:groupName":
                    asg_name = str(val['Value'])
                    return asg_name
        else:
            logger.error("Unable to get autoscale group from describe_instance ")
            return asg_name

    def put_instance_name(self):
        """
        Purpose:    To put name tag on EC2 NGFW instance
        Parameters:
        Returns:    create_tags response
        Raises:
        """
        try:
            response = self.ec2.create_tags(
                Resources=[
                    self.instance_id,
                ],
                Tags=[
                    {
                        'Key': 'Name',
                        'Value': self.vm_name
                    },
                ]
            )
            logger.info("Created Tag for Instance %s " % self.instance_id)
            logger.debug(response)
        except Exception as e:
            logger.error("Unable to create Tag for %s " % self.instance_id)
            logger.debug(str(e))
            return None

    def get_cidr_describe_subnet(self, subnet_id):
        """
        Purpose:    To get cidr from describe subnet
        Parameters: subnet id
        Returns:    cidr
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
            logger.info("Unable find describe-subnets for subnet with filter subnet-id: " + subnet_id)
            logger.debug(str(e))
            return None
        else:
            cidr = response['Subnets'][0]['CidrBlock']
            return cidr

    def get_subnet_mask_from_subnet_id(self, subnet_id):
        """
        Purpose:    To get subnet mask from describe subnet  # Related to CSCvs17405
        Parameters: subnet id
        Returns:    subnet mask
        Raises:
        """
        cidr = self.get_cidr_describe_subnet(subnet_id)
        try:
            if cidr is not None:
                logger.debug("Recieved: cidr %s from subnet id: %s" %(cidr, subnet_id))
                split_cidr = cidr.split("/")
                logger.debug("Found subnet mask: %s for subnet: %s with cidr block: %s" % (split_cidr[1], subnet_id, cidr))
                return str(split_cidr[1])
        except Exception as e:
            logger.error("Unable to split CIDR block to get subnet mask")
            return None
            

class SimpleNotificationService:
    def __init__(self):
        self.sns_client = boto3.client('sns')

    def publish_to_topic(self, topic_arn, message, subject, to_function, category, instance_id, counter='-1'):
        """
        Purpose:    Publish message to SNS Topic
        Parameters: Topic ARN, Message Body, Subject, to_function, category, instance_id, counter
        Returns:    Response of Message publish
        Raises:     None
        """
        if counter == '-1':
            if to_function == 'vm_register':
                counter = 5
            elif to_function == 'vm_configure':
                counter = 10
            elif to_function == 'vm_deploy':
                counter = 5
            elif to_function == 'vm_delete':
                counter = 5
            elif to_function == 'vm_ready':
                counter = 3

        # Constructing a JSON object as per AWS SNS requirement
        sns_message = {
            "Description": message,
            "Autoscale_group": utl.e_var['AutoScaleGrpName'],
            "Topic_arn": topic_arn,
            "Device_group": utl.j_var['DeviceGroupName'],
            "to_function": to_function,
            "category": category,
            "instance_id": instance_id,
            "counter": str(counter)
        }
        sns_message_default = json.dumps(sns_message, sort_keys=True, indent=4, separators=(',', ': '))
        sns_message_email = json.dumps(sns_message, sort_keys=True, indent=4, separators=(',', ': '))
        message = {
            "default": sns_message_default,
            "email": sns_message_email
        }

        logger.debug("Publishing Message with attributes to: " + to_function + " " + category + " " + str(counter))
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


# AWS AutoScale group class
class ASG:
    def __init__(self):
        self.asg_client = boto3.client('autoscaling')

    def remove_instance_asg(self, instance_id, decrement_cap=False):
        """
        Purpose:    To remove instance from Autoscale Group
        Parameters: Instance id, DecrementCapacity
        Returns:    boto3 response
        Raises:
        """
        try:
            response = self.asg_client.terminate_instance_in_auto_scaling_group(
                InstanceId=instance_id,
                ShouldDecrementDesiredCapacity=decrement_cap
            )
        except botocore.exceptions.ClientError as e:
            logger.debug("Botocore Error removing the instance: {}".format(e.response['Error']))
            return None
        except Exception as e:
            logger.debug("General Error removing the instance" + str(e))
            return None
        return response
