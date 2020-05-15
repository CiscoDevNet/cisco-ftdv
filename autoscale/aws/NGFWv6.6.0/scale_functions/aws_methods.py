import boto3
import botocore
import re
from constant import *
from botocore.exceptions import ClientError


# AWS Autoscale group class fixme Need to write useful methods in this class
class ASG:
    def __init__(self):
        self.asg_client = boto3.client('autoscaling')

    def remove_instance_asg(self, instance_id, decrement_cap):
        try:
            response = self.asg_client.terminate_instance_in_auto_scaling_group(
                InstanceId=instance_id,
                ShouldDecrementDesiredCapacity=decrement_cap
                # fixme if Scale-In/Out lambda is created this should be made
                #   'False'
            )
        except botocore.exceptions.ClientError as e:
            logger.error("Botocore Error removing the instance: {}".format(e.response['Error']))
            return None
        except Exception as e:
            logger.error("General Error removing the instance" + str(e))
            return None
        return response

    def complete_lifecycle_action_success(self, hookname, groupname, instance_id):
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
        try:
            result = self.ec2_client.describe_instances(InstanceIds=[instance_id])
            vpc_subnet_id = result['Reservations'][0]['Instances'][0]['SubnetId']
            logger.info("Mgmt Subnet id: {}".format(vpc_subnet_id))

        except botocore.exceptions.ClientError as e:
            logger.error("Error describing the instance {}: {}".format(instance_id, e.response['Error']))
            vpc_subnet_id = None
        return vpc_subnet_id

    def create_interface(self, subnet_id, sec_grp_id, eni_name):
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
        try:
            self.ec2_client.delete_network_interface(
                NetworkInterfaceId=network_interface_id
            )
            logger.info("Deleted network interface: {}".format(network_interface_id))
            return True
        except botocore.exceptions.ClientError as e:
            logger.error("Error deleting interface {}: {}".format(network_interface_id, e.response['Error']))

    def get_security_group_id(self, instance_id):
        try:
            result = self.ec2_client.describe_instances(InstanceIds=[instance_id])
            sec_grp_id = result['Reservations'][0]['Instances'][0]['SecurityGroups'][0]['GroupId']
            logger.info("Security Group id: {}".format(sec_grp_id))
        except botocore.exceptions.ClientError as e:
            logger.error("Error describing the instance {}: {}".format(instance_id, e.response['Error']))
            sec_grp_id = None
        return sec_grp_id

    def register_target_outside(self, instance_id, tgARN, port):
        target = None
        if instance_id and tgARN:
            try:
                # Getting outside interface ip
                outside_eni_name = instance_id + OUTSIDE_ENI_NAME
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

    def deregister_target_outside(self, instance_id, tgARN, port):
        target = None
        if instance_id and tgARN:
            try:
                # Getting outside interface ip
                outside_eni_name = instance_id + OUTSIDE_ENI_NAME
                result = self.ec2_client.describe_network_interfaces(Filters=[{'Name': 'tag:Name', 'Values': [outside_eni_name]}])
                try:
                    outside_ip = result['NetworkInterfaces'][0]['PrivateIpAddress']
                except Exception as e:
                    logger.error("Unable to get outside private IP describe_network_interfaces")
                    logger.debug(str(e))

                    return target
                logger.info("Outside Interface IP : {}".format(outside_ip))
                logger.info("Target Group Name {}".format(tgARN))
                # Adding ip to TG
                target = self.ec2_elb_client.deregister_targets(TargetGroupArn=tgARN, Targets=[{'Id': outside_ip, 'Port': port}])
            except botocore.exceptions.ClientError as e:
                logger.error("Error de-registering the target: {}".format(e.response['Error']))
        return target

    def modify_target_group(self, tgARN):
        if tgARN:
            try:
                response = self.ec2_elb_client.modify_target_group_attributes(
                    TargetGroupArn=tgARN,
                    Attributes=[
                        {
                            'Key': 'deregistration_delay.timeout_seconds',
                            'Value': str(DEREGISTRATION_DELAY),
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

    def get_instance_az(self, instance_id):
        r = self.get_describe_instance(instance_id)
        if r is not None:
            availability_zone = r['Reservations'][0]['Instances'][0]['Placement']['AvailabilityZone']
            return availability_zone
        else:
            return None

    def get_describe_subnet(self, instance_az):
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
        subnet_list = []
        r = self.get_describe_subnet(instance_az)
        if r is not None:
            for item in r['Subnets']:
                subnet_list.append(item['SubnetId'])
            return subnet_list
        else:
            return subnet_list


# def get_inside_subnet_id(subnets_list_in_az):
#     try:
#         vpc_subnet_id = get_common_member_in_list(subnets_list_in_az, INSIDE_SUBNET_ID_LIST)
#         logger.debug("Inside Subnet id: {}".format(vpc_subnet_id))
#     except botocore.exceptions.ClientError as e:
#         logger.debug("Error describing the subnet: {}".format(e.response['Error']))
#         vpc_subnet_id = None
#     return vpc_subnet_id
#
#
# def get_outside_subnet_id(subnets_list_in_az):
#     try:
#         vpc_subnet_id = get_common_member_in_list(subnets_list_in_az, OUTSIDE_SUBNET_ID_LIST)
#         logger.debug("Outside Subnet id: {}".format(vpc_subnet_id))
#     except botocore.exceptions.ClientError as e:
#         logger.debug("Error describing the subnet: {}".format(e.response['Error']))
#         vpc_subnet_id = None
#     return vpc_subnet_id


def get_common_member_in_list(list1, list2):
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

