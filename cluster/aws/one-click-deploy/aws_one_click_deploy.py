'''
Copyright (c) 2022 Cisco Systems Inc or its affiliates.

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

Single click deployment for Cisco NGFWv Clustering for AWS

DEFAULT DEPLOYMENT mode:

This script deploys infrastructure stack and uploads lambda-zips to the
bucket created.
(1) If the fmc_ip is assigned a non-empty string, then that value will be
    used for cluster deployment.
	fmc_ip should be assigned a value only if FMC is already deployed, or to be
	deployed with the fixed assigned IP.
	If the user plans to deploy the FMC after infrastructure creation, the
	fmc_ip parameter must be left blank
(2) If fmc_ip is empty (''), user will be given 2 options-
   	(a) Leave the script running but waiting until user enters the fmc_ip. In
	    this time, FMC can be deployed, after which fmc_ip and any parameter
		left empty in the NGFWV_CLUSTER_STACK_PARAMS can be entered.
	    After this, the script will continue deploy the cluster stack
	(b) Exit the execution, use CLUSTER_ONLY_DEPLOYMENT after FMC deployment

CLUSTER_ONLY_DEPLOYMENT mode:

Only cluster stack is deployed in this mode.
However, an infrastructure stack must have been deployed already with this
script, with the same set of PRIME_INFRA_PARAMS as assigned below


System requirements: macOS/Linux/Windows machine with python3 (and hence pip3)
	command working

Remarks:
	boto3 if not already installed will be installed to a virtual environment
	in that case, virtualenv if not already installed wil be installed by pip3
	cfn_flip if not already installed will be installed by pip3

'''

#-------------------SET_PARAMETERS_FOR_ONE_CLICK_DEPLOYMENT--------------------#

#Parameters can be assigned values here
#all parameters are strings, have to be assigned values under quotes ('' or "")
#if parameters are unset ( assigned '' ) but required during execution,
#user will be prompted for input

#------------------------------AWS_SESSION_PARAMS------------------------------#
#to unset, assign ''

aws_access_key_id = ''
#access key for AWS account

aws_secret_access_key = ''
#secret_access_key for AWS account: to unset, assign ''

aws_region_code = 'us-east-1'
#region code: to unset, assign ''
#make sure to select region which supports atleast 1 new VPC, 1 new Elastic IP
#and a valid NGFWv AmiID for deployment

#--------------------------------DEPLOYMENT_MODE-------------------------------#
#choose whether to deploy one or two stacks

deployment_mode = ''
#set to '1' to deploy only cluster stack over existing infrastructure stack
#set to anything else to deploy both infrastructure and cluster stacks
#when set to '1', make sure that an infrastructure stack has already been
#deployed with the same PRIME_INFRA_PARAMS as assigned in the below section

#------------------------------PRIME_INFRA_PARAMS------------------------------#
#parameters required in both the deployment modes
#these are used for creating infrastructure in DEFAULT_DEPLOYMENT mode,
#and to identify valid existing stack in CLUSTER_ONLY_DEPLOYMENT mode

infra_stack_name = 'cisco-infra'
#name of infrastructure stack
#used for infrastructure creation in DEFAULT_DEPLOYMENT mode,
#and for identifying existing infrastructure in CLUSTER_ONLY_DEPLOYMENT mode
#in the region specified in AWS_SESSION_PARAMS

use_gwlb = 'y'
#common parameter used for both the stacks
#In DEFAULT_DEPLOYMENT mode, decide if gateway load balancer is to be deployed:
#set to any string starting with 'y' or 'Y' to deploy gateway load balancer
#set to any other non-empty string, otherwise.
#In CLUSTER_ONLY_DEPLOYMENT mode, make sure the stack mentioned above was
#deployed in the region specified in AWS_SESSION_PARAMS, with the same use_gwlb
#value as assigned here,

#---------------INFRASTRUCTURE_STACK_PARAMS_FOR_POD_CONFIGURATION--------------#
#ignored in CLUSTER_ONLY_DEPLOYMENT mode
#to unset, assign ''

infra_prefix = 'cisco-infra'
#used in the names of infrastructure stack resources

infra_number = '1'
#used in the names of infrastructure stack resources

vpc_cidr = '10.0.0.0/16'
#vpc to deploy the cluster

availability_zone = 'us-east-1a'
#make sure its valid in the region selected

mgmt_subnet_name = 'ManagementSubnet'
#name of management subnet (with internet gateway as Route)

mgmt_subnet_cidr = '10.0.1.0/24'
#CIDR block for management subnet

inside_subnet_name = 'InsideSubnet'
#name of inside subnet (with private route)

inside_subnet_cidr = '10.0.2.0/24'
#CIDR block for inside subnet

outside_subnet_name = 'OutsideSubnet'
#name of outside subnet
#ignored if gateway load balancer is deployed

outside_subnet_cidr = '10.0.3.0/24'
#CIDR block of outside subnet
#ignored if gateway load balancer is deployed

ccl_subnet_name = 'CCLSubnet'
#name of CCL subnet

ccl_subnet_cidr = '10.0.4.0/24'
#CIDR block of CCL subnet

lambda_azs = 'us-east-1a,us-east-1b'
#comma seperated availability zones for Lambda Subnets
#enter exactly 2 zones

lambda_subnet_names = 'LambdaSubnet-1,LambdaSubnet-2'
#comma seperated subnet names for Lambda functions
#enter exactly 2 subnets

lambda_subnet_cidrs = '10.0.5.0/24,10.0.6.0/24'
#comma seperated subnet CIDRs for Lambda functions
#enter exactly 2 CIDR blocks

#--------------------------NGFWV_CLUSTER_STACK_PARAMS--------------------------#
#to unset, assign ''

ngfwv_stack_name = 'cisco-ngfw'
#name of the ngfw stack

#POD_CONFIGURATION

cluster_prefix = 'cisco-cluster'
#used in the names of NGFWv cluster stack resources

cluster_number = '1'
#used in the names of NGFWv cluster stack resources

cluster_size = '3'
#number of NGFWv instances in the cluster

email_for_notif = ''
#Ignored if empty ('')
#Email address to which CLuster Events Emails needs to be sent

#INFRSTRUCTURE_DETAILS

ccl_first = '10.0.4.4'
#CCL pool first IP

ccl_last = '10.0.4.254'
#CCL Pool last IP

#GWLB_CONFIGURATION

deploy_gwlbe = 'y'
#decide if gateway load balancer endpoint is to be deployed
#set to any string starting with 'y' or 'Y' to deploy gateway load balancer
#set to any other non-empty string, otherwise
#ignored if not using gateway load balancer

targetfailover = 'no_rebalance'
#With target failover, Gateway load balancer  handles existing traffic flows after a target becomes unhealthy or when the target is deregistered.
#You can manage these flows by either rehashing them (rebalance) or leaving them at the default state (no_rebalance).
#Enable Target Failover Support ("rebalance" or "no_rebalance").
#This feature is only supported on version 7.4.1 onwards.

gwlbe_vpc = 'Enter VPC ID for Gateway Load Balancer Endpoint.'
#Vpc Id for deploying gateway load balancer endpoint
#ignored if not using gateway load balancer or the endpoint

gwlbe_subnet = 'Enter Subnet ID for Gateway Load Balancer Endpoint.'
#Subnet Id for deploying load balancer endpoint
#ignored if not using gateway load balancer or the endpoint
#make sure it is present in gwlbe_vpc

health_port = '80'
#This port should not be used traffic by default
#ignored if not using gateway load balancer or the endpoint

#CISCO NGFWV INSTANCE CONFIGURATION

ngfwv_instance_type = 'c5.xlarge'
#choose one of 'c3.xlarge', 'c4.xlarge', 'c5.xlarge', 'c5.2xlarge', 'c5.4xlarge', 
#'c5d.xlarge', 'c5d.2xlarge', 'c5d.4xlarge', 'c5a.xlarge', 'c5a.2xlarge', 'c5a.4xlarge', 
#'c5ad.xlarge', 'c5ad.2xlarge', 'c5ad.4xlarge', 'c5n.xlarge', 'c5n.2xlarge', 'c5n.4xlarge', 
#'m5n.xlarge', 'm5n.2xlarge', 'm5n.4xlarge', 'm5zn.xlarge', 'm5zn.2xlarge'
#if gateway load balancer is not deployed, 'c5.4xlarge' will be forced
#make sure the instance type is supported in the region specified

ngfwv_ami_ID = 'ami-033dfrgbghyhhfuda'
#Ami Id used to launch FTDv instances: to unset, assign ''
#make sure this AMI has the status of 'available' in the selected region
#use the AMI with ENA type.

public_ip_assign = 'Yes'
#decide if NGFWv instances need a public IP
#set to any string starting with 'y' or 'Y' to use public IP for NGFWv instances
#set to any other non-empty string, otherwise

kms_arn = ''
#Ignored if empty
#ARN of an existing KMS (AWS KMS key to encrypt at rest)
#If specified, ngfw_passwd and fmc_passwd below should be encrypted Password
#The Password encryption should be done only using the specified ARN.
#Encryted passwords can be generated as:
#" aws kms encrypt --key-id <KMS ARN> --plaintext <password> "
#use such passwords for ngfwv_passwd if kms_arn is nonempty

ngfwv_passwd = 'Yu0rPass@344'
#plain text or KMS encrypted password, min length: 8

#FMC_AUTOMATION_CONFIGURATION

fmc_ip = '1.1.1.1'
#Leave this blank if FMC is to be deployed after infrastructure creation
#should be reachable from management subnet

fmc_uname = 'restuser'
#Unique Internal user for Cluster Manager automation tasks on FMC
#User should have roles system provided 'Network Admin' and 'Maintenance User'
#Refer 'Firepower Management Center Configuration Guide' for more details

fmc_passwd = 'Yu0rPass@344'
#if KMS ARN provided above, enter encrypted password
#otherwise, enter plaintext password

fmc_group_name = 'cisco-cluster'
#Device Group Name for FMC

#______________________________________________________________________________#
#package imports

import os
import builtins
import traceback
import sys
import platform
import subprocess

#______________________________________________________________________________#
#boto3 checking, install and import

try:
	import boto3
except:
	try:
		venv = "one_click_deploy_venv"
		activate_this_file = "./" + venv + "/bin/activate_this.py"
		exec(compile(open(activate_this_file, "rb").read(),
			activate_this_file, 'exec'), dict(__file__=activate_this_file))
	except:
		print(".. No boto3 package found ..")
		print(".. Creating virtual environment to install boto3 ..")
		f=os.popen("pip3 freeze | grep virtualenv" ).read()
		if f == '' :
			print(".. No virtualenv package found ..")
			print(".. Installing vitualenv ..")
			os.system("pip3 install virtualenv")
		venv = "one_click_deploy_venv"
		os.system("virtualenv " + venv)
		activate_this_file = "./" + venv + "/bin/activate_this.py"
		exec(compile(open(activate_this_file, "rb").read(),
			activate_this_file, 'exec'), dict(__file__=activate_this_file))
		os.system("pip3 install boto3")
	import boto3
from boto3.s3.transfer import S3Transfer
import botocore

#______________________________________________________________________________#
#cfn_flip checking, install and import

try:
	from cfn_tools import load_yaml, dump_yaml
except:
	print(".. No cfn-flip package found ..")
	os.system("pip3 install cfn_flip")
	from cfn_tools import load_yaml, dump_yaml

#______________________________________________________________________________#
#dummy object v

class Script:
    def __init__(self):
        pass
try:
    builtins.v
except:
    builtins.v = Script()

#______________________________________________________________________________#
#initiate AWS session

print("Getting AWS account details")

if aws_access_key_id == '':
	aki = str(input("Enter access key ID: "))
else:
	aki = aws_access_key_id
	print("Proceeding with the assigned value for access key ID")

if aws_secret_access_key == '':
	sak = str(input("Enter secret access key: "))
else:
	sak = aws_secret_access_key
	print("Proceeding with the assigned value for secret_access_key")

if aws_region_code == '':
	reg = str(input("Enter region code (such as 'us-east-1'): "))
else:
	reg = aws_region_code
	print("Proceeding with the assigned value for region code")

sflag = 0
while sflag == 0:
	try:
		print('Establishing AWS Session')
		session = boto3.Session(
			aws_access_key_id=aki,
			aws_secret_access_key=sak,
			region_name=reg)
		v.ec2_client = session.client('ec2')
		r = v.ec2_client.describe_vpcs()
		print('Success')
		sflag = 1
	except:
		print('Invalid credentials or region code')
		print('Try again or press CTRL+C to quit')
		aki = str(input("Enter access key ID: "))
		sak = str(input("Enter secret access key: "))
		reg = str(input("Enter region code (such as 'us-east-1'): "))

v.cf_template = session.client('cloudformation')
v.s3_resource = session.resource('s3')
v.s3_client = session.client('s3')
v.ec2_resource = session.resource('ec2')
v.iam = session.client('iam')

#______________________________________________________________________________#
#deploy infrastructure stack

while infra_stack_name == '':
	print("infra_stack_name cannot be left empty")
	infra_stack_name = str(input("Enter infrastructure stack name: "))

while use_gwlb == '':
	print('use_gwlb cant be left empty')
	use_gwlb = str(input("Do you want to use gateway load balancer? (y/n): "))

if use_gwlb[0] == 'y' or use_gwlb[0] == 'Y': use_gwlb = 'Yes'
else: use_gwlb = 'No'

if deployment_mode != '1':

    print('Executing in DEFAULT_DEPLOYMENT mode\n')

    req_params = [
    	['infra_prefix', infra_prefix, 'ClusterName'],
    	['infra_number', infra_number, 'ClusterNumber'],
    	['vpc_cidr', vpc_cidr, 'VpcCidr'],
    	['availability_zone', availability_zone, 'AZ'],
    	['use_gwlb', use_gwlb, 'UseGWLB'],
    	['mgmt_subet_name', mgmt_subnet_name, 'MgmtSubnetName'],
    	['mgmt_subnet_cidr', mgmt_subnet_cidr, 'MgmtSubnetCidr'],
    	['inside_subnet_name', inside_subnet_name, 'InsideSubnetName'],
    	['inside_subnet_cidr', inside_subnet_cidr, 'InsideSubnetCidr'],
    	['ccl_subnet_name', ccl_subnet_name, 'CCLSubnetName'],
    	['ccl_subnet_cidr', ccl_subnet_cidr, 'CCLSubnetCidr'],
    	['lambda_azs', lambda_azs, 'LambdaAZs'],
    	['lambda_subnet_names', lambda_subnet_names, 'LambdaSubnetName'],
    	['lambda_subnet_cidrs', lambda_subnet_cidrs, 'LambdaSubnetCidrs']
    ]

    cond_params = [
    	['outside_subnet_name', outside_subnet_name, 'OutsideSubnetName'],
    	['outside_subnet_cidr', outside_subnet_cidr, 'OutsideSubnetCidr']
    ]

    input_params = [
    	{ 'ParameterKey': 'NoOfAZs', 'ParameterValue': '1' }
    ]

    for i in range(len(req_params)):
    	while req_params[i][1] == '':
    		print('Parameter ' + req_params[i][0] + ' cannot be empty')
    		req_params[i][1] = str(input('Enter a valid value for '
    			+ req_params[i][0] + ': '))
    		if req_params[i][0] == 'availability_zone':
    			availability_zone = req_params[i][1]
    	input_params.append(
    		{
    			'ParameterKey': req_params[i][2],
    			'ParameterValue': req_params[i][1]
    		})

    if use_gwlb == 'No':
    	for i in range(len(cond_params)):
    		while cond_params[i][1] == '':
    			print('Parameter ' + cond_params[i][0] +
    				' cannot be empty if not using gateway load balancer')
    			cond_params[i][1] = str(input('Enter a valid value for '
    				+ cond_params[i][0] + ': '))
    		input_params.append(
    			{
    				'ParameterKey': cond_params[i][2],
    				'ParameterValue': cond_params[i][1]
    			})

    with open('infrastructure.yaml') as yaml_data: template = load_yaml(yaml_data)
    tbody = dump_yaml(template)
    print("\nParameters input for deployment: \n")
    for param in input_params:
    	print(param['ParameterKey'] + ': ' + param['ParameterValue'])
    print("\n")
    print("Deploying infrastructure stack..")

    params = {
    			'StackName': infra_stack_name,
             	'TemplateBody': tbody,
                'Capabilities':
    				[	'CAPABILITY_IAM',
    					'CAPABILITY_AUTO_EXPAND',
    					'CAPABILITY_NAMED_IAM'
    				],
    			'Parameters': input_params
             }

    try:
    	v.cf_template.create_stack(**params)

    except v.cf_template.exceptions.AlreadyExistsException:
    	exists = 1
    	while exists == 1:
    		print('Stack name already exists in the region')
    		print('Try again or press CTRL+C to quit')
    		infra_stack_name = str(input("Enter infrastructure stack name: "))
    		try:
    			params['StackName'] = infra_stack_name
    			v.cf_template.create_stack(**params)
    			exists = 0
    			print("Deploying infrastructure stack..")
    		except v.cf_template.exceptions.AlreadyExistsException:
    			pass

    except:
    	print("Unable to deploy infrastructure stack.\n{}".format(
    		traceback.format_exc()))

    waiter = v.cf_template.get_waiter('stack_create_complete')
    waiter.wait(StackName=infra_stack_name)
    print("Infrastructure stack deployment complete")

    #__________________________________________________________________________#
    #upload to s3 bucket

    r = v.cf_template.describe_stack_resource(
    	StackName = infra_stack_name,
    	LogicalResourceId = 'S3bucketCluster'
    )
    v.bucketname = r['StackResourceDetail']['PhysicalResourceId']

    print('Uploding cluster_manager.zip')
    response = v.s3_client.upload_file('cluster_manager.zip', v.bucketname,
    	'cluster_manager.zip')
    print("Upload Complete")

    print('Uploding cluster_layer.zip')
    response = v.s3_client.upload_file('cluster_layer.zip', v.bucketname,
    	'cluster_layer.zip')
    print("Upload Complete")

    print('Uploding cluster_lifecycle.zip')
    response = v.s3_client.upload_file('cluster_lifecycle.zip', v.bucketname,
    	'cluster_lifecycle.zip')
    print("Upload Complete")

    if fmc_ip == '':
    	print('\nfmc_ip is empty')
    	print("If FMC is available now, press Enter and enter fmc_ip when asked")
    	print("\nOtherwise, the user has two options:")
    	print("1. Keep this process running but waiting until FMC is deployed")
    	print("\tPress 'Enter' once the FMC is available, process will continue")
    	print("\tAfter that, user will be asked to enter the FMC IP ")
    	print("2. Press CTRL+C to terminate this process")
    	print("\tAfter the FMC is deployed, rerun this script after changing only:")
    	print("\ta. deployment_mode = '1' in DEPLOYMENT_MODE section")
    	print("\tb. fmc_ip = '<FMC_IP_ADDRESS>' in NGFWV_CLUSTER_STACK_PARAMS")
    	print("\tc. any other required changes in the NGFWV_CLUSTER_STACK_PARAMS")
    	print("\t   but not other sections")
    	print("\nPress 'Enter' to choose (1) and continue OR")
    	input("Press 'CTRL+C' to choose (2) and quit")
    	while fmc_ip == '':
    		fmc_ip = str(input("Enter fmc_ip: "))
    else:
    	print("Proceeding to cluster deployment using the assigned fmc_ip: " + fmc_ip)

#______________________________________________________________________________#
#prepare input_params for ngfw stack

if deployment_mode == '1':
    print('Executing in CLUSTER_ONLY_DEPLOYMENT mode')

while ngfwv_stack_name == '':
	print("ngfwv_stack_name cannot be left empty")
	ngfwv_stack_name = str(input("Enter NGFWv stack name: "))

if use_gwlb == 'No':
	deploy_gwlbe = 'No'
	print("Instance type set to c5.4xlarge as load balancer isn't deployed")
	ngfwv_instance_type = 'c5.4xlarge'

while deploy_gwlbe == '':
	print('deploy_gwlbe cant be left empty')
	deploy_gwlbe = str(input(
		"Do you want to deploy gateway load balancer endpoint? (y/n): "))

if deploy_gwlbe[0] == 'y' or deploy_gwlbe[0] == 'Y': deploy_gwlbe = 'Yes'
else: deploy_gwlbe = 'No'

while public_ip_assign == '':
	print('public_ip_assign cant be left empty')
	public_ip_assign = str(input(
		"Do you want to use gateway load balancer? (y/n): "))

if public_ip_assign[0] == 'y' or public_ip_assign[0] == 'Y':
	public_ip_assign = 'true'
else: public_ip_assign = 'false'

valid_itypes = [
	'c3.xlarge', 'c4.xlarge', 'c5.xlarge', 'c5.2xlarge', 'c5.4xlarge', 'c5d.xlarge', 'c5d.2xlarge', 'c5d.4xlarge', 'c5a.xlarge', 'c5a.2xlarge', 'c5a.4xlarge', 'c5ad.xlarge', 'c5ad.2xlarge', 'c5ad.4xlarge', 'c5n.xlarge', 'c5n.2xlarge', 'c5n.4xlarge', 'm5n.xlarge', 'm5n.2xlarge', 'm5n.4xlarge', 'm5zn.xlarge', 'm5zn.2xlarge'
	]

while ngfwv_instance_type not in valid_itypes:
	print('Invalid value for ngfwv_instance_type')
	print('Enter the instance type of NGFWv to be deployed\nEnter one of')
	nngfwv_instance_type = str(input(
		"c3.xlarge, c4.xlarge, c5.xlarge, c5.2xlarge, c5.4xlarge, c5d.xlarge, c5d.2xlarge, c5d.4xlarge, c5a.xlarge, c5a.2xlarge, c5a.4xlarge, c5ad.xlarge, c5ad.2xlarge, c5ad.4xlarge, c5n.xlarge, c5n.2xlarge, c5n.4xlarge, m5n.xlarge, m5n.2xlarge, m5n.4xlarge, m5zn.xlarge, m5zn.2xlarge: "))

empty_ok_params = [
	['email_for_notif', email_for_notif, 'NotifyEmailID'],
	['kms_arn', kms_arn, 'KmsArn']
]

req_params = [
	['cluster_prefix', cluster_prefix, 'ClusterGrpNamePrefix'],
	['cluster_number', cluster_number, 'ClusterNumber'],
	['cluster_size', cluster_size, 'ClusterSize'],
	['deploy_gwlbe', deploy_gwlbe, 'DeployGWLBE'],
	['targetfailover', targetfailover, 'TargetFailover'],
	['availability_zone', availability_zone, 'AZ'],
	['ccl_first', ccl_first, 'CCLfirstIP'],
	['ccl_last', ccl_last, 'CCLlastIP'],
	['ngfwv_instance_type', ngfwv_instance_type, 'InstanceType'],
	['ngfwv_ami_ID', ngfwv_ami_ID, 'AmiID'],
	['public_ip_assign', public_ip_assign, 'AssignPublicIP'],
	['ngfwv_passwd', ngfwv_passwd, 'ngfwPassword'],
	['fmc_ip', fmc_ip, 'fmcServer'],
	['fmc_uname', fmc_uname, 'fmcOperationsUsername'],
	['fmc_passwd', fmc_passwd, 'fmcOperationsPassword'],
	['fmc_group_name', fmc_group_name, 'fmcDeviceGrpName']
]

cond_params = [
	['gwlbe_vpc', gwlbe_vpc, 'VpcIdLBE'],
	['gwlbe-subnet', gwlbe_subnet, 'GWLBESubnetId']
]

input_params = [
	{ 'ParameterKey': 'UseGWLB', 'ParameterValue': use_gwlb }
]


for p in empty_ok_params:
	input_params.append(
		{
			'ParameterKey': p[2],
			'ParameterValue': p[1]
		})

if use_gwlb == 'Yes':
    input_params.append(
        {
            'ParameterKey': 'TgHealthPort',
            'ParameterValue': health_port
        })

for i in range(len(req_params)):
	while req_params[i][1] == '':
		print('Parameter ' + req_params[i][0] + ' cannot be empty')
		req_params[i][1] = str(input('Enter a valid value for '
			+ req_params[i][0] + ': '))
		if req_params[i][0] == 'availability_zone':
			availability_zone = req_params[i][1]
	input_params.append(
		{
			'ParameterKey': req_params[i][2],
			'ParameterValue': req_params[i][1]
		})

if deploy_gwlbe == 'Yes':
	for i in range(len(cond_params)):
		while cond_params[i][1] == '':
			print('Parameter ' + cond_params[i][0] +
				' cannot be empty if using gateway load balancer endpoint')
			cond_params[i][1] = str(input('Enter a valid value for '
				+ cond_params[i][0] + ': '))
		input_params.append(
			{
				'ParameterKey': cond_params[i][2],
				'ParameterValue': cond_params[i][1]
			})

#independent params

in_int_sg = 'InsideInterfaceSGwithoutGWLB'
if use_gwlb == 'Yes':
	in_int_sg = 'InsideInterfaceSGwithGWLB'
else:
	r = v.cf_template.describe_stack_resource(
		StackName = infra_stack_name,
		LogicalResourceId = 'subnetOutside0'
	)
	pv = r['StackResourceDetail']['PhysicalResourceId']
	input_params.append({'ParameterKey' : 'OutsideSubnetId',
		'ParameterValue' : pv })
	r = v.cf_template.describe_stack_resource(
		StackName = infra_stack_name,
		LogicalResourceId = 'OutsideInterfaceSG'
	)
	pv = r['StackResourceDetail']['PhysicalResourceId']
	input_params.append({'ParameterKey' : 'OutsideInterfaceSG',
		'ParameterValue' : pv })

cluster_to_infra_mappings = {
	 'VpcId' : 'VpcCluster',
	 'S3BktName' : 'S3bucketCluster',
	 'LambdaSubnets' : ['subnetLambda0','subnetLambda1'],
	 'LambdaSG' : 'LambdaSecurityGroup',
	 'MgmtSubnetId' : 'subnetMgmt0',
	 'InsideSubnetId' : 'subnetInside0',
	 'CCLSubnetId' : 'subnetCCL0',
	 'MgmtInterfaceSG' : 'InstanceSG',
	 'InsideInterfaceSG' : in_int_sg,
	 'CCLInterfaceSG' : 'CCLInterfaceSG'
}

def append_to_params(a):
	c = cluster_to_infra_mappings[a]
	if isinstance(c, str):
		r = v.cf_template.describe_stack_resource(
		    StackName = infra_stack_name,
		    LogicalResourceId = c
		)
		pv = r['StackResourceDetail']['PhysicalResourceId']
	else:
		pv = ''
		for ca in c:
			r = v.cf_template.describe_stack_resource(
			    StackName = infra_stack_name,
			    LogicalResourceId = ca
			)
			pva = r['StackResourceDetail']['PhysicalResourceId']
			if pv == '': pv = pva
			else: pv = pv + ',' + pva
	input_params.append({'ParameterKey' : a, 'ParameterValue' : pv })

#params requiring ids of resources from infrastructure stack
for k in cluster_to_infra_mappings:
	append_to_params(k)

print("\nAuto-generated parameters input for deployment: \n")
for param in input_params:
	print(param['ParameterKey'] + ': ' + param['ParameterValue'])
print("\n")

#______________________________________________________________________________#
#deploy ngfw stack

with open('deploy_ngfw_cluster.yaml') as yaml_data:
	template = load_yaml(yaml_data)
tbody = dump_yaml(template)

if email_for_notif != '':
    print("Please lookout for a subscription confirmation mail in the account")
    print(email_for_notif)
    print("Sender: AWS Notifications")
    print("Mail Subject: AWS-Notification - Subscription Confirmation")
    print("Click on the subscription confirmation link to start recieving")
    print("cluster event notifications\n")

print("Deploying NGFWv Stack")

params = {
			'StackName': ngfwv_stack_name,
         	'TemplateBody': tbody,
            'Capabilities':
				[	'CAPABILITY_IAM',
					'CAPABILITY_AUTO_EXPAND',
					'CAPABILITY_NAMED_IAM'
				],
			'Parameters': input_params
         }

try:
	v.cf_template.create_stack(**params)

except v.cf_template.exceptions.AlreadyExistsException:
	exists = 1
	while exists == 1:
		print('Stack name already exists in the region')
		print('Try again or press CTRL+C to quit')
		ngfwv_stack_name = str(input("Enter NGFWv stack name: "))
		try:
			params['StackName'] = ngfwv_stack_name
			v.cf_template.create_stack(**params)
			exists = 0
			print("Deploying NGFWv stack..")
		except v.cf_template.exceptions.AlreadyExistsException:
			pass

except:
	print("Unable to deploy NGFWv stack.\n{}".format(
		traceback.format_exc()))

waiter = v.cf_template.get_waiter('stack_create_complete')
waiter.wait(StackName=ngfwv_stack_name)
print("NGFWv stack deployment complete")
