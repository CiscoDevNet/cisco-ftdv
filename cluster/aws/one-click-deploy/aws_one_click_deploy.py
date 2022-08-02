'''

Single click deployment for Cisco NGFWv Clustering for AWS

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

aws_region_code = 'ap-northeast-3'
#region code: to unset, assign ''
#make sure to select region which supports atleast 1 new VPC, 1 new Elastic IP
#and a valid NGFWv AmiID for deployment

#---------------INFRASTRUCTURE_STACK_PARAMS_FOR_POD_CONFIGURATION--------------#
#to unset, assign ''

infra_stack_name = 'neo-cls-infra-yn'
#name of infrastructure stack

pod_name = 'infrastructure'
#used in the names of infrastructure stack resources

pod_number = '1'
#used in the names of infrastructure stack resources

vpc_cidr = '10.2.0.0/16'
#vpc to deploy the cluster

availability_zone = 'ap-northeast-3a'
#make sure its valid in the region selected

use_gwlb = 'y'
#decide if gateway load balancer is to be deployed: to unset, assign ''
#set to any string starting with 'y' or 'Y' to deploy gateway load balancer
#set to any other non-empty string, otherwise

mgmt_subnet_name = 'ManagementSubnet'
#name of management subnet (with internet gateway as Route)

mgmt_subnet_cidr = '10.2.250.0/24'
#CIDR block for management subnet

inside_subnet_name = 'InsideSubnet'
#name of inside subnet (with private route)

inside_subnet_cidr = '10.2.100.0/24'
#CIDR block for inside subnet

outside_subnet_name = 'OutsideSubnet'
#name of outside subnet
#ignored if gateway load balancer is deployed

outside_subnet_cidr = '10.2.200.0/24'
#CIDR block of outside subnet
#ignored if gateway load balancer is deployed

ccl_subnet_name = 'CCLSubnet'
#name of CCL subnet

ccl_subnet_cidr = '10.2.90.0/24'
#CIDR block of CCL subnet

lambda_azs = 'ap-northeast-3a,ap-northeast-3b'
#comma seperated availability zones for Lambda Subnets
#enter exactly 2 zones

lambda_subnet_names = 'LambdaSubnet-1,LambdaSubnet-2'
#comma seperated subnet names for Lambda functions
#enter exactly 2 subnets

lambda_subnet_cidrs = '10.2.50.0/24,10.2.51.0/24'
#comma seperated subnet CIDRs for Lambda functions
#enter exactly 2 CIDR blocks

app_subnet_name = 'AppSubnet'
#name of Application subnet (with private route)

app_subnet_cidr = '10.2.70.0/24'
#CIDR block for application subnet

#--------------------------NGFWV_CLUSTER_STACK_PARAMS--------------------------#
#to unset, assign ''

ngfwv_stack_name = 'neo-cls-ngfw-yn'
#name of the ngfw stack

#POD_CONFIGURATION

cluster_prefix = 'NGFWv-Clustering'
#used in the names of NGFWv cluster stack resources

cluster_podnum = '1'
#used in the names of NGFWv cluster stack resources

email_for_notif = ''
#Ignored if empty ('')
#Email address to which CLuster Events Emails needs to be sent

#INFRSTRUCTURE_DETAILS

ccl_first = '10.2.90.4'
#CCL pool first IP

ccl_last = '10.2.90.254'
#CCL Pool last IP

#GWLB_CONFIGURATION

deploy_gwlbe = 'n'
#decide if gateway load balancer endpoint is to be deployed
#set to any string starting with 'y' or 'Y' to deploy gateway load balancer
#set to any other non-empty string, otherwise
#ignored if not using gateway load balancer

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

ngfwv_instance_type = 'c5.4xlarge'
#choose one of 'c3.xlarge', 'c4.xlarge', 'c5.xlarge', 'c5.2xlarge', 'c5.4xlarge'
#if gateway load balancer is not deployed, 'c5.4xlarge' will be forced
#make sure the instance type is supported in the region specified

ngfwv_ami_ID = 'ami-0980f05af85a4b216'
#Ami Id used to launch FTDv instances: to unset, assign ''
#make sure this AMI has the status of 'available' in the selected region
#to use the AMI with name 'ftdv-7.2.0-1365-ENA' use the ami IDs:
#'ami-0265b4bbf47bd0171' for region code: 'me-south-1' (Bahrain)
#'ami-0e94f6226b069e2cc' for region code: 'ap-northeast-2' (Seoul)
#'ami-0980f05af85a4b216' for region code: 'ap-northeast-3' (Osaka)
#'ami-06d759781d0672de4' for region code: 'ap-south-1' (Mumbai)
#'ami-029254ef480d17e57' for region code: 'ap-southeast-2' (Sydney)

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

ngfwv_passwd = 'Cisco@123123'
#plain text or KMS encrypted password, min length: 8

#FMC_AUTOMATION_CONFIGURATION

fmc_ip = '10.2.1.5'
#should be reachable from management subnet

fmc_uname = 'CiscoUser'
#Unique Internal user for Cluster Manager automation tasks on FMC
#User should have roles system provided 'Network Admin' and 'Maintenance User'
#Refer 'Firepower Management Center Configuration Guide' for more details

fmc_passwd = 'Cisco@123123'
#if KMS ARN provided above, enter encrypted password
#otherwise, enter plaintext password

fmc_group_name = 'ftdvcluster'
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

req_params = [
	['pod_name', pod_name, 'PodName'],
	['pod_number', pod_number, 'PodNumber'],
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
	['lambda_subnet_cidrs', lambda_subnet_cidrs, 'LambdaSubnetCidrs'],
	['app_subnet_name', app_subnet_name, 'ApplicationSubnetName'],
	['app_subnet_cidr', app_subnet_cidr, 'ApplicationSubnetCidr']
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

#______________________________________________________________________________#
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

#______________________________________________________________________________#
#prepare input_params for ngfw stack

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
	'c3.xlarge', 'c4.xlarge', 'c5.xlarge', 'c5.2xlarge', 'c5.4xlarge'
	]

while ngfwv_instance_type not in valid_itypes:
	print('Invalid value for ngfwv_instance_type')
	print('Enter the instance type of NGFWv to be deployed\nEnter one of')
	nngfwv_instance_type = str(input(
		"c3.xlarge, c4.xlarge, c5.xlarge, c5.2xlarge, c5.4xlarge: "))

empty_ok_params = [
	['email_for_notif', email_for_notif, 'NotifyEmailID'],
	['kms_arn', kms_arn, 'KmsArn']
]

req_params = [
	['cluster_prefix', cluster_prefix, 'ClusterGrpNamePrefix'],
	['cluster_podnum', cluster_podnum, 'PodNumber'],
	['deploy_gwlbe', deploy_gwlbe, 'DeployGWLBE'],
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
	['gwlbe-subnet', gwlbe_subnet, 'GWLBESubnetId'],
	['health_port', health_port, 'TgHealthPort'],
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
