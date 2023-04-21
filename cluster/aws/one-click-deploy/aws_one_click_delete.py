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

Single click delete for Cisco NGFWv Cluster Stacks for AWS

System requirements: macOS/Linux/Windows machine with python3 (and hence pip3)
	command working

Remarks:
	boto3 if not already installed will be installed to a virtual environment
	in that case, virtualenv if not already installed wil be installed by pip3
	cfn_flip if not already installed will be installed by pip3

'''

#----------------------SET_PARAMETERS_FOR_ONE_CLICK_DELETE---------------------#

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

#--------------------------------STACK_PARAMS----------------------------------#
#to unset, assign ''

ngfwv_stack_name = 'cisco-ngfw'
#name of the ngfw stack

infra_stack_name = 'cisco-infra'
#name of infrastructure stack

control_delete = '4'
#set to '1' to delete only NGFWv stack
#set to '2' to delete NGFWv stack and empty s3 bucket of infrastructure stack
#set to '3' to delete NGFWv stack, s3 bucket, and infrastructure stack
#set to '4' to delete NGFWv stack, s3 bucket, infrastructure stack and the
#virtual environment 'one_click_deploy_venv' created locally during deployment

#the virtual enviroment will be installed again during deployment if deleted
#if the system does not have boto3 installed

#______________________________________________________________________________#
#package imports

import os
import traceback
import builtins
import sys
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
v.s3 = session.resource('s3')

#______________________________________________________________________________#
#delete stacks

while control_delete not in ['1','2','3','4']:
	print('control_delete set to invalid value')
	print('Enter 1 to delete only infrastructure stack')
	print('Enter 2 to delete infrastructure stack and empty the s3 bucket' +
		'created during deployment')
	print('Enter 3 to delete NGFWv stack, s3 bucket, and infrastructure stack')
	control_delete = str(input(
		"Enter 4 to delete NGFWv stack, s3 bucket, infrastructure stack" +
		" and the local virtual environment 'one_click_deploy_venv': "
	))

while ngfwv_stack_name == '':
	print("ngfwv_stack_name cannot be left empty")
	ngfwv_stack_name = str(input("Enter NGFWv stack name: "))
input('press enter to delete stack: ' + ngfwv_stack_name + ' or CTRL+C to quit')

v.cf_template.delete_stack(StackName=ngfwv_stack_name)

if control_delete != '1':
	while infra_stack_name == '':
		print("infra_stack_name cannot be left empty")
		infra_stack_name = str(input("Enter infrastructure stack name: "))
	r = v.cf_template.describe_stack_resource(
		StackName = infra_stack_name,
		LogicalResourceId = 'S3bucketCluster'
	)
	bucket_name = r['StackResourceDetail']['PhysicalResourceId']
	s3_bucket = v.s3.Bucket(bucket_name)
	input('press enter to empty bucket: ' + bucket_name + ' or CTRL+C to quit')
	bucket_versioning = v.s3.BucketVersioning(bucket_name)
	if bucket_versioning.status == 'Enabled':
	    r = s3_bucket.object_versions.delete()
	else:
	    r = s3_bucket.objects.all().delete()
	if r:
		print('Bucket emptied succesfully')

waiter = v.cf_template.get_waiter('stack_delete_complete')
waiter.wait(StackName=ngfwv_stack_name)
print('NGFWv stack deleted succesfully')
if control_delete == '1' or control_delete == '2':
	sys.exit(0)

input('press enter to delete stack: ' + infra_stack_name + ' or CTRL+C to quit')
v.cf_template.delete_stack(StackName=infra_stack_name)
waiter = v.cf_template.get_waiter('stack_delete_complete')
waiter.wait(StackName=infra_stack_name)
print('Infrastructure stack deleted succesfully')

if control_delete == '4':
	os.system('rm -r one_click_deploy_venv')
	print('virtual environment removed succesfully')
