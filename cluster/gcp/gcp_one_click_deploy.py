"""
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
Name:       gcp_one_click_deploy.py
Purpose:    This python file has user input based script for deploying
            Cloud Infrastructure, Cloud Function and multi-node FTDv Cluster.
"""

'''

Single click deployment for Cisco NGFWv Clustering for GCP

DEFAULT DEPLOYMENT mode:

This script deploys all required infrastructure first.
(1) If the fmc_ip is assigned a non-empty string, then that value will be
    used for function deployment, after which cluster is deployed.
	fmc_ip should be assigned a value only if FMC is already deployed, or to be
	deployed with the fixed assigned IP.
	If the user plans to deploy the FMC after infrastructure creation, the
	fmc_ip parameter must be left blank
(2) If fmc_ip is empty (''), user will be given 2 options-
   	(a) Leave the script running but waiting until user enters the fmc_ip. In
	    this time, FMC can be deployed, after which fmc_ip and any parameter
		left empty in the GOOGLE_FUNCTION_PARAMS and CLUSTER_DEPLOYMENT_PARAMS
		can be entered.
	    After this, the script will continue and deploy the funtion and cluster.
	(b) Exit the execution, use CONTROLLED DEPLOYMENT-1 after FMC deployment

CONTROLLED DEPLOYMENT mode:

To override deafault behavior, use parameters in CONTROL_DEPLOYMENT section
(1) in CONTROLLED DEPLOYMENT-1 mode:
	only function and cluster is created using the COMMON_PARAMS,
	GOOGLE_FUNCTION_PARAMS and CLUSTER_DEPLOYMENT_PARAMS
(2) in CONTROLLED DEPLOYMENT-2 mode, only cluster is created using the
	COMMON_PARAMS and CLUSTER_DEPLOYMENT_PARAMS
	see the CONTROL_DEPLOYMENT section parameters for setting the mode

System requirements: macOS/Linux/Windows machine with
	(1)	python3 (and hence pip3) command working
	(2) google cloud SDK installed: gcloud and gsutil commands working
		(can be checked with 'gcloud --version' and 'gsutil --version')
	(3) If the machine is Windows: the contents of cluster-function should
	    be compressed to ftdv_cluster_function.zip (donot include the
		cluster-function directory in the zip file - include only its contents)
		and kept in the same directory as this script

GCP side requirements: google cloud SDK is properly configured -
	(1) 'gcould init' has run atleast once before running this script
	(2) project name for the deployment is set as required (can be checked
		by running 'gcloud init')

'''

#-------------------SET_PARAMETERS_FOR_ONE_CLICK_DEPLOYMENT--------------------#

#Parameters can be assigned values here
#all parameters are strings, have to be assigned values under quotes ('' or "")
#if parameters are unset (assigned '') but required during execution,
#user will be prompted for input
#to unset, assign ''

#------------------------------CONTROL_DEPLOYMENT------------------------------#
#Override deafult behavior here

#CONTROLLED DEPLOYMENT-1
deploy_only_function_and_cluster = ''
#if set to '1', make sure that a function bucket, infrastructure deployment and
#vpc connector has already been created with the same "COMMON_PARAMS" as
#assigned in the below section, through this script
#this parameter is treated as empty ('') if set to anything other than '1'

#CONTROLLED DEPLOYMENT-2
deploy_only_cluster = ''
#ignored if deploy_function_and_cluster set to '1'
#if set to '1', make sure that a function bucket, infrastructure deployment,
#vpc connector and function deployment has already been created with the same
#"COMMON_PARAMS" as assigned in the below section, through this script
#this parameter is treated as empty ('') if set to anything other than '1'

#---------------------------------COMMON_PARAMS--------------------------------#
#These params are required for infrastructure, function and cluster deployments

resource_prefix = 'oneclicktest' #restricted to single word 
#prefix for all the resources to be created (or already existing if
#'deploy_only_function_and_cluster' set to '1' or deploy_only_cluster
#set to '1') by the infrastructure, function and cluster deployment

region = 'us-central1'
#region code for deploying the cluster

zonecode = 'c'
#zone code for deploying the cluster

mail_id = '340375726592-compute@developer.gserviceaccount.com'
#mail ID of either the default service account for compute engine -
#of the form : '<project-number>-compute@developer.gserviceaccount.com'
#or any other service account with relevant permissions

#-----------------------INFRASTRUCTURE_DEPLOYMENT_PARAMS-----------------------#

infra_deployment_name = resource_prefix + '-infra'
#name of the infrastructure deployment

#VPC CIDR params

mgmt_cidr = '10.10.71.0/24'
#CIDR block for management VPC
mgmt_cidr28 = '10.10.0.0/28'
#CIDR block for management vpc connector
diag_cidr = '10.10.72.0/24'
#CIDR block for diagnostic VPC
in_cidr = '10.10.73.0/24'
#CIDR block for inside VPC
out_cidr = '10.10.74.0/24'
#CIDR block for outside VPC
ccl_cidr = '10.10.75.0/24'
#CIDR block for CCL VPC


#----------------------------GOOGLE_FUNCTION_PARAMS----------------------------#
#Environment variables for Google Function

function_deployment_name = resource_prefix + '-function'

#leave the fmc_ip empty if FMC cannot be deployed with a pre-decided IP,
#or to be deployed after infrastructure creation
#leave any other parameter empty if it cannot be determined now
#any parameter left empty will be asked for, during execution

fmc_ip = ''
#FMC ip address - leave this empty ('') if FMC is to yet to be deployed
#This field will be asked for only if left empty
######## Uncomment below lines [58-62] in north-south/deploy_ngfw_cluster.jinja for deploying with public/external IP #######
          #accessConfigs:
          #- kind: compute#accessConfig
            #name: External NAT
            #type: ONE_TO_ONE_NAT
            #networkTier: PREMIUM
########################## After uncommenting make sure 'deploy_with_externalIP' set as True ################################
deploy_with_externalIP = 'False' #default is FTDv with only private IP
# False: only private IP required for FTDv: make sure FMC should be available in same private network.
retry_count = '10' #allowed range >=6 (Min 6 retry_count required for 4-nodes cluster and 10 retry_count required for 16-nodes cluster)
#auto-registration google function ececution retry count
registration_id = 'cisco'
#for registration to FMC
nat_id = 'cisco'
#for registration to FMC
cluster_grp_name = 'oneclicktest-cluster'
#for registration to FMC
policy_id = 'ftdv-acl-policy'
#for registration to FMC
fmc_passwd = 'Cisco@123123'
#password for FMC
fmc_uname = 'testuser'
#username for FMC
ftdv_passwd = 'Cisco@123123'
#password for FTDv
license_list = 'BASE,MALWARE,URLFilter,THREAT'
#list of linceses for FTDv
perf_tier = 'FTDv50'
#performance tier linceses for FTDv

#--------------------------CLUSTER_DEPLOYMENT_PARAMS---------------------------#

cluster_deployment_name = resource_prefix + '-cluster'
#name of the NGFWv-cluster deployment

#day0 startup-script input params

admin_passwd = 'Cisco@123123'
#ftdv admin password
host_name = 'ciscoftdv'
#ftdv hostname
ccl_range = '10.10.75.2 10.10.75.253'
#space seperated first and last ips for ccl subnet, allowed range is x.x.x.2 x.x.x.253

#FTDv instance template params

machine_type = 'e2-standard-8'
#FTDv machine type
src_img_url = 'projects/asavgcp-poc-4krn/global/images/cisco-secure-firewall-threat-defense-virtual-gcp-7-2-0-1553'
#source image url for FTDv instance template

#FTDv Autoscaled cluster params

cpu_util = '0.8'
#cpu utilization expressed in 0 to 1 range
ftdv_count = '4'
#number of ftdv replicas in cluster allowed range 1-16

#ELB Service params

elb_port = '80'
#port number for elb services
elb_port_name = 'tcp'
#port name for elb services
elb_protocol = 'TCP'
#protocol for elb services
elb_timeout = '5'
#timeout in seconds for elb sevices
elb_health_protocol = 'TCP'
#healthcheck protocol for elb services
elb_threshold = '10'
#unhealthy threshold count for elb services, allowed range 1-10
elb_rule_protocol = 'TCP'
#forwarding rule protocol for elb services
elb_rule_ports = '[80,443,22]'
#forwarding rule ports for elb services

#ILB Service params

ilb_protocol = 'TCP'
#protocol for ilb services
ilb_drain_timeout = '60'
#draining timeout in seconds for ilb services
ilb_port = '80'
#port number for ilb services
ilb_check_interval = '10'
#check interval in seconds for ilb services
ilb_timeout = '5'
#timeout in seconds for ilb services
ilb_health_protocol = 'TCP'
#healthcheck protocol for ilb services
ilb_threshold = '10'
#unhealthy threshold count for ilb services, allowed range 1-10

#______________________________________________________________________________#
#package imports

import os
import ipaddress
import platform

#______________________________________________________________________________#

while resource_prefix == '':
	print("resource_prefix cannot be left empty")
	resource_prefix = str(input("Enter resource_prefix: "))

while region == '':
	print("region cannot be left empty")
	region = str(input("Enter region: "))

while mail_id == '':
	print("mail_id cannot be left empty")
	mail_id = str(input("Enter mail_id: "))

#override deploy_only_ngfwv_cluster if deploy_function_and_cluster is set
if deploy_only_function_and_cluster == '1':
	deploy_only_cluster = ''

#set some parameters
bucket_name = resource_prefix + '-ftdv-cluster-bucket'
connector_name = resource_prefix + '-ssh'
subnet28 = resource_prefix + '-ftdv-mgmt-subnet28'

if deploy_only_function_and_cluster != '1' and deploy_only_cluster != '1':

	#__________________________________________________________________________#
	#create zip, google bucket and upload zip
	print("Executing in Default Deployment Mode..")

	if platform.system() != 'Windows':
		os.system('zip -j ftdv_cluster_function.zip ./cluster-function/*')
	os.system('gsutil mb --pap enforced gs://' + bucket_name + '/')
	os.system('gsutil cp ftdv_cluster_function.zip gs://' + bucket_name)

	#__________________________________________________________________________#
	#deploy infrastructure and conector

	delim = '^!@#^'
	if platform.system() == 'Windows':
		delim = '^^!@#^^'

	while infra_deployment_name == '':
		print("infra_deployment_name cannot be left empty")
		infra_deployment_name = str(input(
			"Enter infrastructure_deployment_name: "))

	def get_gip(cidr):
		n = ipaddress.IPv4Network(cidr)
		return str(n[1])

	silent_params = [
		[ 'mgmtVpcRoutingMode', 'GLOBAL' ],
		[ 'mgmtGatewayAddress', get_gip(mgmt_cidr) ],
		[ 'diagVpcRoutingMode', 'GLOBAL'],
		[ 'diagGatewayAddress', get_gip(diag_cidr) ],
		[ 'insideVpcRoutingMode', 'GLOBAL' ],
		[ 'insideGatewayAddress', get_gip(in_cidr) ],
		[ 'outsideVpcRoutingMode', 'GLOBAL' ],
		[ 'outsideGatewayAddress', get_gip(out_cidr) ],
		[ 'cclVpcRoutingMode', 'GLOBAL' ],
		[ 'cclGatewayAddress', get_gip(ccl_cidr) ],
	]

	infra_params = [
		[ 'mail_id', 'serviceAccountMailId', mail_id ],
	    [ 'region', 'region', region ],
	    [ 'resource_prefix', 'resourceNamePrefix', resource_prefix ],
	    [ 'mgmt_cidr', 'mgmtIpCidrRange', mgmt_cidr ],
	    [ 'mgmt_cidr28', 'vpcConnectorIpCidrRange', mgmt_cidr28 ],
	    [ 'diag_cidr', 'diagIpCidrRange', diag_cidr ],
	    [ 'in_cidr', 'insideIpCidrRange', in_cidr ],
	    [ 'out_cidr', 'outsideIpCidrRange', out_cidr ],
	    [ 'ccl_cidr', 'cclIpCidrRange', ccl_cidr ]
	]

	pstr = ''

	for p in silent_params:
		if pstr == '':
			pstr = p[0] + ':' + p[1]
		else:
			pstr = pstr + '!@#' + p[0] + ':' + p[1]

	for p in infra_params:
		while p[2] == '':
			print('Parameter ' + p[0] + ' cannot be empty')
			p[2] = str(input('Enter a valid value for ' + p[0] + ': '))
		pstr = pstr + '!@#' + p[1] + ':' + p[2]


	os.system('gcloud deployment-manager deployments create ' +
		infra_deployment_name +
		' --template infrastructure.jinja --properties ' + delim + pstr)

	print("Infrastructure deployment complete, creating connector now")

	os.system('gcloud compute networks vpc-access connectors create ' +
		connector_name + ' --region ' + region + ' --subnet ' + subnet28)

	print("Bucket, infrastructure and connector creation complete")
	if fmc_ip == '':
		print('fmc_ip is empty')
		print("If FMC is available now, press Enter and enter fmc_ip when asked")
		print("Otherwise, the user has two options:")
		print("1. Keep this process running but waiting until FMC is deployed")
		print("\tPress 'Enter' once the FMC is available, process will continue")
		print("\tAfter that, user will be asked to enter the FMC IP ")
		print("2. Press CTRL+C to terminate this process")
		print("\tAfter the FMC is deployed, rerun this script after changing only:")
		print("\ta. deploy_only_function_and_cluster = '1' in CONTROL_DEPLOYMENT")
		print("\tb. fmc_ip = '<FMC_IP_ADDRESS>' in GOOGLE_FUNCTION_PARAMS")
		print("\tc. any other required changes in the GOOGLE_FUNCTION_PARAMS and")
		print("\t   CLUSTER_DEPLOYMENT_PARAMS section but not other sections")
		print("\nPress 'Enter' to choose (1) and continue OR")
		input("Press 'CTRL+C' to choose (2) and quit")
		while fmc_ip == '':
			fmc_ip = str(input("Enter fmc_ip: "))

	else:
		print("Proceeding deployment with using the assigned fmc_ip: " + fmc_ip)

#______________________________________________________________________________#
#deploy function

if deploy_only_cluster != '1':

	delim = '^!@#^'
	if platform.system() == 'Windows':
		delim = '^^!@#^^'

	while function_deployment_name == '':
		print("function_deployment_name cannot be left empty")
		function_deployment_name = str(input(
			"Enter function_deployment_name: "))

	function_params = [
		[ 'mail_id', 'serviceAccountMailId', mail_id ],
		[ 'region', 'region', region ],
		[ 'resource_prefix', 'resourceNamePrefix', resource_prefix ],
		[ 'connector_name', 'vpcConnectorName', connector_name ],
		[ 'bucket_name', 'bucketName', bucket_name ],
		[ 'retry_count', 'retryCount', retry_count ],
		[ 'deploy_with_externalIP', 'deployWithExternalIP', deploy_with_externalIP ],
		[ 'registration_id', 'regID', registration_id ],
		[ 'nat_id', 'natID', nat_id ],
		[ 'cluster_grp_name', 'clsGrpName', cluster_grp_name ],
		[ 'policy_id', 'policyID', policy_id ],
		[ 'fmc_ip', 'fmcIP', fmc_ip ],
		[ 'fmc_passwd', 'fmcPassword', fmc_passwd ],
		[ 'fmc_uname', 'fmcUsername', fmc_uname ],
		[ 'ftdv_passwd', 'ftdvPassword', ftdv_passwd ],
		[ 'license_list', 'licenseCAPS', license_list ],
		[ 'perf_tier', 'performanceTier', perf_tier ]
	]

	pstr = 'srcDirName:ftdv_cluster_function.zip'

	for p in function_params:
		while p[2] == '':
			print('Parameter ' + p[0] + ' cannot be empty')
			p[2] = str(input('Enter a valid value for ' + p[0] + ': '))
		pstr = pstr + '!@#' + p[1] + ':' + p[2]

	os.system('gcloud deployment-manager deployments create ' +
		function_deployment_name +
		' --template cluster_function_infra.jinja --properties ' + delim + pstr)

	print("Function deployment complete, proceeding to cluster deployment")

#______________________________________________________________________________#
#deploy ngfwv cluster

while cluster_deployment_name == '':
	print("cluster_deployment_name cannot be left empty")
	cluster_deployment_name = str(input(
		"Enter NGFWv-cluster deployment name: "))

delim = '^!@#^'
if platform.system() == 'Windows':
	delim = '^^!@#^^'

c = ccl_range.split(' ')

if platform.system() == 'Windows':
	ccl_range = c[0] + '^ ' + c[1]
else:
	ccl_range = c[0] + '\ ' + c[1]

rp = resource_prefix + '-'

silent_params = [
    [ 'mgmtVpcName' , rp + 'ftdv-mgmt-vpc' ],
    [ 'diagVpcName', rp + 'ftdv-diag-vpc' ],
    [ 'outsideVpcName', rp + 'ftdv-outside-vpc' ],
    [ 'insideVpcName', rp + 'ftdv-inside-vpc' ],
    [ 'cclVpcName', rp + 'ftdv-ccl-vpc' ],
    [ 'mgmtSubnetworkName', rp + 'ftdv-mgmt-subnet' ],
    [ 'diagSubnetworkName', rp + 'ftdv-diag-subnet' ],
    [ 'outsideSubnetworkName', rp + 'ftdv-outside-subnet' ],
    [ 'insideSubnetworkName', rp + 'ftdv-inside-subnet' ],
    [ 'cclSubnetworkName', rp + 'ftdv-ccl-subnet' ],
    [ 'mgmtFirewallRule', rp + 'ftdv-mgmt-firewall-rule' ],
    [ 'diagFirewallRule', rp + 'ftdv-diag-firewall-rule' ],
    [ 'outsideFirewallRule', rp + 'ftdv-out-firewall-rule' ],
    [ 'insideFirewallRule', rp + 'ftdv-in-firewall-rule' ],
    [ 'cclFirewallRule', rp + 'ftdv-ccl-firewall-rule' ],
    [ 'healthCheckFirewallRule', rp + 'ftdv-hc-firewall-rule' ],
    [ 'targetSize', '1' ],
    [ 'ftdvHealthCheckPort', '80' ],
    [ 'ftdvCheckIntervalSec', '300' ],
    [ 'ftdvTimeoutSec', '300' ],
    [ 'ftdvHealthCheckProtocolName', 'TCP' ],
    [ 'ftdvUnhealthyThreshold', '10' ]
]

cluster_params = [
	[ 'mail_id', 'serviceAccountMailId', mail_id ],
    [ 'region', 'region', region ],
    [ 'zonecode', 'zonecode', zonecode ],
    [ 'resource_prefix', 'resourceNamePrefix', resource_prefix ],
    [ 'admin_passwd', 'adminPassword', admin_passwd ],
    [ 'host_name', 'hostname', host_name ],
    [ 'ccl_range', 'cclSubnetRange', ccl_range ],
    [ 'cluster_grp_name', 'clusterGrpName', cluster_grp_name],
    [ 'machine_type', 'machineType', machine_type ],
    [ 'src_img_url', 'sourceImageURL', src_img_url ],
    [ 'cpu_util', 'cpuUtilizationTarget', cpu_util ],
    [ 'ftdv_count', 'ftdvReplicas', ftdv_count ],
    [ 'elb_port', 'elbPort', elb_port ],
    [ 'elb_port_name', 'elbPortName', elb_port_name ],
    [ 'elb_protocol', 'elbProtocol', elb_protocol ],
    [ 'elb_timeout', 'elbTimeoutSec', elb_timeout ],
    [ 'elb_health_protocol', 'elbProtocolName', elb_health_protocol ],
    [ 'elb_threshold', 'elbUnhealthyThreshold', elb_threshold ],
    [ 'elb_rule_protocol', 'elbIpProtocol', elb_rule_protocol ],
    [ 'elb_rule_ports', 'elbFePorts', elb_rule_ports ],
    [ 'ilb_protocol', 'ilbProtocol', ilb_protocol ],
    [ 'ilb_drain_timeout', 'ilbDrainingTimeoutSec', ilb_drain_timeout ],
    [ 'ilb_port', 'ilbPort', ilb_port ],
    [ 'ilb_check_interval', 'ilbCheckIntervalSec', ilb_check_interval ],
    [ 'ilb_timeout', 'ilbTimeoutSec', ilb_timeout ],
    [ 'ilb_health_protocol', 'ilbProtocolName', ilb_health_protocol ],
    [ 'ilb_threshold', 'ilbUnhealthyThreshold', ilb_threshold ]
]

pstr = ''

for p in silent_params:
	if pstr == '':
		pstr = pstr + p[0] + ':' + p[1]
	else:
		pstr = pstr + '!@#' + p[0] + ':' + p[1]

for p in cluster_params:
	while p[2] == '':
		print('Parameter ' + p[0] + ' cannot be empty')
		p[2] = str(input('Enter a valid value for ' + p[0] + ': '))
	pstr = pstr + '!@#' + p[1] + ':' + p[2]

os.system('gcloud deployment-manager deployments create ' +
	cluster_deployment_name +
	' --template north-south/deploy_ngfw_cluster.jinja --properties ' +
	delim + pstr)
