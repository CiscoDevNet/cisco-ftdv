"""
Copyright (c) 2021 Cisco Systems Inc or its affiliates.

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

Name:       main.py
Purpose:    This python file has handler for guardduty event analyser lambda
"""

import os
import json
import utils as util
import aws as aws_util
from fmcv import FirepowerManagementCenter
from fdm import FirepowerDeviceManager
from concurrent import futures
from itertools import repeat, chain

# Setup Logging
logger = util.setup_logging(os.environ['DEBUG_LOGS'])

# Get User input
user_input = util.get_user_input_gd_event_analyser_lambda()

def lambda_handler(event, context):
	"""
	Purpose:    Finding Analyser Lambda, to analyse GuardDuty finding and configure network object group in FMCv(s)/FDM(s)
	Parameters: AWS Event(CloudWatch)
	Returns:
	Raises:
	"""

	if user_input is None:
		return
	user_input['default_object_group'] = 'aws-gd-suspicious-hosts'
	user_input['email_subject'] = 'GuardDuty Event Notification - [{}]'.format(user_input['deployment_name'])

	util.put_line_in_log('Lambda Handler started', 'thick')
	logger.debug('Received Lambda Event: ' + json.dumps(event, separators=(',', ':')))

	try:
		eventSource = util.fetch_object(event, 'detail/service/serviceName')
		if eventSource == 'guardduty':
			event_detail = util.fetch_object(event, 'detail')
			logger.debug('Received an event of type {}' .format(eventSource))
			take_action(event_detail)
		else:
			logger.info('Skipping event as this is not a guardduty event')
	except util.NotifyWithError as e:
		logger.error(e)
		send_notification(user_input['email_subject'], e.message)
		return
	except Exception as e:
		logger.error('Failed to process event, Error - {}'.format(e))
		return

	util.put_line_in_log('Lambda Handler finshed', 'thick')
	return {'statusCode': 200, 'body': 'Lambda execution successful'}


def take_action(event):
	"""
	Purpose:    This function will parse the event and based on the analysis,
				it takes the required action
	Parameters: event detail
	Returns:
	Raises:
	"""
	try:
		severity = util.fetch_object(event, 'severity')
		logger.info('Recieved a guardduty event with severity level {}' .format(float(severity)))
		if float(severity) >= float(user_input['min_severity']):
			malicious_ip = util.fetch_object(event,
											 'service/action/networkConnectionAction/remoteIpDetails/ipAddressV4')
			direction = util.fetch_object(event, 'service/action/networkConnectionAction/connectionDirection')
			threatlist = util.fetch_object(event, 'service/additionalInfo/threatListName')
			finding_id = util.fetch_object(event, 'id')
			finding_type = util.fetch_object(event, 'type')
			if malicious_ip is None or direction == 'OUTBOUND' or direction == 'UNKNOWN' and threatlist is None:
				logger.info('Malicious IP: {}, connection direction: {}, threatlist: {}'.format(malicious_ip, direction,
																								threatlist))
				logger.info('No Action required for finding - {}, finding type - {}' .format(finding_id, finding_type))
				return
		else:
			logger.info('Skipping the finding as the severity {} is lower than configured level {}'.format(float(severity), float(user_input['min_severity'])))
			return
	except Exception as e:
		raise Exception('Unable to parse event attributes, {}'.format(e))
		
	logger.info('Processing the event with finding id - {}, finding type - {}' .format(finding_id, finding_type))
	logger.info('Successfully parsed the event with malicious IP: {}, connection direction: {}, threatlist: {}'.format(malicious_ip, direction, threatlist))

	try:
		# update blacklist file in S3
		logger.debug('Updating the malicious host details in the S3 report')
		is_new = update_blacklist(malicious_ip)
		if not is_new:
			logger.info('Skipping finding id {} with ip address {}, item has been already processed earlier'.format(finding_id, malicious_ip))
			return
	except Exception as e:
		logger.error('Error while updating the malicious host in the S3 report: {}'.format(e))
		raise Exception('Unable to perform S3 operations, {}'.format(e))
	logger.info('Successfully updated the malicious host in the S3 report')
	
	manager_details = []
	message = 'Hello,\n\nAWS GuardDuty has reported the finding \"{finding_type}\" with remote IP(malicious IP) {malicious_ip}.\nThe remote IP(malicious IP) is updated in the report file in S3 bucket\n\tReport file s3 URI - {s3_url}\n\tReport file object URL - {web_url}\n\tReport file MD5 URL - {md5_url}\n'.format(
		finding_type=finding_type,
		malicious_ip=malicious_ip,
		s3_url=aws_util.get_s3_url(user_input['s3_bucket'], user_input['s3_report_key']),
		web_url=aws_util.get_object_url(user_input['s3_bucket'], user_input['s3_report_key']).split('?')[0],
		md5_url=aws_util.get_object_url(user_input['s3_bucket'], user_input['s3_report_md5']).split('?')[0])
	configure_si = 'configure the above S3 report file object URL as a security intelligence network feed and associate this feed to a security intelligence block list in the required access policy(s) in FMCv(s). Please ensure the S3 object URLs are accessible from the FMCv (Kindly ignore this if configured already).\n'

	if user_input['manager_input_file'] is  None:
		message += '\nYou may {}' .format(configure_si)
		raise util.NotifyWithError('FMCv/FDM input details is not provided, directing to use the FMCv security intelligence solution', message)

	configure_si = '\nNote: Alternatively, you may also ' + configure_si
	logger.info('Fetching FMCv/FDM details from the provided configuration file {}'.format(user_input['manager_input_file']))
	try:
		resp = aws_util.get_object(user_input['s3_bucket'], user_input['manager_input_file'])
		manager_data = resp['Body'].read().decode('utf-8')
	except Exception as e:
		message += '\nFMCv/FDM details is missing.\nYou may create the network object using the malicious host {} and associate the object to the network group and add this group to the block list in the required access control policies on the FMCv(s)/FDM(s) to block the malicious host reported.\n'.format(malicious_ip)
		message += configure_si
		raise util.NotifyWithError('Unable to get FMCv/FDM details, {}'.format(e), message)
	
	manager_entities = []
	try:
		# Parse FMCv/FDM details
		manager_details = util.parse_config(manager_data)
		logger.info('Successfully parsed FMCv/FDM config file, updating the network object groups')
		
		manager_details = validate_manager_input(manager_details, malicious_ip)
		if len(manager_details) == 0:
			raise Exception('No FMCv/FDM details found in the configuration input file')
		logger.debug('Successfully parsed FMCv/FDM details, adding malicious host to the network object group')
		
		# Using threads for running concurrent tasks
		ex_pool = futures.ThreadPoolExecutor(max_workers=3)
		fmcv_results = ex_pool.map(fmcv_send_request, iter([x for x in manager_details if 'Valid' not in x and 'FMC' in x['device-type'].upper()]), repeat(malicious_ip))
		fdm_results = ex_pool.map(fdm_send_request, iter([x for x in manager_details if 'Valid' not in x and 'FDM' in x['device-type'].upper()]), repeat(malicious_ip))
		
		# Collect execution results
		for res in chain(fdm_results, fmcv_results):
			if res['Status']:
				logger.info('Successfully updated the network group(s) {} for {} with IP {}'.format(', '.join(res['object-group-name']), res['device-type'], res['public-ip']))
				msg = 'Network group(s) \"{}\" updated'.format(', '.join(res['object-group-name']))
				if res['object-group-name'][0] == user_input['default_object_group']:
					msg = 'Network group name is not provided, updated default network group \"{}\"'.format(res['object-group-name'][0])
				manager_entities.append([res['name'], res['public-ip'], res['device-type'].upper(), 'Success', msg])
			else:
				logger.error('Failed to update the object group(s) {} for {} with IP {}, {}'.format(', '.join(res['object-group-name']), res['device-type'], res['public-ip'], res['error']))
				manager_entities.append([res['name'], res['public-ip'], res['device-type'].upper(), 'Failure', '{}'.format(res['error'])])
	except Exception as e:
		message += '\nPlease provide valid FMCv/FDM details in the manager details configuration file {}.\nYou may create the network object using the malicious host {} and associate the object to the network group and add this group to the block list in the required access control policies on the FMCv(s)/FDM(s) to block the malicious host reported.\n'.format(user_input['manager_input_file'], malicious_ip)
		message += configure_si
		raise util.NotifyWithError('Unable to configure network groups on FMCv/FDM, {}'.format(e), message)
	
	message += '\nBelow is the status of network group updates(with malicious host) on the FMCv(s)/FDM(s) provided in the configuration:\n\n'
	# Collect invalid FMCv/FDM entries
	for entry in manager_details:
		if 'Valid' in entry and not entry['Valid']:
			if 'device-type' not in entry:
				entry['device-type'] = 'None'
			manager_entities.append([entry['name'], entry['public-ip'], entry['device-type'].upper(), 'Failure', entry['error']])
	
	# Build notification messages from the result
	if len(manager_entities) > 0:
		message += util.print_table(["Device ID", "Device IP", "Device Type", "Update Status", "Remarks"], manager_entities)
		
	message += '\n\nYou may associate the network group to the required access control policies on the FMCv(s)/FDM(s) to block the malicious host {} reported.(ignore if already configured)' .format(malicious_ip)
	message += '\nYou may also fix the errors(if any) causing the update failures.(Please check the AWS CloudWatch logs for more details about the failure)\nFor the failed updates, please create a network object using the malicious IP and add it to the network group manually.\n'
	message += configure_si
	send_notification(user_input['email_subject'], message)
	logger.info('Successfully published notification for the guardduty event')
		
def send_notification(subject, message):
	"""
	Purpose:    This function will send email notification to subscribed endpoints
	Parameters: email subject and message
	Returns:
	Raises: Exception when publish to SNS fails
	"""
	logger.info('Publishing Message: ' + json.dumps(message))
	try:
		aws_util.publish_to_topic(user_input['sns_topic_arn'], subject, message)
	except Exception as e:
		raise Exception('Unable to publish message to SNS Topic, {}'.format(e))

def update_blacklist(ip_address):
	"""
	Purpose:    This function will update the malicious host to the file in S3
	Parameters: ip address
	Returns: True if new finding, False otherwise
	Raises: exception if it fails to fetch/read/update blacklist
	"""
	# Write malicious IP to S3
	key = user_input['s3_report_key']
	acl_key = user_input['s3_report_key']
	obj_acl = None
	try:
		aws_util.head_bucket(user_input['s3_bucket'])
	except Exception as e:
		raise Exception('Failed to get S3 bucket to store blacklist, {}'.format(e))

	try:
		aws_util.head_object(user_input['s3_bucket'], key)
		try:
			resp = aws_util.get_object(user_input['s3_bucket'], key)
			blacklist_data = resp['Body'].read().decode('utf-8')
		except Exception as e:
			raise Exception('Failed to get blacklist file content from S3, {}'.format(e))
			return

	except Exception as e:
		logger.debug('Blacklist file does not exist')
		blacklist_data = ''
		acl_key = user_input['s3_base_path']

	try:
		obj_acl = aws_util.get_object_acl(user_input['s3_bucket'], acl_key)
	except Exception as e:
		logger.error('Failed to get blacklist file permissions from  S3, {}'.format(e))

	if len(blacklist_data) > 0 and not blacklist_data.endswith('\n'):
		blacklist_data += '\r\n'
	ip_addr_str = ip_address + '\r\n'
	is_new_finding = False
	if ip_addr_str not in blacklist_data:
		blacklist_data = blacklist_data + ip_addr_str
		is_new_finding = True

	try:
		aws_util.put_object(user_input['s3_bucket'], key, blacklist_data)
	except Exception as e:
		raise Exception('Failed to save blacklist file in S3, {}'.format(e))

	if obj_acl is not None:
		try:
			aws_util.put_object_acl(user_input['s3_bucket'], key, {
				'Grants': obj_acl['Grants'],
				'Owner': obj_acl['Owner']},
			)
		except Exception as e:
			logger.error('Failed to update blacklist file permissions in S3, {}'.format(e))

	# Update report md5
	md5_obj_acl = None
	if acl_key == user_input['s3_base_path']:
		md5_obj_acl = obj_acl
	else:
		try:
			md5_obj_acl = aws_util.get_object_acl(user_input['s3_bucket'], user_input['s3_report_md5'])
		except Exception as e:
			logger.error('Failed to get report-md5 file permissions from  S3, {}'.format(e))

	try:
		aws_util.put_object(user_input['s3_bucket'], user_input['s3_report_md5'], util.get_md5_sum(blacklist_data))
	except Exception as e:
		logger.error('Failed to update report-md5 file in S3, {}'.format(e))

	if md5_obj_acl is not None:
		try:
			aws_util.put_object_acl(user_input['s3_bucket'], user_input['s3_report_md5'], {
				'Grants': md5_obj_acl['Grants'],
				'Owner': md5_obj_acl['Owner']},
									)
		except Exception as e:
			logger.error('Failed to update report-md5 file permissions in S3, {}'.format(e))

	return is_new_finding

def validate_manager_input(manager_details, malicious_ip):

	"""
	Purpose:    This function will validate the manager input file and generate the required CLIs
	Parameters: manager details object and malicious IP
	Returns: validated manager details object
	Raises:
	"""
	mandatory_fields = ['public-ip', 'username', 'password', 'device-type']
	for i in range(0, len(manager_details)):
		if all(item in manager_details[i].keys() for item in mandatory_fields):
			if 'object-group-name' not in manager_details[i] or len(manager_details[i]['object-group-name'].strip()) == 0:
				logger.info('FMCv/FDM network object group is not provided at section {} in the manager details input file, configuring default name as \"{}\"' .format(manager_details[i]['name'], user_input['default_object_group']))
				manager_details[i]['object-group-name'] = [user_input['default_object_group']]
			else:
				manager_details[i]['object-group-name'] = [x.strip() for x in manager_details[i]['object-group-name'].split(',') if len(x.strip()) > 0]

			if user_input['kms_arn'] is not None:
				try:
					manager_details[i]['password'] = aws_util.get_decrypted_key(manager_details[i]['password'])
				except Exception as e:
					logger.error('Failed to decrypt password for the FMCv/FDM details provided at section {} in the manager details file {}, skipping this entry, cannot add the malicious host to the network object group for this device.'.format(manager_details[i]['name'], user_input['manager_input_file']))
					manager_details[i]['Valid'] = False
					manager_details[i]['error'] = 'Failed to decrypt password/enable-password provided at section {}'.format(manager_details[i]['name'])
			
			if manager_details[i]['device-type'].upper() not in ['FMC', 'FDM']:
				manager_details[i]['Valid'] = False
				manager_details[i]['error'] = 'Invalid or no device type provided at section {}'.format(manager_details[i]['name'])
		else:
			logger.error('Incomplete FMCv/FDM details at section {} in the manager details file {}, skipping this entry, cannot add the malicious host to the network object group for this device.' .format(manager_details[i]['name'], user_input['manager_input_file']))
			if 'public-ip' in manager_details[i]:
				manager_details[i]['Valid'] = False
				manager_details[i]['error'] = 'One or more input details missing at section {}'.format(manager_details[i]['name'])
	return manager_details

def fmcv_send_request(fmcv_details, malicious_ip):
	"""
	Purpose:    This function initialises FMC class and
				calls to method to configure network object in FMCv
	Parameters: fmcv details object
	Returns: updated fmcv details object
	Raises:
	"""
	err_msg = 'Network group(s) \"{}\" could not be updated, '.format(', '.join(fmcv_details['object-group-name']))
	# Get auth token
	try:
		fmc = FirepowerManagementCenter(fmcv_details['public-ip'], fmcv_details['username'], fmcv_details['password'])
		fmc.get_auth_token()
		logger.debug('Generated auth token {}'.format(fmc.headers['X-auth-access-token']))
		logger.debug('Setting Domain Uuid {}'.format(fmc.domain_uuid))
		
		# Create host object if it does not exists
		host_name = 'host_' + malicious_ip
		host = fmc.get_host_object_by_name(host_name)
		logger.debug('Get network host resp - {}'.format(host))
		if host is None:
			host = fmc.create_host_object(host_name, malicious_ip)
			logger.info('FMCv[{}] - Created network host object with name {}'.format(fmcv_details['public-ip'], host_name))
			
		# Create/update network group with the host object
		for group_name in fmcv_details['object-group-name']:
			nw_group = fmc.get_network_grp_by_name(group_name)
			logger.debug('Get network object group resp - {}'.format(nw_group))
			if nw_group is None:
				nw_group = fmc.create_network_grp(group_name, host)
				logger.info('FMCv[{}] - Did not find an existing network object group, created new network object {} with hostname {}'.format(fmcv_details['public-ip'], group_name, host_name))
			else:
				update_resp = fmc.update_network_group(nw_group, host)
				logger.info('FMCv[{}] - Updated network object group \"{}\" with hostname {}'.format(fmcv_details['public-ip'], group_name, host_name))
		fmcv_details['Status'] = True
	except Exception as e:
		fmcv_details['Status'] = False
		fmcv_details['error'] = err_msg + str(e)
		logger.error('FMCv[{}] : {}'.format(fmcv_details['public-ip'], fmcv_details['error']))
	return fmcv_details

def fdm_send_request(fdm_details, malicious_ip):
	"""
	Purpose:    This function initialises FDM class and
				calls to method to configure network object in FDM
	Parameters: fdm details object
	Returns: updated fdm details object
	Raises:
	"""
	err_msg = 'Network group(s) \"{}\" could not be updated, '.format(', '.join(fdm_details['object-group-name']))
	try:
		# Get access token
		fdm = FirepowerDeviceManager(fdm_details['public-ip'], fdm_details['username'], fdm_details['password'])
		fdm.get_access_token()
		logger.debug('Generated access token {}'.format(fdm.headers['Authorization'].split(' ')[1]))
		
		# Create host object if it does not exists
		host_name = 'host_' + malicious_ip
		host = fdm.get_host_object_by_name(host_name)
		logger.debug('Get network host resp - {}'.format(host))
		if host is None:
			host = fdm.create_host_object(host_name, malicious_ip)
			logger.info('FDM[{}] - Created host object with name {}'.format(fdm_details['public-ip'], host_name))
			
		# Create/update network group with the host object
		for group_name in fdm_details['object-group-name']:
			nw_group = fdm.get_network_grp_by_name(group_name)
			logger.debug('Get network group resp - {}'.format(nw_group))
			if nw_group is None:
				nw_group = fdm.create_network_grp(group_name, host)
				logger.info('FDM[{}] - Did not find an existing network group, created new network group \"{}\" with hostname {}'.format(fdm_details['public-ip'], group_name, host_name))
			else:
				update_resp = fdm.update_network_group(nw_group, host)
				logger.info('FDM[{}] - Updated network group \"{}\" with host {}'.format(fdm_details['public-ip'], group_name, host_name))
		fdm_details['Status'] = True
	except Exception as e:
		fdm_details['Status'] = False
		fdm_details['error'] = err_msg + str(e)
		logger.error('FDM[{}] : {}'.format(fdm_details['public-ip'], fdm_details['error']))
	return fdm_details
