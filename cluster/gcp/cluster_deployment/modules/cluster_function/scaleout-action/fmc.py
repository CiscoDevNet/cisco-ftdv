"""
Copyright (c) 2022-25 Cisco Systems Inc or its affiliates.
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
Name:       fmc_functions.py
Purpose:    This python file has functions for 
            executing REST APIs in FMCv.
"""

import time
import requests
from requests.exceptions import ConnectionError, HTTPError
import json
import os


class FirepowerManagementCenter:
     def __init__(self,fmc_ip, fmc_username, fmc_password):
          self.server = 'https://' + fmc_ip
          self.username = fmc_username
          self.password = fmc_password
          self.headers = []
          self.domain_uuid = ""
          self.authTokenTimestamp = 0
          self.authTokenMaxAge = 15*60  # seconds - 30 minutes is the max without using refresh

     def get_auth_token(self):
          """
          Purpose:    get a new REST authentication token
                    update the 'headers' variable
                    set a timestamp for the header (tokens expire)
          Parameters:
          Returns:
          Raises:
          """
          self.headers = {'Content-Type': 'application/json'}
          api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
          auth_url = self.server + api_auth_path
          print("DEBUG: Authentication URL: "+ auth_url)
          try:
               # 2 ways of making a REST call are provided:
               # One with "SSL verification turned off" and the other with "SSL verification turned on".
               # The one with "SSL verification turned off" is commented out. If you like to use that then
               # uncomment the line where verify=False and comment the line with =verify='/path/to/ssl_certificate'
               # REST call with SSL verification turned off:
               r = requests.post(auth_url, headers=self.headers, auth=requests.auth.HTTPBasicAuth(self.username, self.password), verify=False, timeout=30)
               print("R in get_auth_token:", r)
               # REST call with SSL verification turned on: Download SSL certificates
               # from your FMC first and provide its path for verification.
               # r = requests.post(auth_url, headers=self.headers,
               #                   auth=requests.auth.HTTPBasicAuth(username,password), verify='/path/to/ssl_certificate')
               auth_headers = r.headers
               auth_token = auth_headers.get('X-auth-access-token', default=None)
               self.domain_uuid = auth_headers.get('domain_uuid', default=None)
               self.headers['X-auth-access-token'] = auth_token
               self.authTokenTimestamp = int(time.time())
               # print("Acquired AuthToken: " + auth_token)
               # print("domain_uuid: " + domain_uuid)
               if auth_token is None:
                    raise Exception("ERROR: auth_token not found")
          except ConnectionError as conn_err:
               # Handle network-related errors, such as DNS failures or refused connections
               raise Exception(f"ERROR: Connection error occured in get_auth_token, Google function might not be able to connect to FMCv, Please verify if FMCv IP is correct and Function IP is allowed in network security group of FMCv. {str(conn_err)}")
          except HTTPError as http_err:
               # Handle HTTP errors, including authentication errors
               if r.status_code == 401:
                    raise Exception(f"ERROR: Exception occured in get_auth_token, FMCv Authentication failed: Incorrect username or password, {str(http_err)}")
               else:
                    raise Exception(f"ERROR: Exception occured in get_auth_token, {str(http_err)}")
          except Exception as err:
               raise Exception(f"ERROR: Exception occured in get_auth_token, {str(err)}")
          return

     def rest_get(self, url):
          """
          Purpose:    Issue REST get to the specified URL
          Parameters: url
          Returns:    r.text is the text response (r.json() is a python dict version of the json response)
                    r.status_code = 2xx on success
          Raises:
          """
          # if the token is too old then get another
          try:
               if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
                    print("INFO: Getting a new authToken")
                    self.get_auth_token()
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in rest_get, {str(e)}")
          r = None
          try:
               print("DEBUG: Requesting(rest_get):" + url)
               r = requests.get(url, headers=self.headers, verify=False, timeout=30)
               if "Access token invalid" in r.text:
                    print("Access token invalid. Getting a new authToken.")
                    self.get_auth_token()
                    r = requests.get(url, headers=self.headers, verify=False, timeout=30)  
               status_code = r.status_code
               resp = r.text
               print("DEBUG: Response Status Code(rest_get): " + str(status_code))
               print("DEBUG: Response body(rest_get): " + str(resp))
               if 200 <= status_code <= 300:
                    return r
               else:
                    raise Exception("ERROR: Exception occurred in rest_get", str(resp))
          except Exception as err:
               raise Exception("ERROR: Exception occurred in rest_get", str(err))
          finally:
               if r: r.close()
     
     def rest_post(self, url, post_data):
          """
          Purpose:    Issue REST post to the specified url with the post_data provided
          Parameters: url, post data
          Returns:    This function will return 'r' which is the response from the post:
                    r.text is the text response (r.json() is a python dict version of the json response)
                    r.status_code = 2xx on success
          Raises:     Error occurred in post
          """
          # if the token is too old then get another
          
          try:
               if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
                    print("INFO: Getting a new authToken")
                    self.get_auth_token()
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in rest_post, {str(e)}")
          r = None
          try:
               print("DEBUG: Requesting(rest_post): " + url)
               r = requests.post(url, data=json.dumps(post_data), headers=self.headers, verify=False, timeout=30)
               if "Access token invalid" in r.text:
                    print("Access token invalid. Getting a new authToken.")
                    self.get_auth_token()
                    r = requests.post(url, data=json.dumps(post_data), headers=self.headers, verify=False, timeout=30)
               status_code = r.status_code
               resp = r.text
               print("DEBUG: Response Status Code(rest_post): ", str(status_code))
               print("DEBUG: Response body(rest_post): " + str(resp))
               if 201 <= status_code <= 202:
                    return r
               else:
                    r.raise_for_status()
                    raise Exception("ERROR: Exception occurred in rest_post"+resp)
          except requests.exceptions.HTTPError as err:
               raise Exception("ERROR: Exception occurred in rest_post", str(err))
          finally:
               if r: r.close()
               
     def rest_put(self, url, put_data):
          """
          Purpose:    Issue REST put to specific url with the put_data provided
          Parameters: url, put data
          Returns:    This function will return 'r' which is the response from the put:
                    r.text is the text response (r.json() is a python dict version of the json response)
                    r.status_code = 2xx on success
          Raises:
          """
          try:
               if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
                    print("Getting a new authToken")
                    self.get_auth_token()
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in rest_put, {str(e)}")
          r = None
          try:
               print("DEBUG: Requesting(rest_put): " + url)
               r = requests.put(url, data=json.dumps(put_data), headers=self.headers, verify=False, timeout=30)
               if "Access token invalid" in r.text:
                    print("Access token invalid. Getting a new authToken.")
                    self.get_auth_token()
                    r = requests.put(url, data=json.dumps(put_data), headers=self.headers, verify=False, timeout=30)
               # REST call with SSL verification turned on:
               # r = requests.put(url, data=json.dumps(put_data), headers=headers, verify='/path/to/ssl_certificate')
               status_code = r.status_code
               resp = r.text
               print("DEBUG: Response Status Code(rest_put): " + str(status_code))
               print("DEBUG: Response body(rest_put): ", str(resp))
               if status_code == 200:
                    return r
               else:
                    r.raise_for_status()
                    print("")
                    raise Exception("ERROR: Exception occurred in rest_put, " + resp)
          except requests.exceptions.HTTPError as err:
               raise Exception("ERROR: Exception occurred in rest_put.", str(err))
          finally:
               if r: r.close()

     def get_access_policy_id_by_name(self, name):
          """
          Purpose:    Get Access Policy Id by its name
          Parameters: Access policy name
          Returns:    Access Policy Id, None
          Raises:
          """
          try:
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies"
               url = self.server + api_path + '?offset=0&limit=10000'
               r = self.rest_get(url)
               # Search for policy by name
               if 'items' in r.json():
                    for item in r.json()['items']:
                         if item['name'] == name:
                              return str(item['id'])
               return None
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in get_access_policy_id_by_name,  {str(e)}")

     #policy id => access policy id
     def register_ftdv(self, vm_name, mgmtip, reg_id, nat_id, policy_id, performanceTier='FTDv50'):
          """
          Purpose:    Register the device to FMC
          Parameters: Device Name, Mgmgt Ip, Registration & NAT id, Licenses cap, grp id
          Returns:    Task id, None
          Raises:
          """
          try:
               vm_policy_id = self.get_access_policy_id_by_name(policy_id)
          except Exception as e:
               raise Exception("ERROR: Exception occured in register_ftdv, "+ str(e))
          else:
               try:
                    if vm_policy_id is not None:
                         print("INFO: Registering FTDv: " + vm_name + " to FMCv with policy id: " + vm_policy_id)
                         #grp_id = self.get_device_grp_id_by_name(grp_id)
                         r = self.register_device(vm_name, mgmtip, vm_policy_id, reg_id, nat_id, performanceTier)
                         if 'type' in r.json():
                              if r.json()['type'] == 'Device':
                                   return r.json()['metadata']['task']['id']
                    else:
                         print("INFO: No policy found")
                    return None
               except Exception as e:
                    raise Exception("ERROR: Exception occurred while registering device:", str(e))

     def register_device(self, name, mgmt_ip, policy_id, reg_id, nat_id, performanceTier):
          """
          Purpose:    Register the device to FMC
          Parameters: Name of device, Mgmt ip, Access Policy Id, Registration & NAT id, Licenses Caps, Group Id
          Returns:    REST post response
          Raises:
          """
          try:
               lic_caps = os.getenv('LICENSE_CAPS')
               lic_caps = lic_caps.split(",")
               print("Registering: "+ name)
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords"
               url = self.server + api_path
               post_data = {
                    "name": name,
                    "hostName": mgmt_ip,
                    "regKey": reg_id,
                    "natID": nat_id,
                    "type": "Device",
                    "license_caps": lic_caps,
                    "performanceTier": performanceTier,
                    "accessPolicy": {
                         "id": policy_id,
                         "type": "AccessPolicy"
                    }
               }
               r = self.rest_post(url, post_data)
               return r
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in register_device, {str(e)}")
          
     def get_device_id_by_name(self, vm_name):
          """
          Purpose:    Get Device Id by its name
          Parameters: Device Name
          Returns:    Device Id
          Raises:
          """
          try:
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords"
               url = self.server + api_path + '?offset=0&limit=10000'
               r = self.rest_get(url)
               if 'items' in r.json():
                    for item in r.json()['items']:
                         if item['name'] == vm_name:
                              return str(item['id'])
               # or return empty string
               return ''
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in get_device_id_by_name, {str(e)}")

     def get_device_grp_id_by_name(self, name):
          """
          Purpose:    To get device group id by passing name of the group
          Parameters: Name of device group
          Returns:    Group Id or None
          Raises:
          """
          try:
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devicegroups/devicegrouprecords"
               url = self.server + api_path + '?offset=0&limit=9000'
               r = self.rest_get(url)
               if 'items' in r.json():
                    for item in r.json()['items']:
                         if item['name'] == name:
                              return str(item['id'])
               return None
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in get_device_grp_id_by_name, {str(e)}")

     def get_cluster_id_by_name(self, name):
          """
          Purpose:    To get cluster id by passing name of the group
          Parameters: Name of device
          Returns:    Cluster Id or None
          Raises:
          """
          try:
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/deviceclusters/ftddevicecluster"
               url = self.server + api_path + '?offset=0&limit=9000'
               r = self.rest_get(url)
               if 'items' in r.json():
                    for item in r.json()['items']:
                         # Need to take care of hardcoded cluster name - wip
                         if item['name'] == name:
                              return str(item['id'])
                    return None
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in get_cluster_id_by_name, {str(e)}")

     def get_cluster_members(self, cls_id):
          """
          Purpose:    To get devices name list from cluster
          Parameters: Cluster Id
          Returns:    list or None
          Raises:
          """
          try:
               member_name_list = []
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/deviceclusters/ftddevicecluster/"
               url = self.server + api_path + cls_id
               r = self.rest_get(url)
               # Add Control Node
               member_name_list.append(r.json()['controlDevice']['deviceDetails']['name'])
               # Add Data Nodes
               if 'dataDevices' in r.json():
                    for item in r.json()['dataDevices']:
                         member_name_list.append(item['deviceDetails']['name'])
               if member_name_list:
                    return member_name_list
               else:
                    return None
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in get_cluster_members, {str(e)}")

     def check_reg_status_from_fmc(self, vm_name):
          """
          Purpose:    Checks if device is registered to FMC
          Parameters: Device Name
          Returns:    SUCCESS, FAILED
          Raises:
          """
          device_id = ''
          try:
               device_id = self.get_device_id_by_name(vm_name)
          except Exception as e:
               raise Exception("Exception in check_reg_status_from_fmc "+ str(e))
          else:
               if device_id != '':
                    return "SUCCESS"
               else:
                    return "FAILED"

     def check_task_status_from_fmc(self, task_id):
          """
          Purpose:    Checks task status from fmc
          Parameters: task id
          Returns:    SUCCESS, FAILED, PENDING, RUNNING
          Raises:
          """
          try:
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/job/taskstatuses/"
               url = self.server + api_path + task_id
               r = self.rest_get(url)
               status = r.json()['message']
               return status
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in check_task_status_from_fmc, {str(e)}")

     def get_security_objectid_by_name(self, name):
          """
          Purpose:    Get Zone ID from it's name
          Parameters: Zone Name
          Returns:    Zone ID, None
          Raises:
          """
          try:
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/securityzones"
               url = self.server + api_path + '?offset=0&limit=9000'
               r = self.rest_get(url)
               if 'items' in r.json():
                    for item in r.json()['items']:
                         if item['name'] == name:
                              return str(item['id'])
               return None
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in get_security_objectid_by_name, {str(e)}")
     
     def get_network_objectid_by_name(self, name):
          """
          Purpose:    Get Network object Id by its name
          Parameters: Object Name
          Returns:    Object Id
          Raises:
          """
          try:
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkaddresses"
               url = self.server + api_path + '?offset=0&limit=10000'
               r = self.rest_get(url)
          
               for item in r.json()['items']:
                    if item['type'] == 'Network' and item['name'] == name:
                         return str(item['id'])
               return ''
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in get_network_objectid_by_name, {str(e)}")
     
     def get_static_routeid_by_name(self, device_name):
          """
          Purpose:    Get Network object Id by its name
          Parameters: Object Name
          Returns:    Object Id
          Raises:
          """
          try:
               device_id = self.get_device_id_by_name(device_name)
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + device_id + "/routing/ipv4staticroutes"
               url = self.server + api_path
               r = self.rest_get(url)
               return ''
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in get_static_routeid_by_name, {str(e)}")
     
     def get_static_routeid(self):
          """
          Purpose:    Get Network object Id by its name
          Parameters: Object Name
          Returns:    Object Id
          Raises:
          """
          try:
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/8a4633e2-e48d-11eb-a074-b8d647c0a433/routing/ipv4staticroutes"
               url = self.server + api_path
               r = self.rest_get(url)
               return ''
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in get_static_routeid, {str(e)}")
          
     def get_nic_id_by_name(self, device_name, nic_name):
          """
          Purpose:    Get Nic Id by device & nic name
          Parameters: Device Name, Nic name
          Returns:    Nic Id, None
          Raises:
          """
          try:
               if nic_name != 'GigabitEthernet0/0' and nic_name != 'GigabitEthernet0/1':
                    print("Warning - nic name must be GigabitEthernet0/0 or GigabitEthernet0/1. "
                                   "The argument name was " + nic_name)
               device_id = self.get_device_id_by_name(device_name)
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + device_id + "/physicalinterfaces"
               url = self.server + api_path + '?offset=0&limit=10000'
               r = self.rest_get(url)
               if 'items' in r.json():
                    for item in r.json()['items']:
                         if item['name'] == nic_name:
                              return str(item['id'])
               return None
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in get_nic_id_by_name, {str(e)}")
     
     def configure_nic_dhcp(self, device_name, nic, nic_name, zone, mtu):
          """
          Purpose:    Configure an Nic interface as DHCP
          Parameters: Device Name, Nic, Nic name, Zone, MTU
          Returns:    REST put response
          Raises:
          """
          try:
               device_id = self.get_device_id_by_name(device_name)
               nic_id = self.get_nic_id_by_name(device_name, nic)
               zone_id = self.get_security_objectid_by_name(zone)

               if nic_id != None:
                    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + \
                              device_id + "/physicalinterfaces/" + nic_id
               else:
                    print("NIC ID is none")
                    return 
               url = self.server + api_path
               put_data = {
                         "type": "PhysicalInterface",
                         "managementOnly": "false",
                         "MTU": int(mtu),
                         "ipv4": {
                         "dhcp": {
                              "enableDefaultRouteDHCP": "false",
                              "dhcpRouteMetric": 1
                              }
                         },
                         "securityZone": {
                         "id": zone_id,
                         "type": "SecurityZone"
                         },
                         "mode": "NONE",
                         "ifname": nic_name,
                         "enabled": "true",
                         "name": nic,
                         "id": nic_id
                         }
               r = self.rest_put(url, put_data)
               return r
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in configure_nic_dhcp, {str(e)}")
     
     def get_host_objectid_by_name(self, name):
          """
          Purpose:    Get Host object Id by Name
          Parameters: Object Name
          Returns:    Object Id
          Raises:
          """
          try:
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/hosts"
               url = self.server + api_path + '?offset=0&limit=10000'
               r = self.rest_get(url)
               for item in r.json()['items']:
                    if item['type'] == 'Host' and item['name'] == name:
                         return str(item['id'])
               return ''
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in get_host_objectid_by_name, {str(e)}")

     def create_static_network_route(self, device, interface_name, network_object_name, host_object_name_gw, metric):
          """
          Purpose:    To create static network route on device
          Parameters: Device, Interface Name, Network, Gateway, Metric
          Returns:    REST response
          Raises:
          """
          try:
               print("Static route creation: Interface->"+interface_name+" Network Object->"+network_object_name+
                         " Gateway Object->"+host_object_name_gw+" Metric->"+str(metric))
               ngfwid = self.get_device_id_by_name(device)
               network_object_id = self.get_network_objectid_by_name(network_object_name)
               host_object_id_gw = self.get_host_objectid_by_name(host_object_name_gw)
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + ngfwid + \
                         "/routing/ipv4staticroutes"
               url = self.server + api_path
               if host_object_id_gw != '':
                    gate_way = {
                         "object": {
                         "type": "Host",
                         "id": host_object_id_gw,
                         "name": host_object_name_gw
                         }
                    }
               else:
                    gate_way = {
                         "literal": {
                         "type": "Host",
                         "value": host_object_name_gw
                         }
                    }
               post_data = {
                    "interfaceName": interface_name,
                    "selectedNetworks": [
                         {
                         "type": "Network",
                         "id": network_object_id,
                         "name": network_object_name
                         }
                    ],
                    "gateway": gate_way,
                    "metricValue": metric,
                    "type": "IPv4StaticRoute",
                    "isTunneled": False
               }
               r = self.rest_post(url, post_data)
               return r
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in create_static_network_route, {str(e)}")

     def get_deployable_devices(self):
          """
          Purpose:    Get list of deployable devices
          Parameters:
          Returns:    List of devices, pending to be deployed
          Raises:
          """
          try:
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/deployment/deployabledevices"
               url = self.server + api_path
               r = self.rest_get(url)
               print("Deployable devices:" + str(r.json()))
               device_list = []
               if 'items' in r.json():
                    for item in r.json()['items']:
                         if item['type'] == 'DeployableDevice':
                              device_list.append(item['name'])
               return device_list
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in get_deployable_devices, {str(e)}")

     def start_deployment(self, device_name):
          """
          Purpose:    Deploys policy changes on device
          Parameters: Device name
          Returns:    Task Id
          Raises:
          """
          try:
               print("Deploy called for: " + device_name)
               device_list = self.get_deployable_devices()
               #to test whether auth failed in first instance reg
               device_list = self.get_deployable_devices()
               if device_name in device_list:
                    print("Deploying on device: " + device_name)
                    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/deployment/deploymentrequests"
                    url = self.server + api_path
                    post_data = {
                         "type": "DeploymentRequest",
                         "version": str(self.get_time_stamp()),
                         "forceDeploy": True,
                         "ignoreWarning": True,
                         "deviceList": [self.get_device_id_by_name(device_name)]
                    }
                    r = self.rest_post(url, post_data)
                    if 'type' in r.json():
                         if r.json()['type'] == 'DeploymentRequest':
                              return r.json()['metadata']['task']['id']
               return ''
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in start_deployment, {str(e)}")

     def get_time_stamp(self):
          """
          Purpose:    Get time stamp
          Parameters:
          Returns:    Audit time stamp
          Raises:
          """
          try:
               api_path = "/api/fmc_platform/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/audit/auditrecords"
               url = self.server + api_path
               r = self.rest_get(url)
               return r.json()['items'][0]['time']*1000
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in get_time_stamp, {str(e)}")

     # -----------------------------------------------------------------------
     # Health-check NAT helpers
     # -----------------------------------------------------------------------

     def _get_or_create_security_zone(self, name):
          """Return zone id for the named security zone, creating it (ROUTED mode) if absent."""
          try:
               existing_id = self.get_security_objectid_by_name(name)
               if existing_id:
                    print(f"INFO: Security zone '{name}' already exists, id={existing_id}")
                    return existing_id
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/securityzones"
               url = self.server + api_path
               post_data = {"name": name, "type": "SecurityZone", "interfaceMode": "ROUTED"}
               r = self.rest_post(url, post_data)
               zone_id = r.json()['id']
               print(f"INFO: Created security zone '{name}', id={zone_id}")
               return zone_id
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in _get_or_create_security_zone '{name}', {str(e)}")

     def _create_network_object(self, name, value, prefix_length):
          """Create a Network host/subnet object; return its id (existing or new)."""
          try:
               existing_id = self.get_network_objectid_by_name(name)
               if existing_id:
                    print(f"INFO: Network object '{name}' already exists, id={existing_id}")
                    return existing_id
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networks"
               url = self.server + api_path
               post_data = {
                    "name": name,
                    "value": f"{value}/{prefix_length}",
                    "type": "Network",
               }
               r = self.rest_post(url, post_data)
               obj_id = r.json()['id']
               print(f"INFO: Created network object '{name}', id={obj_id}")
               return obj_id
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in _create_network_object '{name}', {str(e)}")

     def _create_host_object(self, name, value):
          """Create or update a Host object; return its id."""
          try:
               existing = self.get_host_objectid_by_name(name)
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/hosts"
               if existing:
                    # PUT to update the IP in case it changed (e.g. after Terraform recreate)
                    url = self.server + api_path + f"/{existing}"
                    self.rest_put(url, {"id": existing, "name": name, "value": value, "type": "Host"})
                    print(f"INFO: Updated host object '{name}' to {value}, id={existing}")
                    return existing
               url = self.server + api_path
               post_data = {"name": name, "value": value, "type": "Host"}
               r = self.rest_post(url, post_data)
               obj_id = r.json()['id']
               print(f"INFO: Created host object '{name}', id={obj_id}")
               return obj_id
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in _create_host_object '{name}', {str(e)}")

     def _create_port_object(self, name, port, protocol="TCP"):
          """Create a TCP/UDP port object; return its id (existing or new)."""
          try:
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/protocolportobjects"
               url = self.server + api_path + '?offset=0&limit=10000'
               r = self.rest_get(url)
               if 'items' in r.json():
                    for item in r.json()['items']:
                         if item['name'] == name:
                              print(f"INFO: Port object '{name}' already exists, id={item['id']}")
                              return str(item['id'])
               post_url = self.server + "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/protocolportobjects"
               post_data = {"name": name, "port": str(port), "protocol": protocol, "type": "ProtocolPortObject"}
               r = self.rest_post(post_url, post_data)
               obj_id = r.json()['id']
               print(f"INFO: Created port object '{name}', id={obj_id}")
               return obj_id
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in _create_port_object '{name}', {str(e)}")

     def _create_network_group(self, name, members):
          """Create or update a NetworkGroup containing the given members.
          `members` is a list of either object ids (treated as Network) or {'id', 'type'} dicts
          for mixed Network/Host membership. Returns the group id."""
          try:
               normalized = [m if isinstance(m, dict) else {"type": "Network", "id": m} for m in members]
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups"
               url = self.server + api_path + '?offset=0&limit=10000&expanded=true'
               r = self.rest_get(url)
               existing = None
               for item in r.json().get('items', []):
                    if item['name'] == name:
                         existing = item
                         break
               if existing:
                    current_ids = {o.get('id') for o in existing.get('objects', [])}
                    desired_ids = {m['id'] for m in normalized}
                    if current_ids == desired_ids:
                         print(f"INFO: Network group '{name}' already exists with same members, id={existing['id']}")
                         return str(existing['id'])
                    existing['objects'] = normalized
                    existing.pop('metadata', None)
                    existing.pop('links', None)
                    self.rest_put(self.server + api_path + '/' + existing['id'], existing)
                    print(f"INFO: Updated network group '{name}' members, id={existing['id']}")
                    return str(existing['id'])
               post_data = {"name": name, "type": "NetworkGroup", "objects": normalized}
               r = self.rest_post(self.server + api_path, post_data)
               grp_id = r.json()['id']
               print(f"INFO: Created network group '{name}', id={grp_id}")
               return grp_id
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in _create_network_group '{name}', {str(e)}")

     def _get_or_create_nat_policy(self, name):
          """Return (id, created) for a FTD NAT policy; create if absent."""
          try:
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/ftdnatpolicies"
               url = self.server + api_path + '?offset=0&limit=10000'
               r = self.rest_get(url)
               if 'items' in r.json():
                    for item in r.json()['items']:
                         if item['name'] == name:
                              print(f"INFO: NAT policy '{name}' already exists, id={item['id']}")
                              return str(item['id']), False
               post_data = {"name": name, "type": "FTDNatPolicy"}
               r = self.rest_post(self.server + api_path, post_data)
               pol_id = r.json()['id']
               print(f"INFO: Created NAT policy '{name}', id={pol_id}")
               return pol_id, True
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in _get_or_create_nat_policy, {str(e)}")

     def _get_subnet_gateway(self, project_id, region, subnet_name):
          """Return the default gateway for a GCP subnet (always network_address + 1)."""
          try:
               import ipaddress
               from googleapiclient import discovery
               api = discovery.build('compute', 'v1', cache_discovery=False)
               result = api.subnetworks().get(project=project_id, region=region, subnetwork=subnet_name).execute()
               cidr = result['ipCidrRange']
               gateway = str(ipaddress.IPv4Network(cidr).network_address + 1)
               print(f"INFO: Subnet '{subnet_name}' CIDR={cidr} gateway={gateway}")
               return gateway
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in _get_subnet_gateway '{subnet_name}', {str(e)}")

     def _get_forwarding_rule_ip(self, project_id, region, rule_name):
          """Look up a GCP forwarding rule IP address via the Compute API. Returns None if not found."""
          try:
               from googleapiclient import discovery
               from googleapiclient.errors import HttpError
               api = discovery.build('compute', 'v1', cache_discovery=False)
               result = api.forwardingRules().get(project=project_id, region=region, forwardingRule=rule_name).execute()
               ip = result.get('IPAddress')
               print(f"INFO: Forwarding rule '{rule_name}' IP = {ip}")
               return ip
          except HttpError as e:
               if e.resp.status == 404:
                    print(f"INFO: Forwarding rule '{rule_name}' not found, skipping")
                    return None
               raise Exception(f"ERROR: Exception occurred in _get_forwarding_rule_ip '{rule_name}', {str(e)}")
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in _get_forwarding_rule_ip '{rule_name}', {str(e)}")

     def _add_dynamic_nat_rule(self, nat_policy_id, rule_name, src_zone_id, dst_zone_id,
                               original_src_id, original_dst_id, original_dst_port_id,
                               translated_dst_id, translated_dst_port_id):
          """
          Add a manual DYNAMIC NAT rule:
            nat (src_zone,dst_zone) source dynamic GCP-HC interface
                                    destination static <LB-VIP>:<hc-port> METADATA:80

          Uses interfaceInTranslatedSource=True so the egress interface IP is used as the
          PAT source — ensuring GCP can route the metadata server response back.
          originalDestination is the explicit LB VIP host object.
          """
          try:
               api_path = (f"/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f"
                           f"/policy/ftdnatpolicies/{nat_policy_id}/manualnatrules")
               # Single expanded GET avoids the N+1 per-item detail lookups; match on name
               # (with description as a fallback for rules created before this change).
               url = self.server + api_path + '?offset=0&limit=10000&expanded=true'
               r = self.rest_get(url)
               for item in r.json().get('items', []):
                    if item.get('name') == rule_name or item.get('description') == rule_name:
                         print(f"INFO: NAT rule '{rule_name}' already exists, skipping")
                         return str(item['id'])
               post_data = {
                    "type": "FTDManualNatRule",
                    "natType": "DYNAMIC",
                    "unidirectional": True,
                    "name": rule_name,
                    "description": rule_name,
                    "enabled": True,
                    "interfaceInOriginalDestination": False,
                    "interfaceInTranslatedSource": True,
                    "originalSource": {"type": "NetworkGroup", "id": original_src_id},
                    "originalDestination": {"type": "Host", "id": original_dst_id},
                    "originalDestinationPort": {"type": "ProtocolPortObject", "id": original_dst_port_id},
                    "translatedDestination": {"type": "Host", "id": translated_dst_id},
                    "translatedDestinationPort": {"type": "ProtocolPortObject", "id": translated_dst_port_id},
                    "sourceInterface": {"type": "SecurityZone", "id": src_zone_id},
                    "destinationInterface": {"type": "SecurityZone", "id": dst_zone_id},
               }
               r = self.rest_post(self.server + api_path.split('?')[0], post_data)
               rule_id = r.json()['id']
               print(f"INFO: Created NAT rule '{rule_name}', id={rule_id}")
               return rule_id
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in _add_dynamic_nat_rule '{rule_name}', {str(e)}")

     def _assign_nat_policy_to_device(self, nat_policy_id, nat_policy_name, device_id, device_name):
          """Assign a NAT policy to a device; skip if already assigned."""
          try:
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/assignment/policyassignments"
               url = self.server + api_path + '?offset=0&limit=10000'
               r = self.rest_get(url)
               if 'items' in r.json():
                    for item in r.json()['items']:
                         if item.get('policy', {}).get('id') == nat_policy_id:
                              for dev in item.get('targets', []):
                                   if dev.get('id') == device_id:
                                        print(f"INFO: NAT policy already assigned to device '{device_name}', skipping")
                                        return
               post_data = {
                    "type": "PolicyAssignment",
                    "policy": {"type": "FTDNatPolicy", "id": nat_policy_id, "name": nat_policy_name},
                    "targets": [{"type": "Device", "id": device_id, "name": device_name}],
               }
               r = self.rest_post(self.server + api_path, post_data)
               print(f"INFO: Assigned NAT policy '{nat_policy_name}' to device '{device_name}'")
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in _assign_nat_policy_to_device, {str(e)}")

     def _assign_nat_policy_to_cluster(self, nat_policy_id, nat_policy_name, cluster_id, cluster_name):
          """Assign a NAT policy to a device cluster (all members); skip if already assigned."""
          try:
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/assignment/policyassignments"
               url = self.server + api_path + '?offset=0&limit=10000&expanded=true'
               r = self.rest_get(url)
               for item in r.json().get('items', []):
                    if item.get('policy', {}).get('id') != nat_policy_id:
                         continue
                    if any(t.get('id') == cluster_id for t in item.get('targets', [])):
                         print(f"INFO: NAT policy already assigned to cluster '{cluster_name}', skipping")
                         return
               post_data = {
                    "type": "PolicyAssignment",
                    "policy": {"type": "FTDNatPolicy", "id": nat_policy_id, "name": nat_policy_name},
                    "targets": [{"type": "DeviceCluster", "id": cluster_id, "name": cluster_name}],
               }
               r = self.rest_post(self.server + api_path, post_data)
               print(f"INFO: Assigned NAT policy '{nat_policy_name}' to cluster '{cluster_name}'")
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in _assign_nat_policy_to_cluster, {str(e)}")

     def _get_any_ipv4_network_id(self):
          """Return the object id of the built-in 'any-ipv4' network object."""
          try:
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkaddresses"
               url = self.server + api_path + '?offset=0&limit=10000'
               r = self.rest_get(url)
               for item in r.json().get('items', []):
                    if item.get('name') == 'any-ipv4':
                         return str(item['id'])
               raise Exception("'any-ipv4' network object not found in FMC")
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in _get_any_ipv4_network_id, {str(e)}")

     def _add_static_route(self, device_id, interface_name, network_obj_id, network_obj_name,
                           network_obj_type, gateway_host_id, gateway_host_name, metric=1):
          """Add an IPv4 static route on a device; skip if an identical route already exists."""
          try:
               api_path = (f"/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f"
                           f"/devices/devicerecords/{device_id}/routing/ipv4staticroutes")
               r = self.rest_get(self.server + api_path + '?offset=0&limit=10000&expanded=true')
               for item in r.json().get('items', []):
                    if (item.get('interfaceName') == interface_name and
                            any(n.get('id') == network_obj_id
                                for n in item.get('selectedNetworks', []))):
                         print(f"INFO: Static route {network_obj_name} via {interface_name} already exists, skipping")
                         return str(item['id'])
               post_data = {
                    "type": "IPv4StaticRoute",
                    "interfaceName": interface_name,
                    "selectedNetworks": [{"type": network_obj_type, "id": network_obj_id, "name": network_obj_name}],
                    "gateway": {"object": {"type": "Host", "id": gateway_host_id, "name": gateway_host_name}},
                    "metricValue": metric,
                    "isTunneled": False,
               }
               r = self.rest_post(self.server + api_path, post_data)
               route_id = r.json()['id']
               print(f"INFO: Created static route {network_obj_name} via {interface_name}, id={route_id}")
               return route_id
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in _add_static_route, {str(e)}")

     def _ensure_ecmp_zone(self, device_id, inside_ifc_id, outside_ifc_id, zone_name="ecmp-default"):
          """Ensure an ECMP zone named `zone_name` exists with both inside and outside interfaces.
          Required for dual default routes to load-balance instead of FMC rejecting the second route."""
          try:
               api_path = (f"/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f"
                           f"/devices/devicerecords/{device_id}/routing/ecmpzones")
               r = self.rest_get(self.server + api_path + '?offset=0&limit=100&expanded=true')
               required = {inside_ifc_id, outside_ifc_id}
               existing_zone = None
               for item in r.json().get('items', []):
                    if item.get('name') == zone_name:
                         existing_zone = item
                         break
               if existing_zone:
                    members = {ifc.get('id') for ifc in existing_zone.get('interfaces', [])}
                    if required.issubset(members):
                         print(f"INFO: ECMP zone '{zone_name}' already has inside+outside, skipping")
                         return
                    # Zone exists but is missing one of our interfaces — PUT to add them
                    existing_zone['interfaces'] = [
                         {"id": inside_ifc_id, "type": "PhysicalInterface"},
                         {"id": outside_ifc_id, "type": "PhysicalInterface"},
                    ]
                    existing_zone.pop('metadata', None)
                    existing_zone.pop('links', None)
                    self.rest_put(self.server + api_path + '/' + existing_zone['id'], existing_zone)
                    print(f"INFO: Updated ECMP zone '{zone_name}' to include inside+outside")
                    return
               post_data = {
                    "name": zone_name,
                    "type": "ECMPZone",
                    "interfaces": [
                         {"id": inside_ifc_id, "type": "PhysicalInterface"},
                         {"id": outside_ifc_id, "type": "PhysicalInterface"},
                    ],
               }
               r = self.rest_post(self.server + api_path, post_data)
               print(f"INFO: Created ECMP zone '{zone_name}', id={r.json().get('id')}")
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in _ensure_ecmp_zone, {str(e)}")

     def _get_interface_ids(self, device_id, inside_ifname, outside_ifname):
          """Return (inside_ifc_id, outside_ifc_id) physical interface IDs by ifname."""
          try:
               api_path = (f"/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f"
                           f"/devices/devicerecords/{device_id}/physicalinterfaces")
               r = self.rest_get(self.server + api_path + '?offset=0&limit=100')
               inside_id = outside_id = None
               for item in r.json().get('items', []):
                    detail = self.rest_get(self.server + api_path + '/' + item['id'])
                    ifname = detail.json().get('ifname', '')
                    if ifname == inside_ifname:
                         inside_id = item['id']
                    elif ifname == outside_ifname:
                         outside_id = item['id']
               if not inside_id or not outside_id:
                    raise Exception(f"Could not find interfaces ifname='{inside_ifname}' or '{outside_ifname}'")
               return inside_id, outside_id
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in _get_interface_ids, {str(e)}")

     def _assign_interfaces_to_zones(self, device_id, inside_zone_id, outside_zone_id,
                                     inside_ifname="inside", outside_ifname="outside"):
          """Ensure the inside and outside physical interfaces are bound to their security zones.
          NAT rules reference zones by ID; if no interface is in the zone, the rule matches nothing."""
          try:
               api_path = (f"/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f"
                           f"/devices/devicerecords/{device_id}/physicalinterfaces")
               r = self.rest_get(self.server + api_path + '?offset=0&limit=100')
               for item in r.json().get('items', []):
                    detail = self.rest_get(self.server + api_path + '/' + item['id']).json()
                    ifname = detail.get('ifname', '')
                    if ifname not in (inside_ifname, outside_ifname):
                         continue
                    target_zone_id = inside_zone_id if ifname == inside_ifname else outside_zone_id
                    current_zone_id = detail.get('securityZone', {}).get('id')
                    if current_zone_id == target_zone_id:
                         print(f"INFO: Interface '{ifname}' already in correct zone")
                         continue
                    detail["securityZone"] = {"id": target_zone_id, "type": "SecurityZone"}
                    detail.pop("metadata", None)
                    detail.pop("links", None)
                    self.rest_put(self.server + api_path + '/' + item['id'], detail)
                    print(f"INFO: Assigned interface '{ifname}' to zone id={target_zone_id}")
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in _assign_interfaces_to_zones, {str(e)}")

     def configure_health_check_nat(self, cluster_name, inside_zone, outside_zone,
                                    ilb_hc_port, elb_hc_port=None,
                                    project_id=None, region=None, resource_name_prefix=None,
                                    ilb_ip_override=None, ilb_outside_ip_override=None,
                                    elb_ip_override=None,
                                    inside_subnet_name=None, outside_subnet_name=None):
          """
          Configure GCP LB health-check NAT rules, routing, and deploy for the registered cluster.

          NAT strategy (verified working):
            ILB inside: nat (inside,outside) source dynamic GCP-HC interface
                                             destination static ILB-inside-VIP:hc-port METADATA:80
            ILB outside: nat (outside,outside) source dynamic GCP-HC interface
                                               destination static ILB-outside-VIP:hc-port METADATA:80
            interfaceInTranslatedSource=True — egress interface IP used as PAT source so
            GCP can route metadata server response back via the correct VPC.

          Also configures:
            - Default routes (0.0.0.0/0) via inside and outside gateways with ECMP zone
            Gateways are auto-derived from GCP subnet CIDRs (network_address + 1).

          Args:
              cluster_name         : FMC cluster/device name
              inside_zone          : security zone name for inside interface (e.g. 'inside-sz')
              outside_zone         : security zone name for outside interface (e.g. 'outside-sz')
              ilb_hc_port          : ILB health-check TCP port (e.g. 8989)
              elb_hc_port          : ELB health-check TCP port; None for east-west deployments
              project_id           : GCP project ID
              region               : GCP region
              resource_name_prefix : prefix used to derive forwarding rule and subnet names
          """
          print(f"INFO: Configuring health-check NAT for cluster '{cluster_name}'")

          # 1. GCP-HC source network group (four probe ranges)
          net_id_1 = self._create_network_object("gcp-hc-src-130-211-0-22",    "130.211.0.0", 22)
          net_id_2 = self._create_network_object("gcp-hc-src-35-191-0-16",     "35.191.0.0",  16)
          net_id_3 = self._create_network_object("gcp-hc-src-209-85-152-0-22", "209.85.152.0", 22)
          net_id_4 = self._create_network_object("gcp-hc-src-209-85-204-0-22", "209.85.204.0", 22)
          grp_id   = self._create_network_group("gcp-hc-src-ranges",
                                                [net_id_1, net_id_2, net_id_3, net_id_4])

          # 2. METADATA host (translated destination = 169.254.169.254)
          metadata_host_id = self._create_host_object("gcp-hc-metadata", "169.254.169.254")

          # 3. Port objects
          hc_port_id         = self._create_port_object(f"gcp-hc-ilb-port-{ilb_hc_port}", ilb_hc_port)
          translated_port_id = self._create_port_object("gcp-hc-translated-port-80", 80)

          # 4. Zones — get or create, then ensure interfaces are bound
          inside_zone_id  = self._get_or_create_security_zone(inside_zone)
          outside_zone_id = self._get_or_create_security_zone(outside_zone)

          # 4b. Bind inside/outside physical interfaces to their zones on the control node.
          #     NAT rules reference zones by ID; empty zones cause the rules to never match.
          cluster_id_early = self.get_cluster_id_by_name(cluster_name)
          if cluster_id_early:
               try:
                    cluster_detail_url = (self.server +
                         f"/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f"
                         f"/deviceclusters/ftddevicecluster/{cluster_id_early}")
                    cr = self.rest_get(cluster_detail_url)
                    control_node_name = cr.json()['controlDevice']['deviceDetails']['name']
                    control_device_id = self.get_device_id_by_name(control_node_name)
                    if control_device_id:
                         self._assign_interfaces_to_zones(
                              control_device_id, inside_zone_id, outside_zone_id)
               except Exception as e:
                    print(f"WARNING: Could not bind interfaces to zones: {str(e)}")

          # 5. NAT policy
          nat_policy_name = f"{cluster_name}-gcp-hc-nat-policy"
          nat_policy_id, _ = self._get_or_create_nat_policy(nat_policy_name)

          # 6. Detect deployment type by which forwarding rules exist:
          #    east_west:    {prefix}-ftdv-fr-ilb-inside + {prefix}-ftdv-fr-ilb-outside
          #    north_south:  {prefix}-ftdv-fr-ilb       + {prefix}-ftdv-fr-elb
          ilb_inside_ip = ilb_ip_override or self._get_forwarding_rule_ip(
               project_id, region, f"{resource_name_prefix}-ftdv-fr-ilb-inside")
          if ilb_inside_ip:
               deployment_type = "east_west"
               ilb_rule1_ip = ilb_inside_ip
               ilb_rule2_ip = ilb_outside_ip_override or self._get_forwarding_rule_ip(
                    project_id, region, f"{resource_name_prefix}-ftdv-fr-ilb-outside")
               rule2_name = f"gcp-hc-ilb-outside-nat-rule-{ilb_hc_port}"
               rule2_host_obj_name = "gcp-hc-ilb-outside-ip"
               rule2_port_id = hc_port_id
          else:
               deployment_type = "north_south"
               ilb_rule1_ip = ilb_ip_override or self._get_forwarding_rule_ip(
                    project_id, region, f"{resource_name_prefix}-ftdv-fr-ilb")
               ilb_rule2_ip = elb_ip_override or self._get_forwarding_rule_ip(
                    project_id, region, f"{resource_name_prefix}-ftdv-fr-elb")
               rule2_name = f"gcp-hc-elb-nat-rule-{elb_hc_port or ilb_hc_port}"
               rule2_host_obj_name = "gcp-hc-elb-ip"
               rule2_port_id = (self._create_port_object(f"gcp-hc-elb-port-{elb_hc_port}", elb_hc_port)
                                if elb_hc_port else hc_port_id)
          print(f"INFO: Detected deployment type: {deployment_type}")

          # 6a. Rule 1 — inside,outside: probes destined to the inside ILB VIP
          if ilb_rule1_ip:
               ilb_host_id = self._create_host_object("gcp-hc-ilb-ip", ilb_rule1_ip)
               self._add_dynamic_nat_rule(
                    nat_policy_id=nat_policy_id,
                    rule_name=f"gcp-hc-ilb-nat-rule-{ilb_hc_port}",
                    src_zone_id=inside_zone_id,
                    dst_zone_id=outside_zone_id,
                    original_src_id=grp_id,
                    original_dst_id=ilb_host_id,
                    original_dst_port_id=hc_port_id,
                    translated_dst_id=metadata_host_id,
                    translated_dst_port_id=translated_port_id,
               )
          else:
               print(f"INFO: Inside ILB forwarding rule not found; skipping rule 1")

          # 6b. Rule 2 — outside,outside: outside ILB VIP (east_west) or ELB VIP (north_south)
          if ilb_rule2_ip:
               rule2_host_id = self._create_host_object(rule2_host_obj_name, ilb_rule2_ip)
               self._add_dynamic_nat_rule(
                    nat_policy_id=nat_policy_id,
                    rule_name=rule2_name,
                    src_zone_id=outside_zone_id,
                    dst_zone_id=outside_zone_id,
                    original_src_id=grp_id,
                    original_dst_id=rule2_host_id,
                    original_dst_port_id=rule2_port_id,
                    translated_dst_id=metadata_host_id,
                    translated_dst_port_id=translated_port_id,
               )
          else:
               print(f"INFO: Second forwarding rule not found ({deployment_type}); skipping rule 2")

          # 8. Assign NAT policy to the cluster (DeviceCluster target)
          cluster_id = self.get_cluster_id_by_name(cluster_name)
          if not cluster_id:
               raise Exception(f"ERROR: Cluster '{cluster_name}' not found in FMC for NAT policy assignment")
          self._assign_nat_policy_to_cluster(nat_policy_id, nat_policy_name, cluster_id, cluster_name)

          # 9. Static routes — required for health-check traffic to flow correctly.
          #    Gateways derived from GCP subnet CIDRs (network_address + 1).
          #    Routing API needs the control node's device record ID, not the cluster ID.
          #    A failure here MUST be fatal: NAT rules without routes leave ILBs UNHEALTHY,
          #    which is exactly the failure mode this function exists to fix.
          if project_id and region and resource_name_prefix:
               cluster_detail_url = (self.server +
                    f"/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f"
                    f"/deviceclusters/ftddevicecluster/{cluster_id}")
               cr = self.rest_get(cluster_detail_url)
               control_node_name = cr.json()['controlDevice']['deviceDetails']['name']
               device_id = self.get_device_id_by_name(control_node_name)
               if not device_id:
                    raise Exception(f"Control node '{control_node_name}' device record not found")
               print(f"INFO: Using control node '{control_node_name}' (id={device_id}) for route config")

               _inside_subnet  = inside_subnet_name  or f"{resource_name_prefix}-ftdv-inside-subnet"
               _outside_subnet = outside_subnet_name or f"{resource_name_prefix}-ftdv-outside-subnet"
               inside_gw  = self._get_subnet_gateway(project_id, region, _inside_subnet)
               outside_gw = self._get_subnet_gateway(project_id, region, _outside_subnet)

               # Route destination = HC source ranges + metadata host (NOT any-ipv4),
               # so we don't shadow user-added routes for actual data-plane traffic.
               hc_route_grp_id = self._create_network_group("gcp-hc-route-targets", [
                    {"type": "Network", "id": net_id_1},
                    {"type": "Network", "id": net_id_2},
                    {"type": "Network", "id": net_id_3},
                    {"type": "Network", "id": net_id_4},
                    {"type": "Host",    "id": metadata_host_id},
               ])

               outside_gw_id = self._create_host_object("gcp-outside-gw", outside_gw)
               self._add_static_route(device_id, "outside",
                                      hc_route_grp_id, "gcp-hc-route-targets", "NetworkGroup",
                                      outside_gw_id, "gcp-outside-gw", metric=1)

               inside_gw_id = self._create_host_object("gcp-inside-gw", inside_gw)
               # ECMP zone is required by FMC when two routes for the same destination
               # exit different interfaces with the same metric.
               inside_ifc_id, outside_ifc_id = self._get_interface_ids(
                    device_id, "inside", "outside")
               self._ensure_ecmp_zone(device_id, inside_ifc_id, outside_ifc_id)
               self._add_static_route(device_id, "inside",
                                      hc_route_grp_id, "gcp-hc-route-targets", "NetworkGroup",
                                      inside_gw_id, "gcp-inside-gw", metric=1)

          # 10. Deploy
          # Use the `version` field returned by deployabledevices verbatim — FMC rejects
          # the deploy with "Policy was altered since the page was loaded" if we send a
          # mismatched/stale version (e.g. from get_time_stamp's audit-record heuristic).
          # Re-fetch immediately before POST to minimize the race with concurrent edits.
          print(f"INFO: Deploying NAT policy to '{cluster_name}'")
          try:
               api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/deployment/deployabledevices"
               r = self.rest_get(self.server + api_path + "?expanded=true")
               deploy_device_id = None
               deploy_version   = None
               for item in r.json().get('items', []):
                    if item.get('name') == cluster_name:
                         deploy_device_id = item.get('device', {}).get('id')
                         deploy_version   = item.get('version')
                         break
               if not deploy_device_id:
                    print(f"INFO: No pending deployable changes found for '{cluster_name}', skipping deploy")
               else:
                    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/deployment/deploymentrequests"
                    post_data = {
                         "type": "DeploymentRequest",
                         "version": str(deploy_version),
                         "forceDeploy": True,
                         "ignoreWarning": True,
                         "deviceList": [deploy_device_id],
                    }
                    r = self.rest_post(self.server + api_path, post_data)
                    task_id = r.json().get('metadata', {}).get('task', {}).get('id', '')
                    print(f"INFO: Deploy started, task_id={task_id}, version={deploy_version}")
          except Exception as e:
               raise Exception(f"ERROR: Exception occurred in deploy for '{cluster_name}', {str(e)}")
          print(f"INFO: Health-check NAT configuration complete for '{cluster_name}'")
