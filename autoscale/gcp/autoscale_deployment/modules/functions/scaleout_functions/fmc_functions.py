"""
Copyright (c) 2025 Cisco Systems Inc or its affiliates.
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
import json
import os


class FirepowerManagementCenter:
     def __init__(self):
          self.server = 'https://' + os.getenv('FMC_IP')
          self.username = os.getenv('FMC_USERNAME')
          self.password = os.getenv('FMC_PASSWORD')
          self.lic_caps = os.getenv('LICENSE_CAPS')
          self.headers = []
          self.domain_uuid = ""
          self.authTokenTimestamp = 0
          self.authTokenMaxAge = 15*60  # seconds - 30 minutes is the max without using refresh
          self.__config_url__ = '/api/fmc_config/v1/domain/'

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
          print("Authentication URL: "+ auth_url)
          try:
               # 2 ways of making a REST call are provided:
               # One with "SSL verification turned off" and the other with "SSL verification turned on".
               # The one with "SSL verification turned off" is commented out. If you like to use that then
               # uncomment the line where verify=False and comment the line with =verify='/path/to/ssl_certificate'
               # REST call with SSL verification turned off:
               r = requests.post(auth_url, headers=self.headers, auth=requests.auth.HTTPBasicAuth(self.username, self.password), verify=False)
               print("R in get_auth_token:"+ str(r))
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
                    print("auth_token not found")
          except Exception as err:
               print("Error in generating Auth Token")
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
          if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
               print("Getting a new authToken")
               self.get_auth_token()
          try:
               print("Requesting(rest_get):" + url)
               r = requests.get(url, headers=self.headers, verify=False)
               status_code = r.status_code
               resp = r.text
               print("Response Status Code(rest_get): " + str(status_code))
               print("Response body(rest_get): " + str(resp))
               if 200 <= status_code <= 300:
                    pass
               else:
                    print("Exception occurred in rest_get")
                    raise Exception("Error occurred in Get -->"+str(resp))
          except requests.exceptions.HTTPError as err:
               print("Exception occurred in Connection")
               raise Exception("Error in connection --> "+str(err))
          finally:
               if r: r.close()
               return r
     
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
          if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
               print("Getting a new authToken")
               self.get_auth_token()
          try:
               print("Requesting(rest_post): " + url)
               r = requests.post(url, data=json.dumps(post_data), headers=self.headers, verify=False)
               status_code = r.status_code
               resp = r.text
               print("Response Status Code(rest_post): "+ str(status_code))
               print("Response body(rest_post): " + str(resp))
               if 201 <= status_code <= 202:
                    pass
               else:
                    r.raise_for_status()
                    print("Exception occurred in rest_post")
                    raise Exception("Error occurred in POST --> "+str(resp))
          except requests.exceptions.HTTPError as err:
               raise Exception("Error in connection --> "+str(err))
          finally:
               if r: r.close()
               return r

     def rest_put(self, url, put_data):
          """
          Purpose:    Issue REST put to specific url with the put_data provided
          Parameters: url, put data
          Returns:    This function will return 'r' which is the response from the put:
                    r.text is the text response (r.json() is a python dict version of the json response)
                    r.status_code = 2xx on success
          Raises:
          """
          if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
               print("Getting a new authToken")
               self.get_auth_token()
          try:
               print("Requesting(rest_put): " + url)
               r = requests.put(url, data=json.dumps(put_data), headers=self.headers, verify=False)
               # REST call with SSL verification turned on:
               # r = requests.put(url, data=json.dumps(put_data), headers=headers, verify='/path/to/ssl_certificate')
               status_code = r.status_code
               resp = r.text
               print("Response Status Code(rest_put): " + str(status_code))
               print("Response body(rest_put): " + str(resp))
               if status_code == 200:
                    pass
               else:
                    r.raise_for_status()
                    print("Exception occurred in rest_put")
                    raise Exception("Error occurred in put -->" + str(resp))
          except requests.exceptions.HTTPError as err:
               raise Exception("Error in connection --> "+str(err))
          finally:
               if r: r.close()
               return r

     def get_access_policy_id_by_name(self, name):
          """
          Purpose:    Get Access Policy Id by its name
          Parameters: Access policy name
          Returns:    Access Policy Id, None
          Raises:
          """
          api_path = self.__config_url__+self.domain_uuid+"/policy/accesspolicies"
          url = self.server + api_path + '?offset=0&limit=10000'
          r = self.rest_get(url)
          # Search for policy by name
          if 'items' in r.json():
               for item in r.json()['items']:
                    if item['name'] == name:
                         return str(item['id'])
          return None

     #policy id => access policy id
     def register_ftdv(self, vm_name, mgmtip, reg_id, nat_id, policy_id, grp_id):
          """
          Purpose:    Register the device to FMC
          Parameters: Device Name, Mgmgt Ip, Registration & NAT id, Licenses cap, grp id
          Returns:    Task id, None
          Raises:
          """
          existing_device_id = self.get_device_id_by_name(vm_name)
          if existing_device_id != '':
               print("Device {} already registered on FMC, skipping registration".format(vm_name))
               return None
          try:
               vm_policy_id = self.get_access_policy_id_by_name(policy_id)
          except Exception as e:
               print("Access Policy does not exist")
               return None
          else:
               if vm_policy_id is not None:
                    print("Registering FTDv: " + vm_name + " to FMCv with policy id: " + vm_policy_id)
                    grp_id = self.get_device_grp_id_by_name(grp_id)
                    ## raise Exception if Device Group ID does not exist
                    if grp_id is None:
                         raise Exception("Device Group does not exist, please create..")
                    r = self.register_device(vm_name, mgmtip, vm_policy_id, reg_id, nat_id, grp_id)
                    if 'type' in r.json():
                         if r.json()['type'] == 'Device':
                              return r.json()['metadata']['task']['id']
               else:
                    print("No policy found")
               return None

     def register_device(self, name, mgmt_ip, policy_id, reg_id, nat_id, grp_id):
          """
          Purpose:    Register the device to FMC
          Parameters: Name of device, Mgmt ip, Access Policy Id, Registration & NAT id, Licenses Caps, Group Id
          Returns:    REST post response
          Raises:
          """
          lic_caps = self.lic_caps.split(",")
          print("Registering: "+ name)
          api_path = self.__config_url__+self.domain_uuid+"/devices/devicerecords"
          url = self.server + api_path
          post_data = {
               "name": name,
               "hostName": mgmt_ip,
               "regKey": reg_id,
               "natID": nat_id,
               "type": "Device",
               "license_caps": lic_caps,
               "accessPolicy": {
                    "id": policy_id,
                    "type": "AccessPolicy"
               },
               "deviceGroup": {
                    "id": grp_id,
                    "type": "DeviceGroup"
               }
          }

          r = self.rest_post(url, post_data)
          return r

     def get_device_id_by_name(self, vm_name):
          """
          Purpose:    Get Device Id by its name
          Parameters: Device Name
          Returns:    Device Id
          Raises:
          """
          api_path = self.__config_url__+self.domain_uuid+"/devices/devicerecords"
          url = self.server + api_path + '?offset=0&limit=10000'
          r = self.rest_get(url)
          if 'items' in r.json():
               for item in r.json()['items']:
                    if item['name'] == vm_name:
                         return str(item['id'])
          # or return empty string
          return ''

     def get_device_grp_id_by_name(self, name):
          """
          Purpose:    To get device group id by passing name of the group
          Parameters: Name of device group
          Returns:    Group Id or None
          Raises:
          """
          api_path = self.__config_url__+self.domain_uuid+"/devicegroups/devicegrouprecords"
          url = self.server + api_path + '?offset=0&limit=9000'
          r = self.rest_get(url)
          if 'items' in r.json():
               for item in r.json()['items']:
                    if item['name'] == name:
                         return str(item['id'])
          return None

     def check_reg_status_from_fmc(self, vm_name):
          """
          Purpose:    Checks if device is registered to FMC
          Parameters: Device Name
          Returns:    SUCCESS, FAILED
          Raises:
          """
          try:
               device_id = self.get_device_id_by_name(vm_name)
          except Exception as e:
               print("Exception in check_reg_status_from_fmc"+ str(e))
          else:
               if device_id != '':
                    return "SUCCESS"
               else:
                    return "FAILED"

     def get_security_objectid_by_name(self, name):
          """
          Purpose:    Get Zone ID from it's name
          Parameters: Zone Name
          Returns:    Zone ID, None
          Raises:
          """
          api_path = self.__config_url__+self.domain_uuid+"/object/securityzones"
          url = self.server + api_path + '?offset=0&limit=9000'
          r = self.rest_get(url)
          if 'items' in r.json():
               for item in r.json()['items']:
                    if item['name'] == name:
                         return str(item['id'])
          return None
     
     def get_network_objectid_by_name(self, name):
          """
          Purpose:    Get Network object Id by its name
          Parameters: Object Name
          Returns:    Object Id
          Raises:
          """
          api_path = self.__config_url__+self.domain_uuid+"/object/networkaddresses"
          url = self.server + api_path + '?offset=0&limit=10000'
          r = self.rest_get(url)
          for item in r.json()['items']:
               if item['type'] == 'Network' and item['name'] == name:
                    return str(item['id'])
          return ''
     
     def get_static_routeid_by_name(self, device_name):
          """
          Purpose:    Get Network object Id by its name
          Parameters: Object Name
          Returns:    Object Id
          Raises:
          """
          device_id = self.get_device_id_by_name(device_name)
          api_path = self.__config_url__+self.domain_uuid+"/devices/devicerecords/" + device_id + "/routing/ipv4staticroutes"
          url = self.server + api_path
          r = self.rest_get(url)
          return ''
     
     def get_static_routeid(self):
          """
          Purpose:    Get Network object Id by its name
          Parameters: Object Name
          Returns:    Object Id
          Raises:
          """
          api_path = self.__config_url__+self.domain_uuid+"/devices/devicerecords/8a4633e2-e48d-11eb-a074-b8d647c0a433/routing/ipv4staticroutes"
          url = self.server + api_path
          r = self.rest_get(url)
          return ''
          
     def get_nic_id_by_name(self, device_name, nic_name):
          """
          Purpose:    Get Nic Id by device & nic name
          Parameters: Device Name, Nic name
          Returns:    Nic Id, None
          Raises:
          """
          valid_nics = {'Ethernet0/0', 'Ethernet0/1', 'GigabitEthernet0/0', 'GigabitEthernet0/1'}
          if nic_name not in valid_nics:
               print("Warning - nic name must be one of " + ", ".join(sorted(valid_nics)) + ". "
                              "The nic name found was " + nic_name)
          device_id = self.get_device_id_by_name(device_name)
          api_path = self.__config_url__+self.domain_uuid+"/devices/devicerecords/" + device_id + "/physicalinterfaces"
          url = self.server + api_path + '?offset=0&limit=10000'
          r = self.rest_get(url)
          if 'items' in r.json():
               for item in r.json()['items']:
                    if item['name'] == nic_name:
                         return str(item['id'])
          return None

     def get_loopback_nic_id_by_name(self, device_name, nic_name):
          """
          Purpose:    Get Loopback Nic Id by device & nic name
          Parameters: Device Name, Nic name
          Returns:    Nic Id, None
          Raises:
          """
          device_id = self.get_device_id_by_name(device_name)
          api_path = self.__config_url__+self.domain_uuid+"/devices/devicerecords/" + device_id + "/loopbackinterfaces"
          url = self.server + api_path + '?offset=0&limit=10000'
          r = self.rest_get(url)
          if 'items' in r.json():
               for item in r.json()['items']:
                    if item['name'] == nic_name:
                         return str(item['id'])
          return None
     
     def configure_nic_dhcp(self, device_name, nic, nic_name, zone, mtu):
          """
          Purpose:    Configure an Nic interface as DHCP
          Parameters: Device Name, Nic, Nic name, Zone, MTU
          Returns:    REST put response
          Raises:
          """
          device_id = self.get_device_id_by_name(device_name)
          nic_id = self.get_nic_id_by_name(device_name, nic)
          zone_id = self.get_security_objectid_by_name(zone)

          if zone_id is None:
               raise Exception(f"Security Zone {zone} does not exist, please create!")

          if nic_id != None:
               api_path = self.__config_url__+self.domain_uuid+"/devices/devicerecords/" + \
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

     def get_host_objectid_by_name(self, name):
          """
          Purpose:    Get Host object Id by Name
          Parameters: Object Name
          Returns:    Object Id
          Raises:
          """
          api_path = self.__config_url__+self.domain_uuid+"/object/hosts"
          url = self.server + api_path + '?offset=0&limit=10000'
          r = self.rest_get(url)
          for item in r.json()['items']:
               if item['type'] == 'Host' and item['name'] == name:
                    return str(item['id'])
          return ''

     def create_static_network_route(self, device, interface_name, network_object_name, host_object_name_gw, metric):
          """
          Purpose:    To create static network route on device
          Parameters: Device, Interface Name, Network, Gateway, Metric
          Returns:    REST response
          Raises:
          """
          print("Static route creation: Interface->"+interface_name+" Network Object->"+network_object_name+
                    " Gateway Object->"+host_object_name_gw+" Metric->"+str(metric))
          ngfwid = self.get_device_id_by_name(device)
          network_object_id = self.get_network_objectid_by_name(network_object_name)
          host_object_id_gw = self.get_host_objectid_by_name(host_object_name_gw)
          api_path = self.__config_url__+self.domain_uuid+"/devices/devicerecords/" + ngfwid + \
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

     def get_deployable_devices(self):
          """
          Purpose:    Get list of deployable devices
          Parameters:
          Returns:    List of devices, pending to be deployed
          Raises:
          """
          api_path = self.__config_url__+self.domain_uuid+"/deployment/deployabledevices"
          url = self.server + api_path
          r = self.rest_get(url)
          print("Deployable devices:" + str(r.json()))
          device_list = []
          if 'items' in r.json():
               for item in r.json()['items']:
                    if item['type'] == 'DeployableDevice':
                         device_list.append(item['name'])
          return device_list

     def start_deployment(self, device_name):
          """
          Purpose:    Deploys policy changes on device
          Parameters: Device name
          Returns:    Task Id
          Raises:
          """
          print("Deploy called for: " + device_name)
          device_list = self.get_deployable_devices()
          #to test whether auth failed in first instance reg
          device_list = self.get_deployable_devices()
          if device_name in device_list:
               print("Deploying on device: " + device_name)
               api_path = self.__config_url__+self.domain_uuid+"/deployment/deploymentrequests"
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

     def get_time_stamp(self):
          """
          Purpose:    Get time stamp
          Parameters:
          Returns:    Audit time stamp
          Raises:
          """
          api_path = "/api/fmc_platform/v1/domain/"+self.domain_uuid+"/audit/auditrecords"
          url = self.server + api_path
          r = self.rest_get(url)
          return r.json()['items'][0]['time']*1000

     def get_fmc_version(self):
          """
          Purpose:    Get FMC version
          Parameters:
          Returns:    FMC version
          Raises:
          """
          api_path = "/api/fmc_platform/v1/info/serverversion"
          url = self.server + api_path
          r = self.rest_get(url)
          server_version =  r.json()['items'][0]['serverVersion']
          return server_version[0:len("a.b.c")+1]

     def check_deploy_status(self, vm_name):
          """
          Purpose:    Checks if any deployment pending for device
          Parameters: Device name
          Returns:    DEPLOYED, NOT-DEPLOYED
          Raises:
          """
          device_id = self.get_device_id_by_name(vm_name)
          if device_id != '':
               r = self.get_deployable_devices()
               for device in r:
                    if device == vm_name:
                         print("Policies not deployed on " + vm_name)
                         return "NOT-DEPLOYED"
               print("Policies deployed on " + vm_name)
               return "DEPLOYED"
          else:
               print("Device "+vm_name+" not registered.")
     
     def ftdv_deploy_polling(self, vm_name, minutes):
          """
          Purpose:    To Poll for policy deployment completion of NGFW
          Parameters: FirepowerManagementCenter class object, Minutes
          Returns:    SUCCESS, FAILED
          Raises:
          """
          if minutes <= 1:
               minutes = 2
          for i in range(1, 4*minutes):
               self.start_deployment(vm_name)
               status = self.check_deploy_status(vm_name)
               if status != "DEPLOYED":
                    print(str(i) + " Sleeping for 15 seconds, Deploy in Progress")
                    time.sleep(1*15)
               else:
                    return "SUCCESS"
          return "FAILED"

     def execute_vm_deploy_first(self, vm_name):
          """
          Purpose:    This deploys policies on the device
          Parameters: 
          Returns:    SUCCESS, FAIL
          Raises:
          """
          try:
               deploy_status = self.check_deploy_status(vm_name)
               if deploy_status != 'DEPLOYED':
                    if self.start_deployment(vm_name) is None:
                         raise ValueError("Configuration deployment REST post failing")
               deploy_status = self.ftdv_deploy_polling(vm_name, 5) #polling for 5 minutes
               if deploy_status != "SUCCESS":
                    raise ValueError("Configuration deployment failed")
               print("Configuration is deployed, health status in TG needs to be checked")
               return 'SUCCESS'
          except ValueError as e:
               print("Exception(known) occurred {}".format(repr(e)))
          except Exception as e:
               print("Exception(un-known) occurred {}".format(e))
          return 'FAIL'
     
     def create_loopback(self, device_id, loopback_id, ifname, ip, mask):
          """
          Purpose:    Enable VTEP
          Parameters: 
          Returns:    REST post response
          Raises:
          """
          print("Creating Loopback Interface")
          api_path = self.__config_url__+self.domain_uuid+"/devices/devicerecords/"+device_id+"/loopbackinterfaces"
          url = self.server + api_path

          post_data = {
                      "type": "LoopbackInterface",
                      "loopbackId": loopback_id,
                      "enabled": True,
                      "ifname": ifname,
                      "ipv4": {
                        "static": {
                          "address": ip,
                          "netmask": mask
                        }
                      }
                    }

          #security zone may be added later

          r = self.rest_post(url, post_data)
          return r
     
     def create_virtual_router(self, device_name, device_id, vrf_name, interface1, interface_type = "PhysicalInterface", interface_name = "OUTSIDE"):
          """
          Purpose:    Enable VTEP
          Parameters: 
          Returns:    REST post response
          Raises:
          """
          print("Creating Virtual Router")
          api_path = self.__config_url__+self.domain_uuid+"/devices/devicerecords/"+device_id+"/routing/virtualrouters"
          url = self.server + api_path
          isLoopback = False
          if interface_type == "LoopbackInterface":
               isLoopback = True
          post_data = {
                      "type": "VirtualRouter",
                      "name": vrf_name,
                      "description": "Created by Automation",
                      "interfaces": [
                        {
                          "id": self.get_loopback_nic_id_by_name(device_name, interface1),
                          "type": interface_type,
                          "name": interface_name
                        }
                      ]
                    }
          #Multiple interfaces can be added, take care of interface type

          r = self.rest_post(url, post_data)
          return r
     
     def get_group_objectid_by_name(self, name):
          api_path = self.__config_url__+self.domain_uuid+"/object/networkgroups"
          url = self.server + api_path
          r = self.rest_get(url)
          for item in r.json()['items']:
               if item["name"] == name:
                    return str(item["id"])
          return ''
     
     def get_vrfid_by_name(self, device_name, vrf_name):
          device_id = self.get_device_id_by_name(device_name)
          api_path = self.__config_url__+self.domain_uuid+"/devices/devicerecords/" + device_id + "/routing/virtualrouters"
          url = self.server + api_path 
          r = self.rest_get(url)
          for item in r.json()['items']:
               if item["name"] == vrf_name:
                    return str(item["id"])
          return ''
     
     def add_host_object(self, name, ip):
          
          api_path = self.__config_url__+self.domain_uuid+"/object/hosts"
          url = self.server + api_path

          post_data = {"name": name,
                    "type": "Host",
                    "value": ip,
                    "description": ""
                    }

          r = self.rest_post(url, post_data)
          return r
           
     def add_networkgroup_object(self, name, ip_range):
          
          api_path = self.__config_url__+self.domain_uuid+"/object/networkgroups"
          url = self.server + api_path
          literals = []
          for ip in ip_range:
               obj = {
                    "type" : "Network",
                    "value" : ip
               }
               literals.append(obj)
          post_data = {"name": name,
                    "type": "NetworkGroup",
                    "literals" : literals
                    }

          r = self.rest_post(url, post_data)
          return r

     def create_static_network_route_loopback(self, device, interface_name, network_object_name, metric,  host_object_name_gw = '', isGlobalRouter=True, vrf_name = None):
          """
          Purpose:    To create static network route on device
          Parameters: Device, Interface Name, Network, Gateway, Metric
          Returns:    REST response
          Raises:
          """
          print("Static route creation: Interface->"+interface_name+" Network Object->"+network_object_name+
                    " Gateway Object->"+host_object_name_gw+" Metric->"+str(metric))
          ngfwid = self.get_device_id_by_name(device)
          network_type = "Network"
          network_object_id = self.get_network_objectid_by_name(network_object_name)
          if network_object_id == '':
               network_object_id = self.get_host_objectid_by_name(network_object_name)
               network_type = "Host"
               print("@@@@@@@@@@@@ Getting ILB IP network object grp from host object @@@@@@@@")
          if network_object_id == '':
               network_type = "NetworkGroup"
               network_object_id = self.get_group_objectid_by_name(network_object_name)
               print("############ Getting health check probe grp group object from group api #####")
          
               
          host_object_id_gw = self.get_host_objectid_by_name(host_object_name_gw)

          if isGlobalRouter:
               api_path = self.__config_url__+self.domain_uuid+"/devices/devicerecords/" + ngfwid + \
                    "/routing/ipv4staticroutes"
          else:
               vrf_id = self.get_vrfid_by_name(device_name=device, vrf_name=vrf_name)
               print("VRF ID is ", vrf_id, vrf_name)
               api_path = self.__config_url__+self.domain_uuid+"/devices/devicerecords/" + ngfwid + "/routing/virtualrouters/" + vrf_id + "/ipv4staticroutes"
          
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
                    "type": network_type,
                    "id": network_object_id,
                    "name": network_object_name
                    }
               ],
               "metricValue": metric,
               "type": "IPv4StaticRoute",
               "isTunneled": False
          }
          if host_object_name_gw:
               post_data["gateway"] = gate_way
          print("############ URL is ", url, " POST DATA is ", post_data, "#################")
          r = self.rest_post(url, post_data)
          return r
     
     def add_platform_policy(self, name):
          api_path = self.__config_url__+self.domain_uuid+"/policy/ftdplatformsettingspolicies"
          url = self.server + api_path

          post_data = {
               "type": "FTDPlatformSettingsPolicy",
               "name": name
          }

          r = self.rest_post(url, post_data)

          return r
     
     def get_platform_policy(self, name):
          api_path = self.__config_url__+self.domain_uuid+"/policy/ftdplatformsettingspolicies"
          url = self.server + api_path

          r = self.rest_get(url)

          if 'items' in r.json():
               for item in r.json()["items"]:
                    if item["name"] == name:
                         return str(item["id"])
          
          return ''
     
     def add_http_setting(self, policy_name, port, ip_address_objname, interface_name_array):
          poilcy_id = self.get_platform_policy(policy_name)
          api_path = self.__config_url__+self.domain_uuid+"/policy/ftdplatformsettingspolicies/" + poilcy_id + "/httpaccesssettings/" + poilcy_id
          url = self.server + api_path
          ip_address_id = self.get_group_objectid_by_name(ip_address_objname)
          post_data = {
               "id": poilcy_id,
               "enableHttpServer": "true",
               "port": port,
               "httpConfiguration": [
               {
                    "ipAddress": {
                    "name": ip_address_objname,
                    "id": ip_address_id,
                    "type": "Network"
                    },
                    "interfaces": {
                    "literals": interface_name_array
                    }
               }
               ]
          }
          print(post_data)
          
          r = self.rest_put(url, post_data)
          return r

     def get_http_setting(self, policy_name, port, ip_address_objname, interface_name):
          poilcy_id = self.get_platform_policy(policy_name)
          api_path = self.__config_url__+self.domain_uuid+"/policy/ftdplatformsettingspolicies/" + poilcy_id + "/httpaccesssettings/" + poilcy_id
          url = self.server + api_path

          r = self.rest_get(url)
          print(r.json())

          if all(key in r.json() for key in ("port", "httpConfiguration")) and ("literals" in r.json()["httpConfiguration"]):
               if int(r.json()["port"]) == port and r.json()["httpConfiguration"]["name"] == ip_address_objname and r.json()["httpConfiguration"]["literals"][0] == interface_name:
                    return True

          return False

     def add_policy_assignment(self, policy_name, device_group):
          api_path = self.__config_url__+self.domain_uuid+"/assignment/policyassignments"
          url = self.server + api_path
          policy_id = self.get_platform_policy(policy_name)
          device_group_id = self.get_device_grp_id_by_name(device_group)

          post_data = {
               "type": "PolicyAssignment",
               "policy": {
               "type": "FTDPlatformSettingsPolicy",
               "name": policy_name,
               "id": policy_id
               },
               "targets": [
               {
                    "id": device_group_id,
                    "type": "DeviceGroup",
                    "name": device_group
               }
               ]
          }
          print("******* POST DATA is", post_data)
          r = self.rest_post(url, post_data)
          return r

     def get_policy_assignment(self, policy_name):
          api_path = self.__config_url__+self.domain_uuid+"/assignment/policyassignments"
          url = self.server + api_path

          policy_id = self.get_platform_policy(policy_name)

          r = self.rest_get(url)

          if 'items' in r.json():
               for item in r.json()["items"]:
                    if str(item["id"]) == policy_id and item["name"]== policy_name:
                         return True         
          return False
