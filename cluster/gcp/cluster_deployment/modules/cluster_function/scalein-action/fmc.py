"""
Copyright (c) 2023-25 Cisco Systems Inc or its affiliates.
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

FMC_DEVICE_CLUSTER_BASE_PATH = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/deviceclusters/ftddevicecluster"

class FirepowerManagementCenter:
     def __init__(self, ip, user, password):
          self.server = 'https://' + ip
          self.username = user
          self.password = password
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
          print("Authentication URL: "+ auth_url)
          try:
               # 2 ways of making a REST call are provided:
               # One with "SSL verification turned off" and the other with "SSL verification turned on".
               # The one with "SSL verification turned off" is commented out. If you like to use that then
               # uncomment the line where verify=False and comment the line with =verify='/path/to/ssl_certificate'
               # REST call with SSL verification turned off:
               r = requests.post(auth_url, headers=self.headers, auth=requests.auth.HTTPBasicAuth(self.username, self.password), verify=False, timeout=30)
               print("R in get_auth_token: "+ str(r))
               # REST call with SSL verification turned on: Download SSL certificates
               # from your FMC first and provide its path for verification.
               # r = requests.post(auth_url, headers=self.headers,
               #                   auth=requests.auth.HTTPBasicAuth(username,password), verify='/path/to/ssl_certificate')
               auth_headers = r.headers
               auth_token = auth_headers.get('X-auth-access-token', default=None)
               self.domain_uuid = auth_headers.get('domain_uuid', default=None)
               self.headers['X-auth-access-token'] = auth_token
               self.authTokenTimestamp = int(time.time())
               if auth_token is None:
                    print("auth_token not found")
          except Exception as err:
               print("Error in generating Auth Token")
               print("Error in generating auth token --> " + str(err))
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
               print("Requesting(rest_get):" + str(url))
               r = requests.get(url, headers=self.headers, verify=False, timeout=30)
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
     
     
     def rest_delete(self, url):
          """
          Purpose:    Issue REST delete to the specified URL
          Parameters: url
          Returns:    This function will return 'r' which is the response to the request:
                    r.text is the text response (r.json() is a python dict version of the json response)
                    r.status_code = 2xx on success
          Raises:
          """
          if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
               print("Getting a new authToken")
               self.get_auth_token()

          try:
               print("Requesting(rest_delete):" + str(url))
               r = requests.delete(url, headers=self.headers, verify=False, timeout=60)
               status_code = r.status_code
               resp = r.text
               print("Response Status Code(rest_delete): " + str(status_code))
               print("Response body(rest_delete): " + str(resp))
               if 200 <= status_code <= 300:
                    pass
               else:
                    r.raise_for_status()
                    print("Exception occurred in rest_delete")
                    raise Exception("Error occurred in Delete -->"+str(resp))
          except requests.exceptions.HTTPError as err:
               raise Exception("Error in connection --> "+str(err))
          finally:
               if r: r.close()
               return r

     def get_device_id_by_name(self, vm_name):
          """
          Purpose:    Get Device Id by its name
          Parameters: Device Name
          Returns:    Device Id
          Raises:
          """
          api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords"
          url = self.server + api_path + '?offset=0&limit=10000'
          r = self.rest_get(url)
          if 'items' in r.json():
               for item in r.json()['items']:
                    if item['name'] == vm_name:
                         return str(item['id'])
          # or return empty string
          return ""

     def deregister_device(self, name, cluster_id, fmc_devices_list):
          """
          Purpose:    De-registers the device from FMC
          Parameters: Device Name
          Returns:    REST delete response
          Raises:
          """
          print(f"De-registering: {name}, fmc devices list: {fmc_devices_list}")

          dev_id = self.get_device_id_by_name(name)

          base_path = f"{FMC_DEVICE_CLUSTER_BASE_PATH}/{cluster_id}"
          api_path = base_path if len(fmc_devices_list) == 1 else f"{base_path}?filter=dataDeviceIds:{dev_id}"
          url = self.server + api_path
          r = self.rest_delete(url)
          return r
     
     def get_cluster_id_by_name(self, grp_name):
        """
        Parameters:
        Returns:    Cluster Id or None
        Raises:
        """
        count = 1
        while count<=3:
            api_path = FMC_DEVICE_CLUSTER_BASE_PATH
            url = self.server + api_path + '?offset=0&limit=9000'
            r = self.rest_get(url)
            if 'items' in r.json():
                for item in r.json()['items']:
                    if item['name'] == grp_name:
                        return str(item['id'])
            time.sleep(10)
            count += 1
        return None
     
     def get_cluster_members(self, cls_id):
        """
        Purpose:    To get devices name list from cluster
        Parameters: Cluster Id
        Returns:    list or None
        Raises:
        """
        count = 1
        while count<=3:
            member_name_list = []
            member_id_list= []
            api_path = f"{FMC_DEVICE_CLUSTER_BASE_PATH}/{cls_id}"
            url = self.server + api_path
            r = self.rest_get(url)
            if 'controlDevice' in r.json():
                # Add Control Node
                member_id_list.append(r.json()['controlDevice']['deviceDetails']['id'])
                member_name_list.append(r.json()['controlDevice']['deviceDetails']['name'])
                try:
                    # Add Data Nodes
                    for item in r.json()['dataDevices']:
                        member_id_list.append(item['deviceDetails']['id'])
                        member_name_list.append(item['deviceDetails']['name'])
                except:
                    pass
                break
            time.sleep(10)
            count += 1
        if member_name_list:
            return member_name_list,member_id_list
        else:
            return None

     