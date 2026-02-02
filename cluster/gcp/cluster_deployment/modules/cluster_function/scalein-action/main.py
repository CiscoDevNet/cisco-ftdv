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
Name:       main.py
Purpose:    main function
PreRequisites: User has to create <fmcPasswordSecret> in Secret Manager
"""

import base64
import json
import time
from fmc import FirepowerManagementCenter
from googleapiclient import discovery
import urllib3
import os
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def scale_in(event, context):
     """Triggered from a message on a Cloud Pub/Sub topic.
     Args:
          event (dict): Event payload.
          context (google.cloud.functions.Context): Metadata for the event.
     """
     start_time     = time.time()
     timeout_time   = 500
     # Reading event data
     data_buffer    = base64.b64decode(event['data'])
     log_entry      = json.loads(data_buffer)
     
     # Reading Environment variables
     fmc_ip         = os.getenv('FMC_IP')
     fmc_user       = os.getenv('FMC_USERNAME')
     fmc_password   = os.getenv('FMCV_PASSWORD')
     
     # To get the Instance Name
     resourceName = log_entry['protoPayload']['resourceName']
     pos = resourceName.find("instances/")
     instanceName = resourceName[pos+len("instances/"):]

     project_id = log_entry['resource']['labels']['project_id']
     zone = log_entry['resource']['labels']['zone']

     # Get the private and public ips of the mgmt interface of the instance here
     api = discovery.build('compute', 'v1', cache_discovery=False)
     response = api.instances().get(project=project_id, zone=zone, instance=instanceName).execute()
     private_ip = response['networkInterfaces'][2]['networkIP']
     public_ip = response['networkInterfaces'][2]['accessConfigs'][0]['natIP']
     
     # Creating FMCv Object
     try:
        fmc = FirepowerManagementCenter(fmc_ip, fmc_user, fmc_password)
     except Exception as e:
        print("ERROR: Exception occured in creating FMCv object ",e)

     # Getting Cluster ID using name
     cls_id = fmc.get_cluster_id_by_name(os.getenv("CLS_GRP_NAME"))
     if cls_id == None:
          print("Cluster Group not found in FMCv")
          return
     
     # Getting cluster members list
     fmc_devices_list, device_id_list = fmc.get_cluster_members(cls_id)
     print("INFO: ",fmc_devices_list,device_id_list,public_ip,private_ip)

     # Identifying VM name
     vm_name = ""
     if public_ip in fmc_devices_list:
          vm_name = public_ip
     if private_ip in fmc_devices_list:
          vm_name = private_ip
    
     print("Deregistration of FTDv: "+vm_name)

     device_id = fmc.get_device_id_by_name(vm_name)
     if device_id == '':
          print("Device not registered on FMC")
          return
     
     # De-registering the device.
     while (time.time() - start_time) < timeout_time:
          try:
               r = fmc.deregister_device(vm_name, cls_id, fmc_devices_list)
               print("DEBUG: ",r.text)
          except Exception as e:
               print("ERROR: Exception occured in deregistering ftdv" + e)
          
          device_id = fmc.get_device_id_by_name(vm_name)
          if device_id == '':
               print("INFO: Deregistration Successful of " + vm_name)
               return
          time.sleep(20)
     else:
          print(f"ERROR: Device {vm_name} could not be deregistered, please deregister from FMCv manually")
     return