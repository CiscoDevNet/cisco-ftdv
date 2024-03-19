"""
Copyright (c) 2023 Cisco Systems Inc or its affiliates.
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
from fmc_functions import FirepowerManagementCenter
import urllib3
import os
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def scale_in(event, context):
     """Triggered from a message on a Cloud Pub/Sub topic.
     Args:
          event (dict): Event payload.
          context (google.cloud.functions.Context): Metadata for the event.
     """
     
     data_buffer = base64.b64decode(event['data'])
     log_entry = json.loads(data_buffer)

     # To get the Instance Name
     resourceName = log_entry['protoPayload']['resourceName']
     pos = resourceName.find("instances/")
     instanceName = resourceName[pos+len("instances/"):]
     instance_suffix = instanceName[-4:] #last 4 characters of instance name
     
     #VM name based on instance name of FTDv
     vm_name = os.getenv("INSTANCE_PREFIX_IN_FMC") + "-" + instance_suffix
     print("Deregistration of FTDv: "+vm_name)

     fmc = FirepowerManagementCenter()

     device_id = fmc.get_device_id_by_name(vm_name)
     if device_id == '':
          print("Device not registered on FMC")
          return
          
     r = fmc.deregister_device(vm_name)
     device_id = fmc.get_device_id_by_name(vm_name)
     if device_id == '':
          print("Deregistration Successful of " + vm_name)
          return