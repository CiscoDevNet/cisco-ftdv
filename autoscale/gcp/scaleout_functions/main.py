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
PreRequisites: User has to create <fmcPasswordSecret> and <newFtdPasswordSecret> 
               in Secret Manager
"""

# THIS FUNCTION WILL GET EXECUTED WHEN A NEW FTDv INSTANCE COMES UP

import base64
import json
from googleapiclient import discovery
import basic_functions as bf
import time
from fmc_functions import FirepowerManagementCenter
import urllib3
import os
import warnings
from cryptography.utils import CryptographyDeprecationWarning
with warnings.catch_warnings():
     warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)
     import paramiko
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def scale_out(event, context):
     """Triggered from a message on a Cloud Pub/Sub topic.
     Args:
          event (dict): Event payload.
          context (google.cloud.functions.Context): Metadata for the event.
     """

     # Since Google CLoud Functions have a timeout of max 540 seconds, and FTDv may take more time 
     # in bring up and registration process. So the function will get retriggered if functions get
     # timeout in the process of registration.
     
     start_time = time.time()
     timeout_time = 500
     #MAX retries for function, before timeout
     MAX_RETRIES_COUNT = 3
     first_run_flag = False  #the function triggers itself before timeout
     count = 0
     
     data_buffer = base64.b64decode(event['data'])
     log_entry = json.loads(data_buffer)


     try:
          #First run, Info from logs
          #To get the Instance Name
          resourceName = log_entry['protoPayload']['resourceName']
          pos = resourceName.find("instances/")
          instanceName = resourceName[pos+len("instances/"):]
          instance_suffix = instanceName[-4:] #last 4 characters of instance name
          project_id = log_entry['resource']['labels']['project_id']
          zone = log_entry['resource']['labels']['zone']
          api = discovery.build('compute', 'v1',cache_discovery=False)
          response = api.instances().get(project=project_id, zone=zone, instance=instanceName).execute()
          
          # mgmt ip -> nic2
          if  eval(os.getenv('SSH_USING_EXTERNAL_IP')) is False:
               #internal ip
               ssh_ip = response['networkInterfaces'][2]['networkIP']
          else:
               # this will fetch external ip, when FMCv is on other platform
               #external ip
               ssh_ip = response['networkInterfaces'][2]['accessConfigs'][0]['natIP'] #external

          print("FTDv Name: "+instanceName+ " IP for Login: "+ssh_ip)

          info_dict = {"Retry_function":"yes", "ssh_ip":ssh_ip,"instance_suffix":instance_suffix, "project_id": project_id, "count": count, "instanceName":instanceName, "zone":zone}
          first_run_flag = True
     except:
          prev_info = log_entry['textPayload']
          # Extracting the Dict part from string
          prev_info = prev_info[len("Second Attempt "):]
          #making json acceptable format
          prev_info = prev_info.replace("'", "\"")
          prev_info = json.loads(prev_info)

          count = prev_info["count"] + 1
          print("Function retriggered count: "+str(count))

     if count > MAX_RETRIES_COUNT:
          print("Number of retries exceeded "+str(MAX_RETRIES_COUNT))
          return
          
     try:
          prev_info = log_entry['textPayload']
          # Extracting the Dict part from string
          prev_info = prev_info[len("Second Attempt "):]
          #making json acceptable format
          prev_info = prev_info.replace("'", "\"")
          prev_info = json.loads(prev_info)

          instanceName = prev_info["instanceName"]
          ssh_ip = prev_info["ssh_ip"]
          instance_suffix = prev_info["instance_suffix"]
          project_id = prev_info["project_id"]
          zone = prev_info["zone"]
          print("Function(retriggered) for "+ instanceName)
     except:
          print("First run of function")
     
     
     fmc_ip = os.getenv('FMC_IP')
     reg_id = os.getenv('REG_ID')
     nat_id = os.getenv('NAT_ID')
     policy_id = os.getenv('POLICY_ID')
     grp_id = os.getenv('GRP_ID')

     minutes = 7

     user = "admin"
     password = os.getenv('FTDV_PASSWORD')

     if (time.time() - start_time) <= timeout_time:
          r,channel,ssh = bf.establishingConnection(ssh_ip, user, password, minutes)
          print("Establishing Connection Response: "+ r)
     else:
          print("ERROR: Console not up")
          print("Deleting Instance {}".format(instanceName))
          request_body = {
                           "instances": [
                             f"zones/{zone}/instances/{instanceName}"
                           ],
                           "skipInstancesOnValidationError": False
                         }
          api = discovery.build('compute', 'v1',cache_discovery=False)
          response = api.regionInstanceGroupManagers().deleteInstances(project=project_id, region=zone[:-2], instanceGroupManager=instanceName[:-5], body=request_body).execute()
          return

     if r == 'TIMEOUT':
          print("Timeout Retry")
          print("Second Attempt "+str(info_dict))
          return

     if r != 'SUCCESS':
          print("ERROR: Establishing Connection")
          print("Deleting Instance {}".format(instanceName))
          request_body = {
                           "instances": [
                             f"zones/{zone}/instances/{instanceName}"
                           ],
                           "skipInstancesOnValidationError": False
                         }
          api = discovery.build('compute', 'v1',cache_discovery=False)
          response = api.regionInstanceGroupManagers().deleteInstances(project=project_id, region=zone[:-2], instanceGroupManager=instanceName[:-5], body=request_body).execute()
          return

     if first_run_flag:
          bf.closeShell(ssh)
          print("Retriggering Function after FTDv console is up")
          print("Second Attempt "+str(info_dict))
          return
     
     
     conn_status = bf.checkConnection(channel)
     print("Connection Status: "+ conn_status)

     if conn_status == 'FAIL':
          print("ERROR: Connection Failure")
          print("Deleting Instance {}".format(instanceName))
          request_body = {
                           "instances": [
                             f"zones/{zone}/instances/{instanceName}"
                           ],
                           "skipInstancesOnValidationError": False
                         }
          api = discovery.build('compute', 'v1',cache_discovery=False)
          response = api.regionInstanceGroupManagers().deleteInstances(project=project_id, region=zone[:-2], instanceGroupManager=instanceName[:-5], body=request_body).execute()
          return

     ftd_version = bf.showVersion(channel)
    
     
     bf.configureManager(channel, fmc_ip, reg_id, nat_id)
    

     new_password = os.getenv('NEW_FTD_PASSWORD')
     r = bf.changePassword(channel, password, new_password)
     password = new_password
     
     bf.closeShell(ssh)
     
     # Name displayed in FMCv
     vm_name = os.getenv("INSTANCE_PREFIX_IN_FMC") + "-" + instance_suffix
     # We need to have these on FMCv
     # REG ID
     # NAT ID
     # ACL POLICY NAME
     # DEVICE GROUP
     # SECURITY ZONE
     # OBJECT
     # NAT POLICY

     fmc = FirepowerManagementCenter()

     fmc_version = fmc.get_fmc_version()
     versionCheck = bf.versionCheck(ftd_version, fmc_version)
     if versionCheck == 'SUCCESS':
          print("Version Check: SUCCESS")
     else:
          print("FMCv version needs to be upgraded.")
          return

     fmc.register_ftdv(vm_name=vm_name, mgmtip=ssh_ip, reg_id=reg_id, nat_id=nat_id, policy_id=policy_id, grp_id=grp_id)

     minutes = 3
     if (time.time() - start_time) <= timeout_time:
          r,channel,ssh = bf.establishingConnection(ssh_ip, user, password, minutes)
          print("Establishing Connection Response: "+ r)
     else:
          print("ERROR: Console not up")
          print("Deleting Instance {}".format(instanceName))
          request_body = {
                           "instances": [
                             f"zones/{zone}/instances/{instanceName}"
                           ],
                           "skipInstancesOnValidationError": False
                         }
          api = discovery.build('compute', 'v1',cache_discovery=False)
          response = api.regionInstanceGroupManagers().deleteInstances(project=project_id, region=zone[:-2], instanceGroupManager=instanceName[:-5], body=request_body).execute()
          return

     if (time.time() - start_time) <= timeout_time:
          reg_status = bf.ftdv_reg_polling(fmc, channel, vm_name, minutes=3)
          print("Registration Status of FTDv " + vm_name+ " : "+ reg_status)
     else:
          bf.closeShell(ssh)
          print("Second Attempt "+str(info_dict))
          return
     
     bf.closeShell(ssh)
     
     if reg_status != 'SUCCESS':
          print("ERROR: Registration Status: "+reg_status)
          print("Could not register FTDv:{} with FMCv".format(vm_name))
          print("Deleting Instance {}".format(instanceName))
          request_body = {
                           "instances": [
                             f"zones/{zone}/instances/{instanceName}"
                           ],
                           "skipInstancesOnValidationError": False
                         }
          api = discovery.build('compute', 'v1',cache_discovery=False)
          response = api.regionInstanceGroupManagers().deleteInstances(project=project_id, region=zone[:-2], instanceGroupManager=instanceName[:-5], body=request_body).execute()
          return

     print("Sleeping for a minute after FTD registration")
     time.sleep(60)
     
     if (time.time() - start_time) <= timeout_time:
          nic0 = "GigabitEthernet0/0"
          nic_id = fmc.get_nic_id_by_name(vm_name, nic0)
          for i in range(20):
               if nic_id == None:
                    nic_id = fmc.get_nic_id_by_name(vm_name, nic0)
                    print("Could not fetch NIC ID," +str(i)+". Sleeping for 5 seconds")
                    time.sleep(5)
               else:
                    break
     else:
          print("Second Attempt "+str(info_dict))
          return

     if nic_id == None:
          print("ERROR: Could not fetch NIC ID for FTDv:{}".format(vm_name))
          print("Deleting Instance {}".format(instanceName))
          request_body = {
                           "instances": [
                             f"zones/{zone}/instances/{instanceName}"
                           ],
                           "skipInstancesOnValidationError": False
                         }
          api = discovery.build('compute', 'v1',cache_discovery=False)
          response = api.regionInstanceGroupManagers().deleteInstances(project=project_id, region=zone[:-2], instanceGroupManager=instanceName[:-5], body=request_body).execute()
          return
     
     
    
     print("Configuring Interfaces")
     fmc.configure_nic_dhcp(vm_name, 'GigabitEthernet0/0', "outside", os.getenv("OUTSIDE_SEC_ZONE"), 1500)
     fmc.configure_nic_dhcp(vm_name, 'GigabitEthernet0/1', "inside", os.getenv("INSIDE_SEC_ZONE"), 1500)
     

     
     print("Adding Static Routes")
     fmc.create_static_network_route(vm_name, 'outside', 'any-ipv4', os.getenv("OUTSIDE_GW_NAME"), metric=1)
     fmc.create_static_network_route(vm_name, 'inside', 'any-ipv4', os.getenv("INSIDE_GW_NAME"), metric=2)
   
     
     print("Pushing Configs")
     fmc.execute_vm_deploy_first(vm_name)
     