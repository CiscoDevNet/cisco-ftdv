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


def _extract_ips_from_instance(response):
     """Return (ssh_ip, reg_ip) derived from the instance's management NIC."""
     mgmt_interface = response['networkInterfaces'][2]
     ssh_ip = mgmt_interface['networkIP']
     if os.getenv('FTD_REG_VIA_PUBLIC_IP', 'false').lower() != 'true':
          return ssh_ip, ssh_ip
     for access_cfg in mgmt_interface.get('accessConfigs', []):
          nat_ip = access_cfg.get('natIP')
          if nat_ip:
               return ssh_ip, nat_ip
     raise KeyError("External IP not found on management interface for registration")


def _lookup_instance_ips(project_id, zone, instance_name):
     api = discovery.build('compute', 'v1', cache_discovery=False)
     response = api.instances().get(project=project_id, zone=zone, instance=instance_name).execute()
     return _extract_ips_from_instance(response)


def _parse_retry_payload(log_entry):
     text_payload = log_entry.get('textPayload', '')
     if not text_payload.startswith("Second Attempt "):
          raise KeyError("Retry payload missing")
     payload = text_payload[len("Second Attempt "):].replace("'", "\"")
     return json.loads(payload)

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


     ftd_reg_ip = None
     info_dict = {}

     try:
          resourceName = log_entry['protoPayload']['resourceName']
          pos = resourceName.find("instances/")
          instanceName = resourceName[pos+len("instances/"):]
          instance_suffix = instanceName[-4:] #last 4 characters of instance name
          project_id = log_entry['resource']['labels']['project_id']
          zone = log_entry['resource']['labels']['zone']
          region = zone[:-2]
          api = discovery.build('compute', 'v1',cache_discovery=False)
          response = api.instances().get(project=project_id, zone=zone, instance=instanceName).execute()
          ssh_ip, ftd_reg_ip = _extract_ips_from_instance(response)

          print("FTDv Name: "+instanceName+ " IP for Functions to Login: "+ssh_ip)
          print("FTDv Name: "+instanceName+ " IP for Registration to FMCv: "+ftd_reg_ip)

          info_dict = {"Retry_function":"yes", "ssh_ip":ssh_ip,"instance_suffix":instance_suffix, "project_id": project_id, "count": count, "instanceName":instanceName, "zone":zone, "region": region, "ftd_reg_ip": ftd_reg_ip}
          first_run_flag = True
     except Exception:
          prev_info = _parse_retry_payload(log_entry)
          count = prev_info["count"] + 1
          instanceName = prev_info["instanceName"]
          instance_suffix = prev_info["instance_suffix"]
          project_id = prev_info["project_id"]
          zone = prev_info["zone"]
          region = prev_info["region"]
          print("Function retriggered count: "+str(count))
          ssh_ip, ftd_reg_ip = _lookup_instance_ips(project_id, zone, instanceName)
          info_dict = {"Retry_function":"yes", "ssh_ip":ssh_ip,"instance_suffix":instance_suffix, "project_id": project_id, "count": count, "instanceName":instanceName, "zone":zone, "region": region, "ftd_reg_ip": ftd_reg_ip}

     if count > MAX_RETRIES_COUNT:
          print("Number of retries exceeded "+str(MAX_RETRIES_COUNT))
          return

     if first_run_flag:
          print("First run of function")
     else:
          print("Function(retriggered) for "+ instanceName)
     
     fmc_ip = os.getenv('FMC_IP')
     reg_id = os.getenv('REG_ID')
     nat_id = os.getenv('NAT_ID')
     policy_id = os.getenv('POLICY_ID')
     grp_id = os.getenv('GRP_ID')
     http_policy = os.getenv("INSTANCE_PREFIX_IN_FMC") + "-platform-setting"
     health_check_port = os.getenv("HEALTH_CHECK_PORT")
     minutes = 7

     user = "admin"
     password = os.getenv('FTDV_PASSWORD')

     if (time.time() - start_time) <= timeout_time:
          r,channel,ssh = bf.establishingConnection(ssh_ip, user, password, minutes)
          print("Establishing Connection Response: "+ r)
     else:
          print("Console not up")
          print("Deleting Instance {}".format(instanceName))
          api = discovery.build('compute', 'v1',cache_discovery=False)
          response = api.instances().delete(project=project_id, zone=zone, instance=instanceName).execute()
          return

     if r == 'TIMEOUT':
          print("Timeout Retry")
          print("Second Attempt "+str(info_dict))
          return

     if r != 'SUCCESS':
          print("ERROR: Establishing Connection")
          print("Deleting Instance {}".format(instanceName))
          api = discovery.build('compute', 'v1',cache_discovery=False)
          response = api.instances().delete(project=project_id, zone=zone, instance=instanceName).execute()
          return

     if first_run_flag:
          bf.closeShell(ssh)
          print("Retriggering Function after FTDv console is up")
          print("Second Attempt "+str(info_dict))
          return
     
     conn_status = bf.checkConnection(channel)
     print("Connection Status: "+ conn_status)

     if conn_status == 'FAIL':
          print("Connection Failure")
          print("Deleting Instance {}".format(instanceName))
          api = discovery.build('compute', 'v1',cache_discovery=False)
          response = api.instances().delete(project=project_id, zone=zone, instance=instanceName).execute()
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

     fmc.register_ftdv(vm_name=vm_name, mgmtip=ftd_reg_ip, reg_id=reg_id, nat_id=nat_id, policy_id=policy_id, grp_id=grp_id)

     minutes = 3
     if (time.time() - start_time) <= timeout_time:
          r,channel,ssh = bf.establishingConnection(ssh_ip, user, password, minutes)
          print("Establishing Connection Response: "+ r)
     else:
          print("Console not up")
          print("Deleting Instance {}".format(instanceName))
          api = discovery.build('compute', 'v1',cache_discovery=False)
          response = api.instances().delete(project=project_id, zone=zone, instance=instanceName).execute()
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
          api = discovery.build('compute', 'v1',cache_discovery=False)
          response = api.instances().delete(project=project_id, zone=zone, instance=instanceName).execute()
          return

     print("Sleeping for few minutes after FTD registration")
     time.sleep(150)
     
     if (time.time() - start_time) <= timeout_time:
          nic0 = "Ethernet0/0"
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
          api = discovery.build('compute', 'v1',cache_discovery=False)
          response = api.instances().delete(project=project_id, zone=zone, instance=instanceName).execute()
          return
     
     api = discovery.build('compute', 'v1',cache_discovery=False)
     host_object_name_gw_inside = os.getenv("INSIDE_GW_NAME")
     response = api.instances().get(project=project_id, zone=zone, instance=instanceName).execute()
     subnetwork = response["networkInterfaces"][1]["subnetwork"].split("/")[-1]
     print("Subnetwork is", subnetwork)

     response = api.subnetworks().get(project=project_id, region=region, subnetwork=subnetwork).execute()
     inside_gw = response["gatewayAddress"]
     print("Inside GW is", str(inside_gw))

     if fmc.get_host_objectid_by_name(host_object_name_gw_inside) == '':
          fmc.add_host_object(name = host_object_name_gw_inside, ip = inside_gw)
          print("Created INSIDE_GW object in FMCv")
     
     host_object_name_gw_outside = os.getenv("OUTSIDE_GW_NAME")
     response = api.instances().get(project=project_id, zone=zone, instance=instanceName).execute()
     subnetwork = response["networkInterfaces"][0]["subnetwork"].split("/")[-1]
     print("Subnetwork is", subnetwork)

     response = api.subnetworks().get(project=project_id, region=region, subnetwork=subnetwork).execute()
     outside_gw = response["gatewayAddress"]
     print("Outside GW is", str(outside_gw))

     if fmc.get_host_objectid_by_name(host_object_name_gw_outside) == '':
          fmc.add_host_object(name = host_object_name_gw_outside, ip = outside_gw)
          print("Created OUTSIDE_GW object in FMCv")
     
     print("Configuring Interfaces")
     fmc.configure_nic_dhcp(vm_name, 'Ethernet0/0', "outside", os.getenv("OUTSIDE_SEC_ZONE"), 1500)
     fmc.configure_nic_dhcp(vm_name, 'Ethernet0/1', "inside", os.getenv("INSIDE_SEC_ZONE"), 1500)
     
     print("Adding Static Routes")
     fmc.create_static_network_route(vm_name, 'outside', 'any-ipv4', os.getenv("OUTSIDE_GW_NAME"), metric=1)
     fmc.create_static_network_route(vm_name, 'inside', 'any-ipv4', os.getenv("INSIDE_GW_NAME"), metric=2)
    
     version_tuple = (7, 7)
     ftd_version_tuple = tuple(map(int, ftd_version.split('.')[:2]))

     if ftd_version_tuple >= version_tuple:  
        """
        GCP HealthProbe Using Static Route Leaking - Supported from version 7.7
            1. Create objects in FMC
            2. Create Loopback interface
            3. Create VRF
            4. Create Routes
        """
        resourceName = instanceName[:instanceName.find("-")]
        address = resourceName + "-ftdv-ilb-ip"
        response = api.addresses().get(project=project_id, region=region, address=address).execute()
        ilb_ip = response['address']
        print("ILB IP is", ilb_ip)

        address = resourceName + "-ftdv-elb-ip"
        response = api.addresses().get(project=project_id, region=region, address=address).execute()
        elb_ip = response['address']
        print("ELB IP is", elb_ip)

        ilb_ip_object_name = "ilb_ip"
        elb_ip_object_name = "elb_ip"
        health_probe_grp_object_name = "health_probe_range_grp"
        health_probe_range_grp = ["35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22", "130.211.0.0/22"]

        if fmc.get_host_objectid_by_name(ilb_ip_object_name) == '':
            fmc.add_host_object(name = ilb_ip_object_name, ip = ilb_ip)
        
        if fmc.get_host_objectid_by_name(elb_ip_object_name) == '':
            fmc.add_host_object(name = elb_ip_object_name, ip = elb_ip)

        if fmc.get_group_objectid_by_name(health_probe_grp_object_name) == '':
            fmc.add_networkgroup_object(name=health_probe_grp_object_name, ip_range=health_probe_range_grp)

        # Declaring loopback ids eg. Loopback1
        loopback_id_ilb = 1
        loopback_id_elb = 2
        dev_id = fmc.get_device_id_by_name(vm_name)
        health_loopback_interface_ilb = "health-loopback-ilb-int"
        health_loopback_interface_elb = "health-loopback-elb-int"
        try:
            fmc.create_loopback(device_id=dev_id, loopback_id=loopback_id_ilb, ifname=health_loopback_interface_ilb, ip=ilb_ip, mask="255.255.255.255")
            print("Created Loopback Interface for ILB")
        except Exception as e:
            print(f"Loopback creation failed for ILB: {e}")

        try:
            fmc.create_loopback(device_id=dev_id, loopback_id=loopback_id_elb, ifname=health_loopback_interface_elb, ip=elb_ip, mask="255.255.255.255")
            print("Created Loopback Interface for ELB")
        except Exception as e:
            print(f"Loopback creation failed for ELB: {e}")     

        loopback_interface_ilb = "Loopback"+str(loopback_id_ilb)
        vrf_name_ilb = "loopback-ilb-vrf"

        try:
            fmc.create_virtual_router(device_name=vm_name, device_id=dev_id, vrf_name=vrf_name_ilb, interface1=loopback_interface_ilb, interface_type="LoopbackInterface", interface_name=health_loopback_interface_ilb)
            print("Created VRF for ILB")
        except Exception as e:
            print(f"VRF creation failed for ILB!!: {e}") 

        loopback_interface_elb = "Loopback"+str(loopback_id_elb)
        vrf_name_elb = "loopback-elb-vrf"
        
        try:
            fmc.create_virtual_router(device_name=vm_name, device_id=dev_id, vrf_name=vrf_name_elb, interface1=loopback_interface_elb, interface_type="LoopbackInterface", interface_name=health_loopback_interface_elb)
            print("Created VRF for ELB")
        except Exception as e:
            print(f"VRF creation failed for ELB!!: {e}") 
        
        try:
            fmc.create_static_network_route_loopback(device=vm_name, interface_name=health_loopback_interface_ilb, network_object_name=ilb_ip_object_name, metric=1, vrf_name=vrf_name_ilb)
            print("Created Static Route 1 for ILB")
        except Exception as e:
            print(f"Static route 1 creation failed for ILB!!: {e}") 
        
        try:
            fmc.create_static_network_route_loopback(device=vm_name, interface_name=health_loopback_interface_elb, network_object_name=elb_ip_object_name, metric=1, vrf_name=vrf_name_elb)
            print("Created Static Route 1 for ELB")
        except Exception as e:
            print(f"Static route 1 creation failed for ELB!!: {e}")

        try:
            fmc.create_static_network_route_loopback(device=vm_name, interface_name="inside", network_object_name=health_probe_grp_object_name, metric=1, host_object_name_gw = host_object_name_gw_inside)
            print("Created Static Route 2 for ILB")
        except Exception as e:
            print(f"Static route 2 creation failed for ILB!!: {e}")
        
        try:
            fmc.create_static_network_route_loopback(device=vm_name, interface_name="outside", network_object_name=health_probe_grp_object_name, metric=2, host_object_name_gw = host_object_name_gw_outside)
            print("Created Static Route 2 for ELB")
        except Exception as e:
            print(f"Static route 2 creation failed for ELB!!: {e}")

        try:
            fmc.create_static_network_route_loopback(device=vm_name, interface_name="inside", network_object_name=health_probe_grp_object_name, metric=1, isGlobalRouter=False, vrf_name=vrf_name_ilb)
            print("Created Static Route 3 for ILB")
        except Exception as e:
            print(f"Static route 3 creation failed for ILB!!: {e}")

        try:
            fmc.create_static_network_route_loopback(device=vm_name, interface_name="outside", network_object_name=health_probe_grp_object_name, metric=1, isGlobalRouter=False, vrf_name=vrf_name_elb)
            print("Created Static Route 3 for ELB")
        except Exception as e:
            print(f"Static route 3 creation failed for ELB!!: {e}")

        if not fmc.get_platform_policy(name = http_policy):
            print("Adding platform policy")
            fmc.add_platform_policy(name= http_policy)

        if not fmc.get_http_setting(policy_name=http_policy, port= health_check_port, ip_address_objname=health_probe_grp_object_name, interface_name= health_loopback_interface_ilb):
            print("Adding Platform Setting")
            interface_name_array = [health_loopback_interface_ilb, health_loopback_interface_elb]
            fmc.add_http_setting(policy_name=http_policy, port= health_check_port, ip_address_objname=health_probe_grp_object_name, interface_name_array=interface_name_array)
            
        if not fmc.get_policy_assignment(policy_name=http_policy):
            print("Opening HTTP Server")
            fmc.add_policy_assignment(policy_name=http_policy, device_group=grp_id)
     
     print("Pushing Configs")
     fmc.execute_vm_deploy_first(vm_name)