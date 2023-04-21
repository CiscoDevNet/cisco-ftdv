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
Name:       main.py
Purpose:    main function

"""

# THIS FUNCTION WILL GET EXECUTED WHEN A NEW FTDv INSTANCE COMES UP


#Get new password from secret manager
#REMOVE SLEEP FROM execCommand and place it where it is called accordingly!
import base64
import json
from googleapiclient import discovery
import basic_functions as bf
import time
from fmc_functions import FirepowerManagementCenter
import urllib3
import os
import paramiko
import collections

try:
     from StringIO import StringIO
except ImportError:
    from io import StringIO
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def cluster_handler(event, context):
     """Triggered from a message on a Cloud Pub/Sub topic.
     Args:
          event (dict): Event payload.
          context (google.cloud.functions.Context): Metadata for the event.
     """
     
     start_time = time.time()
     timeout_time = 510
     next_attempt = False

     data_buffer = base64.b64decode(event['data'])
     log_entry = json.loads(data_buffer)
     
     try:
        management_ip = None
        registration_ip = None
        vm_name = ""
        min_nodes = 0
        loop_counter = 0
        reg_status = 'FAILED'
        reg_task_id = ""
        #First attempt
        # To get the master Instance

        resourceName = log_entry['protoPayload']['resourceName']
        pos = resourceName.find("instanceGroupManagers/")
        instanceGrpName = resourceName[pos+ len("instanceGroupManagers/"):]
        resourceNamePrefix = instanceGrpName[:instanceGrpName.find('-')]
        print("resourceNamePrefix : "+ resourceNamePrefix)
        project_id = log_entry['resource']['labels']['project_id']
        region = log_entry['resource']['labels']['location']
        print ("Region : "+ region)

        autoscalerName = resourceNamePrefix +"-ftdv-cluster"
        print("autoscalerName : "+ autoscalerName)
        bf.wait_multi_10sec(30)
        api = discovery.build('compute', 'v1', cache_discovery=False)
        response = api.regionAutoscalers().get(project=project_id,region=region, autoscaler=autoscalerName).execute()
        min_nodes = response['autoscalingPolicy']['minNumReplicas']
        print ("Min Cluster Nodes : "+ str(min_nodes))
        bf.wait_multi_10sec(60+min_nodes*10)
        response = api.regionInstanceGroupManagers().listManagedInstances(project=project_id, region=region, instanceGroupManager=instanceGrpName).execute()
        instanceCreation = {}
        ipTable = {}
        IsFTDvWithExternalIP = eval(os.getenv('EXTERNAL_IP_ENABLE'))
        for instanceElement in response['managedInstances']:
            instPath = instanceElement['instance']
            pos = instPath.find("instances/")
            instanceName = instPath[pos+ len("instances/"):]
            print ("Instance Name :"+ instanceName)
            pos = instPath.find("zones/")
            zoneName = instPath[pos+ len("zones/"):]
            zone = zoneName[:len(region)+2]
            response = api.instances().get(project=project_id, zone=zone, instance=instanceName).execute()
            creationTime = response['creationTimestamp']
            instanceCreation[creationTime]= response
            if IsFTDvWithExternalIP is True:
                ipTable[response['networkInterfaces'][2]['networkIP']]= response['networkInterfaces'][2]['accessConfigs'][0]['natIP']
            else:
                ipTable[response['networkInterfaces'][2]['networkIP']]= response['networkInterfaces'][2]['networkIP']    
            
        firstInstanceCreationTime = min(instanceCreation)
        response = instanceCreation[firstInstanceCreationTime]
        vm_name = response['name']
        print("1st launched FTDv VM Name : "+ vm_name)
        # mgmt ip -> nic2
        management_ip = response['networkInterfaces'][2]['networkIP']
        if IsFTDvWithExternalIP is False:
            registration_ip = management_ip
        else:   
            registration_ip = response['networkInterfaces'][2]['accessConfigs'][0]['natIP']
        print("IP for Login : "+ management_ip)
        print("IP for Registration : "+ registration_ip)
        loop_counter = loop_counter + 1
        info_dict = {"Retry_function":"yes", "ipTable": ipTable, "management_ip":management_ip, "registration_ip": registration_ip, "project_id": project_id, "vm_name": vm_name, "min_nodes": min_nodes, "loop_counter": loop_counter, "reg_status": reg_status, "reg_task_id": reg_task_id}
        next_attempt = True
        boot_time= 240
        print("Wait for " + str(boot_time)+ "-secs before trying to login 1st FTDv VM ("+ vm_name + ")")
        bf.wait_multi_10sec(boot_time)
     except:
        print("First Try-Except Block: Either Exception Generated from First Trigger or This is Retriggered Call")

     try:
        prev_info = log_entry['textPayload']
        # Extracting the Dict part from string
        prev_info = prev_info[len("Reattempt "):]
        #making json acceptable format
        prev_info = prev_info.replace("'", "\"")
        prev_info = json.loads(prev_info)
        ipTable = prev_info["ipTable"]
        management_ip = prev_info["management_ip"]
        print("IP for Login : "+ management_ip)
        registration_ip = prev_info["registration_ip"]
        print("IP for Registration : "+ registration_ip)
        project_id = prev_info["project_id"]
        vm_name = prev_info["vm_name"]
        min_nodes = prev_info["min_nodes"]
        loop_counter = prev_info["loop_counter"]
        print("Retrigger Count : "+ str(loop_counter))
        loop_counter = loop_counter + 1
        reg_status = prev_info["reg_status"]
        reg_task_id = prev_info["reg_task_id"]
        info_dict = {"Retry_function":"yes", "ipTable": ipTable, "management_ip": management_ip, "registration_ip": registration_ip, "project_id": project_id, "vm_name": vm_name, "min_nodes": min_nodes, "loop_counter": loop_counter, "reg_status": reg_status, "reg_task_id": reg_task_id}
     except:
        print("Retry-Except Block: Either Exception Generated from Retrigger call or This is First Time Triggered Call")

     max_retry = int(os.getenv('RETRY_COUNT'))

     if (loop_counter <= (max_retry + 1)):
        fmc_ip = os.getenv('FMC_IP')
        reg_id = os.getenv('REG_ID')
        nat_id = os.getenv('NAT_ID')
        cls_grp_name = os.getenv('CLS_GRP_NAME')
        policy_id = os.getenv('POLICY_ID')
        password = os.getenv('FTDV_PASSWORD')
        performanceTier = os.getenv('PERF_TIER')
        minutes = 10
        user = "admin"

        if next_attempt:
            print("Retriggering Function after FTDv console is up")
            print("Reattempt "+ str(info_dict))
            return

        if (time.time() - start_time) <= timeout_time:
            r,channel,ssh = bf.establishingConnection(management_ip, user, password, minutes)
            print("Establishing Connection Response "+ r)
        else:
            bf.closeShell(ssh)
            print("Reattempt "+ str(info_dict))
            return

        if r != 'SUCCESS':
            print("ERROR: Establishing Connection")
            return
        
        if (time.time() - start_time) <= timeout_time:
            conn_status = bf.checkConnection(channel)
            print("Connection Status:"+ conn_status)
        else:
            bf.closeShell(ssh)
            print("Reattempt "+ str(info_dict))
            return

        if (time.time() - start_time) <= timeout_time:
            if reg_status != 'PARTIAL' and r=="SUCCESS" :
                health_status = bf.check_cluster_nodes(channel, min_nodes)
                print("Cluster Nodes Health Status:"+ health_status)
            else:
                print("Registration In-Progress")
        else:
            bf.closeShell(ssh)
            print("Reattempt "+ str(info_dict))
            return

        if (time.time() - start_time) <= timeout_time:
            if reg_status != 'PARTIAL' and r=="SUCCESS" :
                counter =0
                while counter < min_nodes :
                    print("Wait For All Cluster Nodes To Join")
                    bf.wait_multi_10sec(30)
                    health_status = bf.check_cluster_slave_nodes(channel, min_nodes)
                    print("Cluster DATA Nodes Health Status:"+ health_status)
                    if health_status =="Healthy" :
                        break
                    counter = counter + 1
                if (counter > 0):
                    bf.closeShell(ssh)
                    print("Reattempt "+ str(info_dict))
                    return
            else:
                print("Registration In-Progress")
        else:
            bf.closeShell(ssh)
            print("Reattempt "+ str(info_dict))
            return

        if (time.time() - start_time) <= timeout_time:
            if reg_status != 'PARTIAL' and r=="SUCCESS" and health_status=="Healthy" :
                unit = bf.get_master_node_unit(channel)
                print('CONTROL Unit '+ str(unit))
                octets = management_ip.split('.')
                if octets[-1] == unit:
                    bf.configureManager(channel, fmc_ip, reg_id, nat_id)
                else:
                    management_ip = octets[0] +'.'+ octets[1] +'.'+ octets[2] + '.'+ unit
                    if bool(ipTable) is True:
                        registration_ip = ipTable[management_ip]
                    info_dict = {"Retry_function":"yes", "ipTable": ipTable, "management_ip": management_ip, "registration_ip": registration_ip, "project_id": project_id, "vm_name": vm_name, "min_nodes": min_nodes, "loop_counter": loop_counter, "reg_status": reg_status, "reg_task_id": reg_task_id}
                    bf.closeShell(ssh)
                    print("Reattempt "+ str(info_dict))
                    return
            else:
                print("Either Nodes are Unhealthy or Registration In-Progress")
        else:
            bf.closeShell(ssh)
            print("Reattempt "+ str(info_dict))
            return
        bf.closeShell(ssh)

        fmc = FirepowerManagementCenter()
        
        if (time.time() - start_time) <= timeout_time:
            if reg_status != 'PARTIAL':
                reg_task_id = fmc.register_ftdv(vm_name=registration_ip, mgmtip=registration_ip, reg_id=reg_id, nat_id=nat_id, policy_id=policy_id, performanceTier=performanceTier)
        else:
            bf.closeShell(ssh)
            print("Reattempt "+ str(info_dict))
            return

        if (time.time() - start_time) <= timeout_time:
          r,channel,ssh = bf.establishingConnection(management_ip, user, password, minutes)
          print("Establishing Connection Response "+ r)
        else:
          bf.closeShell(ssh)  
          print("Reattempt "+str(info_dict))
          return

        if (time.time() - start_time) <= timeout_time:
            print ('cloud_function_loop_counter ' + str(loop_counter))
            if (loop_counter < 3):
                reg_status = bf.ftdv_reg_polling(fmc, channel, task_id=reg_task_id, minutes=5)
            else:
                reg_status = bf.ftdv_reg_polling(fmc, channel, task_id=reg_task_id, minutes=7)
            print("reg_status: "+ reg_status)
            
            if reg_status != 'SUCCESS':
                info_dict = {"Retry_function":"yes", "ipTable": ipTable, "management_ip": management_ip, "registration_ip": registration_ip, "project_id": project_id, "vm_name": vm_name, "min_nodes": min_nodes, "loop_counter": loop_counter, "reg_status": reg_status, "reg_task_id": reg_task_id}
                bf.closeShell(ssh)
                print("Reattempt "+ str(info_dict))
                return
            else:
                print('REGISTRATION SUCCESSFUL')
                bf.verify_cluster_member(fmc, channel,min_nodes,cls_grp_name=cls_grp_name)
        else:
            bf.closeShell(ssh)
            print("Reattempt "+ str(info_dict))
            return
        

        #Closing FTDv ssh session
        bf.closeShell(ssh)

     else:
        print("MAX_TRY_WARNING: Reached max allowed attemp")
        return
