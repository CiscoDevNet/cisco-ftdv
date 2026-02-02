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
Name:       main.py
Purpose:    main function

"""

# THIS FUNCTION WILL GET EXECUTED WHEN A NEW FTDv INSTANCE COMES UP
#Get new password from secret manager

import os
import time
import base64
import json
import warnings
import urllib3

import ngfw as ftd
import cluster as cl
from fmc import FirepowerManagementCenter

from googleapiclient import discovery
from google.cloud import functions_v1

# Suppress InsecureRequestWarning from urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Suppress CryptographyDeprecationWarning from cryptography
warnings.filterwarnings("ignore", category=UserWarning, message=".*CryptographyDeprecationWarning.*")

def recalling(data, project_id, region, function_name):
    """
    Recalls a cloud function asynchronously.
    Args:
        data (dict): The data to be passed to the cloud function.
        project_id (str): The ID of the project where the cloud function is deployed.
        region (str): The region where the cloud function is deployed.
        function_name (str): The name of the cloud function.
    Returns:
        None
    """
    try:
        # Create client and function path
        client      = functions_v1.CloudFunctionsServiceClient()
        function    = client.cloud_function_path(project_id, region, function_name)
    
        # Creating payload
        payload = {
                "data": base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
            }
        # Creating request
        request = functions_v1.CallFunctionRequest(
            name=function,
            data=str(payload),
        )
    except Exception as e:
        print("ERROR: Exception occured in creating recall request ", str(e))

    # Call the function but do not wait for response,
    # this will raise DeadlineExceeded exception, ignore it.
    try:
        response = client.call_function(request=request, timeout=5)
        print(f"INFO: Function has been recalled successfully, DATA:{data}")
    except Exception as e:
        if e.__class__.__name__ != 'DeadlineExceeded':
            print("ERROR: Exception occured in recalling ", str(e))
    return

def scale_out(event, context):
    """Triggered from a message on a Cloud Pub/Sub topic.
    Args:
        event (dict): Event payload.
        context (google.cloud.functions.Context): Metadata for the event.
    """
    try:
        start_time      = time.time()
        timeout_time    = 480
        data_buffer     = base64.b64decode(event['data'])
        data            = json.loads(data_buffer)
        print("DEBUG: Following data has been received: ", data)
        
        # Adding RECALL variable to track recalling of function.
        MAX_RECALL = 10
        if not ("RECALL" in data):
            data["RECALL"] = 1
            CURRENT_RECALL = 1
        else:
            CURRENT_RECALL = int(data["RECALL"]) + 1
            data["RECALL"] = CURRENT_RECALL
    except Exception as e:
        print("ERROR: Exception occured in parsing event json payload ", str(e))
        return
    
    try:
        # Collecting Parametes
        # From event payload
        project_id      = data['resource']['labels']['project_id']
        zone            = data['resource']['labels']['zone']
        region          = zone.rsplit("-", 1)[0]
        resourceName    = data['protoPayload']['resourceName']
        
        # From OS ENV
        resourceNamePrefix  = os.getenv("RESOURCE_NAME_PREFIX")
        ftdRegViaPublicIP   = os.getenv('FTD_REG_VIA_PUBLIC_IP')
        fmc_ip              = os.getenv('FMC_IP')
        fmc_user            = os.getenv('FMC_USERNAME')
        reg_id              = os.getenv('REG_ID')
        nat_id              = os.getenv('NAT_ID')
        policy_id           = os.getenv('POLICY_ID')
        performanceTier     = os.getenv('PERF_TIER')
        force_stop          = os.getenv('FORCE_STOP')
        
        # These passwords are fetched from secret
        ftd_password_from_scrt   = os.getenv('FTDV_PASSWORD')
        fmc_password_from_scrt   = os.getenv('FMCV_PASSWORD')
        
        instanceGrpName     = resourceNamePrefix +"-ftdv-instance-group"
        instanceName        = resourceName.rsplit('/', 1)[-1]
        function_name       = resourceNamePrefix + "-ftdv-scaleout-action"
    except Exception as e:
        print("ERROR: Exception occured in reading environment variable ", str(e))

    if force_stop == "true":
        print(f"INFO: Force Stop enabled in function environment variable, stopping the function call for instance {instanceName}")
        return
       
    if CURRENT_RECALL > MAX_RECALL:
        print(f"ERROR: MAX RETRY TO CONFIGURE INSTANCE {instanceName} HAS REACHED")
        return
    
    print(f"{instanceName}: Function Call - {CURRENT_RECALL}")
    
    # Fetching size of instance group. (current no. of nodes)
    nodes = 1   # Assumed default value
    try:
        api         = discovery.build('compute', 'v1', cache_discovery=False)
        response    = api.regionInstanceGroups().get(project=project_id,region=region, instanceGroup=instanceGrpName).execute()
        nodes       = response['size']
        print ("INFO:  Cluster Nodes in autoscale group: "+ str(nodes))
        if int(nodes) == 0:
            print("ERROR: No nodes found in the instance group")
            return
    except Exception as e:
        print("ERROR: Exception occured in fetching size of instance group ", str(e))
    
    # First Boot Tasks
    if CURRENT_RECALL == 1:
        time.sleep(30)
        try:
            instance_details    = api.instances().get(project=project_id, zone=zone, instance=instanceName).execute()
            mgmt_pvt_ip         = instance_details['networkInterfaces'][2]['networkIP']
            registration_ip     = mgmt_pvt_ip
            mgmt_pub_ip         = None
            try:
                mgmt_pub_ip = instance_details['networkInterfaces'][2]['accessConfigs'][0]['natIP']
            except Exception as e:
                print("WARNING: Public IP of management interface could not be fetched ", str(e))
              
            if ftdRegViaPublicIP:
                if mgmt_pub_ip is not None:
                    registration_ip = mgmt_pub_ip
                else:
                    print("WARNING: FMCv registration is set via FTDv public IP, but public IP is not available")
                    
            print("INFO: IP for SSH/Login into FTDv by function: "+ mgmt_pvt_ip)
            print("INFO: IP for Registration of FTDv used by FMCv : "+ registration_ip)
        except Exception as e:
            print("ERROR: Exception occured in IP configuration ", str(e))

        # Updating data into the Event Payload
        joined_cluster          = False
        full_cluster_formed     = False
        reg_status              = "PENDING"
        reg_task_id             = 0
        password_updated        = False
        data["mgmt_pvt_ip"]     = mgmt_pvt_ip
        data["mgmt_pub_ip"]     = mgmt_pub_ip
        data["registration_ip"] = registration_ip
        data["reg_status"]      = reg_status
        data["reg_task_id"]     = reg_task_id
        data["joined_cluster"]  = joined_cluster
        data["full_cluster_formed"] = full_cluster_formed
        data["password_updated"] = password_updated
    
        boot_time= 180
        print(f"INFO: Waiting {boot_time} Seconds for first time boot for the instance {instanceName}")
        ftd.wait_multi_10sec(boot_time)
    else:
        # Fetch details from saved data from previous calls if its not the first call
        mgmt_pvt_ip         = data["mgmt_pvt_ip"]
        mgmt_pub_ip         = data["mgmt_pub_ip"]
        registration_ip     = data["registration_ip"]
        joined_cluster      = data["joined_cluster"]
        full_cluster_formed = data["full_cluster_formed"]
        reg_status          = data["reg_status"]
        reg_task_id         = data["reg_task_id"]
        password_updated    = data["password_updated"]
    
    # Creating SSH connection to FTDv
    ftdv_username = "admin"
    ftdv_password = "th1S_w!ll_Be_C#@nged"   # This password will be updated with the new password provided in the secret manager
    ssh_status = "NA"
    if password_updated:
        ftdv_password = ftd_password_from_scrt
    
    while (time.time() - start_time) < timeout_time and ssh_status != "SUCCESS":
        try:
            ssh_status,channel,ssh = ftd.establishingConnection(mgmt_pvt_ip, ftdv_username, ftdv_password)
            if ssh_status != "SUCCESS":
                print("INFO: SSH Connection could not be established, will retry in 30 seconds")
                time.sleep(30)
        except Exception as e:
            print("ERROR: Exception occured in creating SSH connection ", str(e))
    
    if ssh_status == "SUCCESS":
        print("INFO: SSH Connection established successfully")
    else:
        print(f"ERROR: SSH connection could not be established, will rerty in next function call")
        recalling(data, project_id, region, function_name)
        return "Recalling"
    
    if ftd.is_time_up(start_time,timeout_time):
        ftd.closeShell(ssh)
        recalling(data, project_id, region, function_name)
        return "Recalling"
    
    # Updating the password of FTDv
    if not password_updated:
        try:
            ftd.changePassword(channel, ftdv_password, ftd_password_from_scrt)
            data["password_updated"] = True
            print("INFO: FTDv Password updated successfully")
        except Exception as e:
            print("ERROR: Exception occured in changing password ", str(e))
            ftd.closeShell(ssh)
            recalling(data, project_id, region, function_name)
            return "Recalling"
    
    # Verifying SSH connection
    try:
        conn_status = ftd.checkConnection(channel)
        print("INFO: SSH Connection Status:"+ conn_status)
    except Exception as e:
        print("ERROR: Exception occured in verifying SSH connection ", str(e))
        recalling(data, project_id, region, function_name)
        return "Recalling"
    
    if ftd.is_time_up(start_time,timeout_time):
        ftd.closeShell(ssh)
        recalling(data, project_id, region, function_name)
        return "Recalling"

    # Checking if this node joined cluster
    while (time.time() - start_time) < timeout_time and not joined_cluster:
        try:
            node_state = cl.is_joined_cluster(channel)
            if node_state in ["DATA_NODE", "CONTROL_NODE"]:
                print(f"INFO: Instance {instanceName} has joined cluster as {node_state}")
                joined_cluster = True
                data["joined_cluster"] = True
            elif node_state != "NOT_JOINED":
                print(f"INFO: Instance {instanceName} has not joined cluster, is in {node_state} state")
            else:
                print(f"INFO: Instance {instanceName} has not joined cluster")
            time.sleep(20)
        except Exception as e:
            print("ERROR: Exception occurred in checking node's cluster status", str(e))
        
    if ftd.is_time_up(start_time,timeout_time):
        if not joined_cluster:
            print("DEBUG: Node did not join cluster, recalling")
        ftd.closeShell(ssh)
        recalling(data, project_id, region, function_name)
        return "Recalling"

    # Checking if this node is Control node
    try:
        unit = cl.get_control_node_unit(channel)
        print('INFO: CONTROL Unit '+ str(unit))
    except Exception as e:
        print("ERROR: Exception occured in fetching control node ", str(e))
        unit = -1
    octets = mgmt_pvt_ip.rsplit('.',1)
    if octets[-1] == unit:
        control_node = True
        print(f"INFO: This instance {instanceName} is Control Node, IP: {mgmt_pvt_ip}")
    else:
        control_node = False
        print(f"INFO: This instance {instanceName} is Data Node, IP: {mgmt_pvt_ip}")

    # Configuring Manager if this is Control node
    if control_node:
        if reg_status not in ['PARTIAL', 'SUCCESS']:
            try:
                ftd.configureManager(channel, fmc_ip, reg_id, nat_id)
            except Exception as e:
                print("ERROR: Exception occured in onfiguring manager on FTDv ", str(e))
    
    try:
        fmc = FirepowerManagementCenter(fmc_ip, fmc_user, fmc_password_from_scrt)
    except Exception as e:
        print("ERROR: Exception occured in creating FMCv object ", str(e))
    
    # Registering control node to FMCv and checking status
    if control_node:
        while (time.time() - start_time) <= timeout_time and reg_task_id == 0:
            if reg_status not in ['PARTIAL', 'SUCCESS']:
                try:
                    reg_task_id = fmc.register_ftdv(vm_name=registration_ip, mgmtip=registration_ip, reg_id=reg_id, nat_id=nat_id, policy_id=policy_id, performanceTier=performanceTier)
                    data["reg_task_id"] = reg_task_id
                except Exception as e:
                    print("ERROR: Exception occured in registering FTDv to FMCv ", str(e))
                    time.sleep(10)
                
        # Check registration status in both FTDv and FMCv    
        while (time.time() - start_time) <= timeout_time and reg_status != "SUCCESS":
            time.sleep(30)
            try:
                reg_status = ftd.check_reg_status(fmc, channel, task_id=reg_task_id)
                data["reg_status"] = reg_status
            except Exception as e:
                print("ERROR: Exception occured in checking registration status ", str(e))
                
        # Health Check Firewall Rules will be enabled once cluster is registered to FMCv successfully.
        # or Force enabling in case function recall reaches MAX_RECALL.
        if reg_status == 'SUCCESS' or CURRENT_RECALL == (MAX_RECALL-1):
            try:
                print("INFO: Enabling Health Check Firewall Rule after policy deployment")
                api = discovery.build('compute', 'v1', cache_discovery=False)
                firewall_rule_names = [resourceNamePrefix+'-ftdv-in-hc-firewall-rule', resourceNamePrefix+'-ftdv-out-hc-firewall-rule']
                for firewall_rule_name in firewall_rule_names:
                    firewall = api.firewalls().get(project=project_id, firewall=firewall_rule_name).execute()
                    # Check if the firewall rule is disabled
                    if 'disabled' in firewall and firewall['disabled']:
                        # Enable the firewall rule by setting 'disabled' to False
                        firewall['disabled'] = False
                        # Use the patch method to update the firewall rule
                        request = api.firewalls().patch(project=project_id, firewall=firewall_rule_name, body=firewall)
                        response = request.execute()
                        print(f"Enabled firewall rule:{firewall_rule_name} with {response['name']}")
                    else:
                        print(f"Firewall rule '{firewall_rule_name}' is already enabled or does not have a 'disabled' attribute.")
            except Exception as e:
                print("ERROR: Exception occured in enabling Health Check Firewall Rule ", str(e))
    else:
        # For data nodes check if node got registered to FMCv.
        status_in_ftdv = "NA"
        status_in_fmc  = "NA"
        while (time.time() - start_time) <= timeout_time and reg_status != "SUCCESS":
            if status_in_ftdv != "COMPLETED":
                try:
                    status_in_ftdv = ftd.check_ftdv_reg_status(channel)
                except Exception as e:
                    print("ERROR: Exception occured in checking FTDv registration status ", str(e))
            # Public IP is used as name of the Data Nodes in FMCv
            # If Public IP is not available, use Private IP
            if status_in_fmc != "SUCCESS":
                try:
                    if mgmt_pub_ip is not None:
                        status_in_fmc  = fmc.check_reg_status_from_fmc(vm_name=mgmt_pub_ip)
                    else:
                        status_in_fmc  = fmc.check_reg_status_from_fmc(vm_name=mgmt_pvt_ip)
                except Exception as e:
                    print("ERROR: Exception occured in checking FMCv registration status ", str(e))
                    
            if status_in_ftdv == "COMPLETED" and status_in_fmc == "SUCCESS":
                reg_status = "SUCCESS"
            elif status_in_ftdv == "COMPLETED" or status_in_fmc == "SUCCESS":
                reg_status = "PARTIAL"
            
            print("INFO:Registration status in FTDv: " + status_in_ftdv + " & status in FMC: " + status_in_fmc)
            time.sleep(20)
        data["reg_status"] = reg_status
        
    if ftd.is_time_up(start_time,timeout_time) or reg_status != 'SUCCESS':
        if reg_status != 'SUCCESS':
            print("DEBUG: Registration status could not be verified in this function call")
        ftd.closeShell(ssh)
        recalling(data, project_id, region, function_name)
        return "Recalling"
    
    # Checking if all nodes joined the cluster
    while (time.time() - start_time) <= timeout_time and not full_cluster_formed:
        time.sleep(30)
        try:
            full_cluster_formed = cl.is_full_cluster_formed(channel, nodes)
        except Exception as e:
            print("ERROR: Exception occured in verifying cluster formation ", str(e))
        if full_cluster_formed:
            print("INFO: Full cluster formation completed")
            data["full_cluster_formed"] = True
        
    if ftd.is_time_up(start_time,timeout_time):
        if not full_cluster_formed:
            print("DEBUG: Full cluster formation could not be verfied, recalling")
        ftd.closeShell(ssh)
        recalling(data, project_id, region, function_name)
        return "Recalling"
    
    #Closing FTDv ssh session
    ftd.closeShell(ssh)
    print("INFO: Function completed successfully")
    return "Completed"