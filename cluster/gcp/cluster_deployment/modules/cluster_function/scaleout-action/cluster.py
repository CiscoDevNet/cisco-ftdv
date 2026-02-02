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
Name:       cluster_functions.py
Purpose:    This python file has functions for cluster related operations.
"""
from ngfw import *
import re

def is_joined_cluster(channel):
    node_state = "NOT_JOINED"
    cmd = "show cluster info | grep NODE"
    try:
        msg = send_cmd_and_wait_for_execution(channel, cmd)
        match = re.search(r'This is .*state (\w+)', msg)
        if match:
            node_state = match.group(1)
    except Exception as e:
        print("ERROR: Exception occurred in checking cluster node status.", str(e))
    return node_state
            
def is_all_node_joined(channel, min_nodes):
    msg = ""
    cmd = 'show cluster info | count ID'
    try:
        msg = send_cmd_and_wait_for_execution(channel, cmd)
        print("MESSAGE: "+ msg)
    except Exception as e:
        print("ERROR: Exception occured in getting node join status.", str(e))
        
    if str(min_nodes) in msg:
        print("Healthy : All Cluster Nodes available")
        return "Healthy"
    else:
        print("Unhealthy : One or Many Cluster Nodes not available")
        return "Unhealthy"

def is_full_cluster_formed(channel, min_nodes):
    msg = ""
    cmd = 'show cluster info'
    try:
        msg = send_cmd_and_wait_for_execution(channel, cmd)
    except Exception as e:
        raise Exception("ERROR: Exception occured in checking cluster form status.", str(e))
        
    control_data_cls = msg.count('in state CONTROL_NODE\r\n')
    data_nodes = 0
    if  control_data_cls:
        data_nodes = msg.count('in state DATA_NODE\r\n')
        print("Available DATA nodes : "+ str(data_nodes))

    if ((min_nodes-1)  == data_nodes):
        print("INFO: All nodes joined cluster")
        return True
    else:
        print(f"WARNING: Waiting for {min_nodes - control_data_cls - data_nodes} Nodes to join cluster")
        return False
      
def verify_cluster_member(fmc, channel, min_nodes, cluster_grp_name):
    """
    Purpose:    To verify all ftdv cluster node get registered
    Parameters: FirepowerManagementCenter class object
    Returns:    SUCCESS, FAILED
    Raises:
    """
    cls_grp_id = None
    try:
        cls_grp_id = fmc.get_cluster_id_by_name(name=cluster_grp_name)
    except Exception as e:
        print("ERROR: ",str(e))
        
    if cls_grp_id:
        cls_member = fmc.get_cluster_members(cls_id=cls_grp_id)

        if cls_member:
            if min_nodes is len(cls_member):
                print("Cluster members : " + str(cls_member))
                return "SUCCESS"
            else:
                print("FMC not able to discover all nodes...")
                print('Login to FMC and discover pending nodes using "Reconcile All"')
                return "FAILED"
        else:
            print("Cluster member not found")
            return "FAILED"
    else:
        print("Cluster group not found")
        return "FAILED"

def get_control_node_unit(channel):
    msg = ""
    cmd = 'show cluster info'
    try:
        msg = send_cmd_and_wait_for_execution(channel, cmd)
    except Exception as e:
        raise Exception("ERROR: Exception occured in getting control node ", str(e))
        
    for line in msg.splitlines():
        if ('CONTROL_NODE' in line):
            if ((line.strip()).startswith('This')):
                numbers=re.findall('[0-9]+', line)
                return numbers[0]
            else:
                numbers=re.findall('[0-9]+', line)
                return numbers[0]
