"""
Copyright (c) 2024 Cisco Systems Inc or its affiliates.

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

Name:       azure_utils.py
Purpose:    This python file has the azure functions used for cluster.
"""

import os
import time
from azure.identity import ManagedIdentityCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.monitor import MonitorManagementClient


def get_creds_and_subscription():
    credentials = ManagedIdentityCredential()
    subscription_id = os.environ.get(
        'SUBSCRIPTION_ID', '11111111-1111-1111-1111-111111111111')
    return credentials, subscription_id

def get_compute_client():
    creds, subs = get_creds_and_subscription()
    return ComputeManagementClient(creds, subs)

def get_network_client():
    creds, subs = get_creds_and_subscription()
    return NetworkManagementClient(creds, subs)

def get_monitor_metric_client():
    creds, subs = get_creds_and_subscription()
    return MonitorManagementClient(creds, subs)
    
def get_vmss_obj():
    rg = os.environ.get('RESOURCE_GROUP_NAME')
    vmss_name = os.environ.get('VMSS_NAME')
    compute_client = get_compute_client()
    vmss = compute_client.virtual_machine_scale_sets.get(rg, vmss_name)
    return vmss

def get_vmss_vm_list():
    rg = os.environ.get('RESOURCE_GROUP_NAME')
    vmss_name = os.environ.get('VMSS_NAME')
    compute_client = get_compute_client()
    vmss_vms = compute_client.virtual_machine_scale_set_vms.list(rg, vmss_name, expand="InstanceView")
    return vmss_vms

def vmss_create_or_update(location, overprovision, name, tier, capacity):
    rg = os.environ.get('RESOURCE_GROUP_NAME')
    vmss_name = os.environ.get('VMSS_NAME')
    compute_client = get_compute_client() 
    update_status = compute_client.virtual_machine_scale_sets.begin_create_or_update(rg, vmss_name, 
                                   { "location": location,
                                    "overprovision": overprovision,
									"sku": {
                                	    "name": name, 
                                   		"tier": tier, 
                                    	"capacity": capacity
										 }
									})
    return update_status

def vmss_vm_delete(instanceid):
    rg = os.environ.get('RESOURCE_GROUP_NAME')
    vmss_name = os.environ.get('VMSS_NAME')
    compute_client = get_compute_client()
    delete = compute_client.virtual_machine_scale_set_vms.begin_delete(rg, vmss_name, instanceid)
    return delete

def get_vmss_intf_list():
    rg = os.environ.get('RESOURCE_GROUP_NAME')
    vmss_name = os.environ.get('VMSS_NAME')
    network_client = get_network_client()

    return network_client.network_interfaces.list_virtual_machine_scale_set_network_interfaces(rg, vmss_name)

def get_vmss_public_ip(vmindex, networkInterfaceName, ipConfigurationName, publicIpAddressName):
    rg = os.environ.get('RESOURCE_GROUP_NAME')
    vmss_name = os.environ.get('VMSS_NAME')
    network_client = get_network_client()
    pub_ip = network_client.public_ip_addresses.get_virtual_machine_scale_set_public_ip_address(rg, vmss_name, vmindex, networkInterfaceName, ipConfigurationName, publicIpAddressName).ip_address
    return pub_ip

def create_alert_rule(lb_name, ip, alert_name, ag_name):
    subscription_id = os.environ.get('SUBSCRIPTION_ID')
    resourceGroupName = os.environ.get('RESOURCE_GROUP_NAME')
    metric_alert_resource = {
        "location" : "global", 
        "severity" : 3, 
        "enabled":True,
        "scopes" : [
            "/subscriptions/"+subscription_id+"/resourceGroups/"+resourceGroupName+"/providers/Microsoft.Network/loadBalancers/" + lb_name
        ], 
        "evaluation_frequency" : "PT5M", 
        "window_size" : "PT15M",
        "target_resource_type" : "Microsoft.Network/loadBalancers",
        "auto_mitigate" : False,
        "actions": [
            {
                "action_group_id": "/subscriptions/"+subscription_id+"/resourceGroups/"+resourceGroupName+"/providers/microsoft.insights/actionGroups/"+ag_name
            }
        ],
        "criteria" :{
            "all_of": [
                {
                    "criterion_type" : "StaticThresholdCriterion",
                    "name" : "metric1",
                    "metric_name" : "DipAvailability",
                    "metric_namespace" : "Microsoft.Network/loadBalancers",
                    "time_aggregation" : "Maximum",
                    "dimensions": [
                                {
                                    "name": "BackendIPAddress",
                                    "operator": "Include",
                                    "values": [
                                        ip
                                    ]
                                }
                            ], 
                    "operator": "LessThan",
                    "threshold": 95
                }
            ],
            "odata_type" : "Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria"
        }
    }

    monitor_client = get_monitor_metric_client()
    alert_rule = monitor_client.metric_alerts.create_or_update(resourceGroupName, alert_name, metric_alert_resource)
    return alert_rule

def create_action_group(ag_name, ag_short_name):
    subscription_id = os.environ.get('SUBSCRIPTION_ID')
    resourceGroupName = os.environ.get('RESOURCE_GROUP_NAME')
    functionAppName = os.environ.get("FUNCTION_APP_NAME")
    azure_function_reciever = {
        "name":"function-reciever", 
        "function_app_resource_id":"/subscriptions/"+subscription_id+"/resourceGroups/"+resourceGroupName+"/providers/Microsoft.Web/sites/"+functionAppName,
        "function_name" : "DeleteUnhealthyFtd", 
        "http_trigger_url": "https://"+functionAppName+".azurewebsites.net/api/DeleteUnhealthyFtd"
        }
    action_group_resource = {
        "location": "global",
        "group_short_name": ag_short_name,
        "enabled":True,
        "azure_function_receivers":[azure_function_reciever]
    }
    monitor_client = get_monitor_metric_client()
    action_group = monitor_client.action_groups.create_or_update(resource_group_name=resourceGroupName, action_group_name=ag_name,action_group=action_group_resource)
    return action_group

def get_action_group(name):
    resourceGroupName = os.environ.get('RESOURCE_GROUP_NAME')
    monitor_client = get_monitor_metric_client()
    action_group = monitor_client.action_groups.get(resourceGroupName, name)
    return action_group

def delete_alert_rule(name):
    resourceGroupName = os.environ.get('RESOURCE_GROUP_NAME')
    monitor_client = get_monitor_metric_client()
    action_group = monitor_client.metric_alerts.delete(resourceGroupName, name)
    return action_group

def get_iface_ip(iface_name):
    nw_client = get_network_client()
    resourceGroupName = os.environ.get('RESOURCE_GROUP_NAME')
    private_ip = nw_client.network_interfaces.get(resourceGroupName, iface_name).ip_configurations
    return private_ip


