import os
import time
from azure.identity import ManagedIdentityCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient

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

def get_ftdindex_from_mgmt_last(ip_suffix):
    rg = os.environ.get('RESOURCE_GROUP_NAME')
    vname = os.environ.get('VMSS_NAME')

    network_client = get_network_client()
    nics = network_client.network_interfaces.list_virtual_machine_scale_set_network_interfaces(rg,vname)
    for nic in nics:
        if nic.primary:
            ips = nic.ip_configurations
            vmid = nic.virtual_machine.id.split('/')[-1]
            for ip in ips:
                ipsuffix = ip.private_ip_address.split('.')[-1]
                if ip.private_ip_address.split('.')[-1] == ip_suffix:
                    return vmid

def get_private_mgmt_ips(rg,vname):
    info = {}
    network_client = get_network_client()
    nics = network_client.network_interfaces.list_virtual_machine_scale_set_network_interfaces(rg,vname)
    for nic in nics:
        if nic.primary:
            ips = nic.ip_configurations
            vmid = nic.virtual_machine.id.split('/')[-1]
            vm = {}
            for ip in ips:
                vm["MgmtPrivate"] = ip.private_ip_address
            info[vmid] = vm
    return info

def update_names_and_power_states(rg,vname,info):
    #status could be 'is running','is deallocated','is starting','is deallocating'
    compute_client = get_compute_client()
    vmss = compute_client.virtual_machine_scale_set_vms.list(rg,vname,expand="instanceView")
    for vm in vmss:
        vmid = vm.id.split('/')[-1]
        info[vmid]["Name"] = vm.name
        sl = vm.instance_view.statuses
        for s in sl:
            info[vmid]["Status"] = s.display_status
    return info

def update_public_ips(rg,vname,info):
    network_client = get_network_client()
    for index in info:
        nic = os.environ.get('MNGT_NET_INTERFACE_NAME')
        ipc = os.environ.get('MNGT_IP_CONFIG_NAME')
        pubips = network_client.public_ip_addresses.list_virtual_machine_scale_set_vm_public_ip_addresses(rg,vname,index,nic,ipc)
        for ip in pubips:
            info[index]["MgmtPublic"]=ip.ip_address
    return info

def get_vmss_info():

    rg = os.environ.get('RESOURCE_GROUP_NAME')
    vname = os.environ.get('VMSS_NAME')
    info = get_private_mgmt_ips(rg,vname)
    info = update_names_and_power_states(rg,vname,info)
    info = update_public_ips(rg,vname,info)
    return info
