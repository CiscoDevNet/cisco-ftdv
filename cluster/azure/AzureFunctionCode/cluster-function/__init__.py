import os
import sys
import json
import asyncio
import traceback
import azure.functions as func
from .azure_utils import get_vmss_info
from .events_and_outputs import (
    ignore_or_process_event, trigger_acknowledge, send_vmss_info, send_message,
    send_cluster_info, send_retrigger, get_recount
)
from .ssh_and_cluster_utils import get_cluster_info, get_first_reachable_ftd
from .fmc_operations import configureManager, FirepowerManagementCenter, ftdv_reg_polling

def main(msg: func.QueueMessage):

    try:
        #decide if event is to ignored
        if ignore_or_process_event(msg):
            return

        rcount = get_recount(msg)
        #send message to queue indicating function execution has started
        trigger_acknowledge(msg)

        #get dict object with relevent fields
        info = get_vmss_info()

        send_vmss_info(msg.id, info)

        status, index, channel, ssh = get_first_reachable_ftd(info)
        if status != "SUCCESS":
            if ssh is not None: ssh.close()
            send_message(msg.id, status)
            send_retrigger("no reachable FTDvs found", rcount)
            return

        send_message(msg.id, "First reachable FTD index: " + index)

        cluster_info = get_cluster_info(index, channel)
        status = cluster_info[0]
        if status != 'SUCCESS':
            if ssh is not None: ssh.close()
            send_message(msg.id, status)
            send_retrigger("Failed to get cluster info", rcount)
            return

        send_cluster_info(msg.id, cluster_info, rcount)
        if 'UNHEALTHY' in cluster_info[1]:
            return

        fmc_ip = os.environ['FMC_IP']
        reg_id = os.environ['REG_KEY']
        nat_id = os.environ['NAT_ID']
        management_ip = info[index]['MgmtPublic']
        vm_name = management_ip
        policy_id = os.environ['POLICY_NAME']
        performanceTier = 'FTDv50'

        conf_status = configureManager(channel, fmc_ip, reg_id, nat_id)
        if conf_status != "SUCCESS":
            send_message(msg.id, "Manager for the cluster already exists. Proceeding with FMCv Registration.")
            # return

        fmc = FirepowerManagementCenter()
        reg_task_id = fmc.register_ftdv(vm_name=vm_name, mgmtip=management_ip, reg_id=reg_id, nat_id=nat_id, policy_id=policy_id, performanceTier=performanceTier)
        if not reg_task_id:
            send_message(msg.id, "Registration failed in FMCv. Stopping Execution")
            return

        send_message(msg.id, "Registration initiated with task ID in FMC: " + reg_task_id)

        reg_status = ftdv_reg_polling(fmc, task_id=reg_task_id, minutes=1)
        reg_time = 60
        while reg_status != "SUCCESS" and reg_time <= 300:
            send_message(msg.id, "Registration pending after " + str(reg_time) + " seconds from initiation")
            reg_status = ftdv_reg_polling(fmc, task_id=reg_task_id, minutes=1)
            reg_time = reg_time + 60
        if reg_status == "SUCCESS":
            send_message(msg.id, "Registration complete")

    except Exception as e:
        send_message(msg.id, str(e))
        send_retrigger("exception occured", rcount+1 )
