import os
import json
import time
import base64
from datetime import datetime
from azure.storage.queue import QueueClient, TextBase64EncodePolicy

def get_queue():
    constr = os.environ['AzureWebJobsStorage']
    queue = QueueClient.from_connection_string(conn_str=constr, queue_name="outqueue")
    return queue

def get_inqueue():
    constr = os.environ['AzureWebJobsStorage']
    queue = QueueClient.from_connection_string(
        conn_str = constr,
        queue_name = "resourceactionsuccessqueue",
        message_encode_policy = TextBase64EncodePolicy()
    )
    return queue

def send_message(id,output,ttl=604800):
    queue = get_queue()
    thread = "Event thread: " + id + "\n"
    output = thread + str(output)
    queue.send_message(output,time_to_live=ttl)
    time.sleep(5)

def get_fields(m):
    event = json.loads(m.get_body().decode('utf-8'))
    subject = event['subject']
    action = event['data']['authorization']['action']
    return event, subject, action

def get_recount(m):
    event, subject, action = get_fields(m)
    if subject == 'Retrigger':
        rc = int(event['recount'])
        return rc
    return 0

def check_and_clean(inq, outq):
    if inq:
        inqueue = get_inqueue()
        inqueue.clear_messages()
    if outq:
        queue = get_queue()
        queue.clear_messages()

def ignore_or_process_event(m):
    event, subject, action = get_fields(m)
    allowed_actions = [
        'Microsoft.Web/sites/restart/action'#,
        #'Microsoft.Compute/virtualMachineScaleSets/virtualMachines/restart/action',
        #'Microsoft.Compute/virtualMachineScaleSets/virtualMachines/start/action',
        #'Microsoft.Compute/virtualMachineScaleSets/virtualMachines/deallocate/action',
        #'Microsoft.Compute/virtualMachineScaleSets/restart/action',
        #'Microsoft.Compute/virtualMachineScaleSets/deallocate/action',
        #'Microsoft.Compute/virtualMachineScaleSets/start/action'
    ]
    ignored =  True
    clean_in = False
    clean_out = False
    prefix = os.environ['RESOURCE_PREFIX']
    vmssname = prefix + '-vmss'
    appname = prefix + '-function-app'

    if (appname in subject or vmssname in subject) and action in allowed_actions:
        clean_out = True
        ignored = False

    elif subject == 'Retrigger':
        clean_out = True
        ignored = False

    else:
        queue = get_queue()
        l = queue.peek_messages(5)
        if not l:
            ignored = False

    check_and_clean(clean_in, clean_out)
    return ignored

def send_retrigger(cause, recount):
    timenow = str(datetime.now())
    recount = recount +1

    if recount > 9:
        queue = get_queue()
        queue.send_message("Stopping execution as 10 retriggers were encountered")
        return

    retrigger = '{"subject":"Retrigger","data":{"authorization":{'
    retrigger = retrigger + '"action":"Retrigger action"},'
    retrigger = retrigger + '"operationName":"Request retrigger as ' + cause
    retrigger = retrigger + ' during previous execution"},"eventTime":"'
    retrigger = retrigger + timenow + '","recount":"'+ str(recount) + '"}'
    time.sleep(30)
    inqueue = get_inqueue()
    inqueue.send_message(retrigger)

def trigger_acknowledge(m):
    event, subject, action = get_fields(m)
    action = "Action: " + action + "\n"
    opname = "Operation: " + event['data']['operationName'] + "\n"
    time = "Event time: " + event['eventTime'] +"\n"
    body = "Started function execution"
    if subject == 'Retrigger':
        recount = "Recount: " + event['recount'] + '\n'
        output = action + opname + time + recount + body
    else:
        output = action + opname + time + body
    send_message(m.id,output)


def send_vmss_info(id,info):
    body = "Data: Instances Description\n\n"
    for index in info:
        body = body + "Instance ID in scale set: " + index + "\n"
        body = body + "    Name: " + info[index]["Name"] + "\n"
        body = body + "    Status: " + info[index]["Status"] + "\n"
        body = body + "    Public management IP: " + info[index]["MgmtPublic"] + "\n"
        body = body + "    Private management IP: " + info[index]["MgmtPrivate"] + "\n"
    send_message(id,body)

def send_cluster_info(id, cluster_info, rcount):
    output = "Data: Cluster Info\n\n"
    output = output + "Cluster:\n    " + cluster_info[1] + "\n"
    output = output + "Slaves:\n    " + cluster_info[2] + "\n"

    try:
        output = output + "Master Instance ID:\n    " + cluster_info[3]
    except Exception as e:
        output = output + "First reachable FTDv not a part of cluster"
        send_retrigger("exception generated", rcount+1)

    if 'UNHEALTHY' in output:
        retrigger_msg = "Unhealthy cluster detected, nodes count "
        nums = [int(i) for i in cluster_info[1].split() if i.isdigit()]
        retrigger_msg = retrigger_msg  + str(nums[1]) + ' instead of ' + str(nums[0])
        send_message(id, output)
        send_retrigger(retrigger_msg, rcount)
    else:
        send_message(id, output, ttl=604800)
