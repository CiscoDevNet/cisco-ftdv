import os
import sys
import time
import paramiko
from .azure_utils import get_ftdindex_from_mgmt_last

def establishConnection(ip, user, password, try_count):

    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    failure_msg = ""

    for i in range(try_count):
        try:
            ssh.connect(ip, username=user, password=password, timeout=5)
            channel = ssh.invoke_shell()
            time.sleep(3)
            while not channel.recv_ready():
                time.sleep(3)
            resp = channel.recv(9999).decode("utf-8")

            if "Configure firewall mode" in resp:
                while not channel.send_ready():
                    time.sleep(3)
                channel.send("\n")

            j=0
            while ">" not in resp and j<try_count:
                while not channel.recv_ready():
                   time.sleep(3)
                resp = channel.recv(9999).decode("utf-8")

            if ">" in resp:
                 return "SUCCESS",channel,ssh

            else:
                failure_msg = "FTDERROR: FTDv CLI not available for upto "
                failure_msg = failure_msg + str(try_count*5+3) + " seconds past login"

        except:
           failure_msg = "EXCEPTION: " + "Connection timed out"

    return "FAILED: Tried " + str(try_count) + " times, but encountered\n" + failure_msg, None, None

def get_first_reachable_ftd(info):

    username = os.environ.get('FTD_USERNAME')
    passwd = os.environ.get('FTD_PASSWORD')
    ftdcount = int(os.environ.get('FTD_COUNT'))
    infolen = len(info)

    if infolen < ftdcount:
        message = "Instance count in scale set less than the provided ftdCount, "
        message = message + "restart the app after manually scaling instance count to "
        message = message + "the ftdCount provided during template deployment"
        raise RuntimeError(message)

    i = -1
    t = 0
    any_running_or_starting = False

    while True:

        if t>60:
            break

        i = i+1
        if i==infolen:
            i=0
            if not any_running_or_starting:
                break

        vmindex = list(info.keys())[i]
        if info[vmindex]["Status"] not in ["VM running", "VM starting", "Updating"]:
            continue

        any_running_or_starting = True
        login_ip = info[vmindex]["MgmtPublic"]
        status, channel, ssh = establishConnection(login_ip, username, passwd, 1)

        if status == "SUCCESS":
            return "SUCCESS", vmindex, channel, ssh

        time.sleep(5)
        t = t + 15

    if not any_running_or_starting:
        return "FAILURE: No FTDv found in running/starting state", None, None, None
    else:
        fail_msg = "FAILURE: No reachable FTDv found in atleast 1 min\nEither "
        fail_msg = fail_msg + "IPs are not reachable or admin password is wrong"
        return fail_msg, None, None, None

def send_cmd_and_wait_for_execution(channel, command, wait_string='>'):

    channel.settimeout(60) #60 seconds timeout
    total_msg = ""
    resp = ""
    try:
        while not channel.send_ready():
            time.sleep(3)
        channel.send(command + "\n")
        while wait_string not in resp:
            while not channel.recv_ready():
               time.sleep(3)
            resp = channel.recv(10000).decode("utf-8")
            total_msg = total_msg + resp
        return "SUCCESS", total_msg

    except:
        return "FAILED", "Connection timed out"

def check_cluster_nodes(channel, count):

    cmd = 'show cluster info | count ID'
    status, msg = send_cmd_and_wait_for_execution(channel, cmd)
    if status == "FAILED": return status + ': ' + msg

    if str(count) in msg:
        return status, "HEALTHY, " + str(count) + "/" + str(count) + " nodes active"
    else:
        numstart = msg.find("=") + 1
        numend = msg.find('\n', numstart)
        num = msg[numstart:numend].strip()

        if int(num) > int(count):
            message = "Running VMs in scale set more than the provided ftdCount, "
            message = message + "restart the app after manually scaling instance count to "
            message = message + "the ftdCount provided during template deployment"
            raise RuntimeError(message)

        return status, "UNHEALTHY, expected " + str(count) + " nodes but found " + num

def check_cluster_data_nodes(channel, count):

    cmd = 'show cluster info | count DATA_NODE'
    status, msg = send_cmd_and_wait_for_execution(channel, cmd)
    if status == "FAILED": return status + ': ' + msg

    if str(count-1) in msg:
        return status, "HEALTHY, " + str(count-1) + "/" + str(count-1) + " data nodes active"
    else:
        numstart = msg.find("=") + 1
        numend = msg.find('\n', numstart)
        num = msg[numstart:numend].strip()
        return status, "UNHEALTHY, expected " + str(count-1) + " data nodes but found " + num

def get_control_node(index, channel):

    cmd = "show cluster info"
    node_info_line = "ELECTION"

    while "ELECTION" in node_info_line:
        status, msg = send_cmd_and_wait_for_execution(channel, cmd)
        if status == "FAILED": return status + ': ' + msg

        if 'Clustering is not enabled' in msg:
            status, msg = send_cmd_and_wait_for_execution(channel, 'cluster enable')
            status, msg = send_cmd_and_wait_for_execution(channel, cmd)

        pos1 = msg.find("This is")
        pos2 = msg.find('\n',pos1)
        node_info_line = msg[pos1:pos2]

    if "CONTROL_NODE" in node_info_line:
        return "SUCCESS", index

    pos1 = msg.find("CONTROL_NODE")
    pos1 = msg.find("CCL IP",pos1)
    pos2 = msg.find('\n',pos1)
    control_node_ccl_line = (msg[pos1:pos2]).strip()
    control_node_mgmt = control_node_ccl_line.split(' ')[-1]
    control_node_mgmt_last = control_node_mgmt.split('.')[-1]

    return "SUCCESS", get_ftdindex_from_mgmt_last(control_node_mgmt_last)

def get_cluster_info(index, channel):

    status, control_node = get_control_node(index,channel)
    if status != "SUCCESS": return exec_status, None, None, None

    ftdcount = os.environ.get('FTD_COUNT')
    exec_status, cluster_health_status = check_cluster_nodes(channel,ftdcount)
    if exec_status != "SUCCESS": return exec_status, None, None, None

    exec_status, data_node_health_status = check_cluster_data_nodes(channel,int(ftdcount))
    if exec_status != "SUCCESS": return exec_status, None, None, None

    return "SUCCESS", cluster_health_status, data_node_health_status, control_node
