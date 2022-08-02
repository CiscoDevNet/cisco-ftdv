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
Name:       basic_functions.py
Purpose:    This python file has basic functions for 
            SSH and running commands in FTDv.
"""

import paramiko
import time
import re
from fmc_functions import FirepowerManagementCenter
from google.cloud import secretmanager

fmc = FirepowerManagementCenter()


def responseMsg(channel):
     resp = channel.recv(9999) # 9999 is the number of bytes
     return resp.decode("utf-8")

def execCommand(channel,cmd):
     cmd = cmd + "\n"
     send_cmd_and_wait_for_execution(channel, cmd)
     channel.send(cmd)
     #time.sleep(3)  # 3 sec wait time
     resp = responseMsg(channel)
     print(resp)
     return resp

def send_cmd_and_wait_for_execution(channel, command, wait_string='>'):
     """
     Purpose:    Sends command and waits for string to be received
     Parameters: command, wait_string
     Returns:    rcv_buffer or None
     Raises:
     """
     channel.settimeout(60) #60 seconds timeout
     total_msg = ""
     rcv_buffer = b""
     try:
          channel.send(command + "\n")
          while wait_string not in rcv_buffer.decode("utf-8"):
               rcv_buffer = channel.recv(10000)
               print(rcv_buffer.decode("utf-8"))
               total_msg = total_msg + ' ' + rcv_buffer.decode("utf-8")
          return total_msg
     except Exception as e:
          print("Error occurred: {}".format(repr(e)))

def closeShell(ssh):
     ssh.close()

def establishingConnection(ip, user, password, minutes):
     print("Trying to Login to FTDv")
     ssh = paramiko.SSHClient()
     ssh.load_system_host_keys()
     ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
     for i in range(6*minutes):
          try:
               ssh.connect(ip, username=user, password=password, timeout=10)
               channel = ssh.invoke_shell()
               wait_multi_1sec(3)
               resp = channel.recv(9999)
               print(resp.decode("utf-8"))
               if "Configure firewall mode" in resp.decode("utf-8"):
                    channel.send("\n")
               if ">" in resp.decode("utf-8"):
                    return "SUCCESS",channel,ssh
               wait_multi_10sec(10)
          except paramiko.AuthenticationException as exc:
               print("Exception occurred: AuthenticationException {}".format(repr(exc)))
               print(str(i)+". Sleeping for 10 seconds")
               time.sleep(10)
          except paramiko.BadHostKeyException as exc:
               print("Exception(un-known) occurred: BadHostKeyException {}".format(repr(exc)))
               print(str(i)+". Sleeping for 10 seconds")
               time.sleep(10)
          except paramiko.SSHException as exc:
               print("Exception(un-known) occurred: SSHException {}".format(repr(exc)))
               print(str(i),". Sleeping for 10 seconds")
               time.sleep(10)
          except BaseException as exc:
               #for timeout
               #print("Exception(un-known) occurred: BaseException {}".format(repr(exc)))
               print(str(i)+". Sleeping for 10 seconds.BaseException")
               time.sleep(10)

     print("Timeout after ", minutes, " minutes.")
     return

def checkConnection(channel):
     cmd = ''
     msg = send_cmd_and_wait_for_execution(channel, cmd)
     if ">" in msg:
          print("Connection Alright")
          return 'SUCCESS'
          
     return 'FAIL'

def check_cluster_nodes(channel, min_nodes):
     cmd = 'show cluster info | count ID'
     msg = send_cmd_and_wait_for_execution(channel, cmd)
     print("MESSAGE: "+ msg)

     if str(min_nodes) in msg:
          print("Healthy : All Cluster Nodes available")
          return "Healthy"
     else:
          print("Unhealthy : One or Many Cluster Nodes not available")
          return "Unhealthy"

def check_cluster_slave_nodes(channel, min_nodes):
     cmd = 'show cluster info'
     msg = send_cmd_and_wait_for_execution(channel, cmd)
     slave_nodes = msg.count('in state SLAVE\r\n') 
     print("Available SLAVE nodes : "+ str(slave_nodes))

     if (min_nodes-1)  == slave_nodes:
          print("Healthy : All Cluster Nodes Ready for Registration")
          return "Healthy"
     else:
          print("Unhealthy : One or Many Cluster Nodes not available")
          return "Unhealthy"

def configureManager(channel, fmc_ip, reg_id, nat_id):
     cmd = 'configure manager add ' + fmc_ip + ' ' + reg_id + ' ' + nat_id

     msg = send_cmd_and_wait_for_execution(channel, cmd)

     print("MESSAGE: "+ msg)
     
     if "Manager successfully configured." in msg:
          print("MANAGER CONFIGURED")
          return
     if "already exists" in msg:
          print("MANAGER ALREADY EXISTS")
          return
     return

def check_ftdv_reg_status(channel):
     cmd = "show managers"
     msg = send_cmd_and_wait_for_execution(channel, cmd)

     if "Completed" in msg:
          return "COMPLETED"
     elif "Pending" in msg:
          return "PENDING"
     elif "No managers" in msg:
          return "NO MANAGERS"
     else:
          return "FAILED"

def ftdv_reg_polling(fmc, channel, task_id, minutes=2):
     """
     Purpose:    To poll both NGFW & FMCv for registration status
     Parameters: FirepowerManagementCenter class object, Minutes
     Returns:    SUCCESS, PARTIAL, FAILED
     Raises:
     """
     # Polling registration completion for specified 'minutes'
     if minutes <= 1:
          minutes = 2
     status_in_ftdv = ''
     status_in_fmc = ''
     for i in range(1, 2*minutes):
          if i != ((2*minutes)-1):
               status_in_ftdv = check_ftdv_reg_status(channel)
               status_in_fmc = fmc.check_task_status_from_fmc(task_id)
               if status_in_ftdv == "COMPLETED" and status_in_fmc == 'DEVICE_SUCCESSFULLY_REGISTERED':
                    return "SUCCESS"
               elif status_in_fmc == 'DEPLOYMENT_FAILED' or status_in_fmc == 'REGISTRATION_FAILED':
                    return "FAILED"
               else:
                    print("Registration status in FTDv: " + status_in_ftdv + " in FMC: " + status_in_fmc)
                    print("Sleeping for 30 seconds")
                    time.sleep(30)
     if status_in_ftdv == "COMPLETED" or status_in_fmc == "SUCCESS":
          return "PARTIAL"
     return "FAILED"

def verify_cluster_member(fmc, channel, min_nodes, cls_grp_name):
     """
     Purpose:    To verify all ftdv cluster node get registered
     Parameters: FirepowerManagementCenter class object
     Returns:    SUCCESS, FAILED
     Raises:
     """
     cls_grp_id = fmc.get_cluster_id_by_name(name=cls_grp_name)
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

def get_master_node_unit(channel):
     cmd = 'show cluster info'
     msg = send_cmd_and_wait_for_execution(channel, cmd)

     for line in msg.splitlines():
         if 'MASTER' in line :
             if ((line.strip()).startswith('This')):
                 numbers=re.findall('[0-9]+', line)
                 return numbers[0]
             else:
                 numbers=re.findall('[0-9]+', line)
                 return numbers[0]

def secretCode(project_id, secret_id, version_id):
     client = secretmanager.SecretManagerServiceClient()
     name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
     response = client.access_secret_version(request={"name": name})
     return response.payload.data.decode("UTF-8")

def wait_multi_10sec(time_in_sec):
    abort_after = time_in_sec
    start = time.time()
    time_left = abort_after
    while True:
        delta = time.time() - start
        print ("wait for "+ str(time_left) +" seconds ...")
        if delta >= abort_after:
            break
        time.sleep(10)
        time_left = time_left -10

def wait_multi_1sec(time_in_sec):
    abort_after = time_in_sec
    start = time.time()
    time_left = abort_after
    while True:
        delta = time.time() - start
        print ("wait for "+ str(time_left) +" seconds ...")
        if delta >= abort_after:
            break
        time.sleep(1)
        time_left = time_left -1
