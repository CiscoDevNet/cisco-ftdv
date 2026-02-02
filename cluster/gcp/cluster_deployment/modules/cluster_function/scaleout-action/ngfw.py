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
Name:       basic_functions.py
Purpose:    This python file has basic functions for 
            SSH and running commands in FTDv.
"""
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)

import paramiko
import time
from google.cloud import secretmanager

def responseMsg(channel):
     resp = channel.recv(9999) # 9999 is the number of bytes
     return resp.decode("utf-8")

def execCommand(channel,cmd):
     cmd = cmd + "\n"
     resp = ""
     try:
          send_cmd_and_wait_for_execution(channel, cmd)
          channel.send(cmd)
          #time.sleep(3)  # 3 sec wait time
          resp = responseMsg(channel)
     except Exception as e:
          print("ERROR: " + str(e))
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
               # print(f"DEGUG: {rcv_buffer.decode("utf-8")}")
               total_msg = total_msg + ' ' + rcv_buffer.decode("utf-8")
          return total_msg
     except Exception as e:
          raise Exception("Error occurred: {}".format(repr(e)))

def closeShell(ssh):
     ssh.close()

def establishingConnection(ip, user, password):
     ssh = paramiko.SSHClient()
     ssh.load_system_host_keys()
     ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
     try:
          ssh.connect(ip, username=user, password=password, timeout=20)
          channel = ssh.invoke_shell()
          time.sleep(3)
          resp = channel.recv(9999)
          # print(resp.decode("utf-8"))
          if "Configure firewall mode" in resp.decode("utf-8"):
               channel.send("\n")
          if ">" in resp.decode("utf-8"):
               return "SUCCESS", channel, ssh
          time.sleep(10)
     except paramiko.AuthenticationException as exc:
          print("Exception occurred: AuthenticationException {}".format(repr(exc)))
     except paramiko.BadHostKeyException as exc:
          print("Exception(un-known) occurred: BadHostKeyException {}".format(repr(exc)))
     except paramiko.SSHException as exc:
          print("Exception(un-known) occurred: SSHException {}".format(repr(exc)))
     except Exception as exc:
          # SSH is not ready yet, handling print in main function.
          pass

     return "FAIL", None, None

def checkConnection(channel):
     msg = ''
     cmd = ''
     try:
          msg = send_cmd_and_wait_for_execution(channel, cmd)
     except Exception as e:
          print("ERROR: " + str(e))
     if ">" in msg:
          print("Connection Alright")
          return 'SUCCESS'
     return 'FAIL'

def configureManager(channel, fmc_ip, reg_id, nat_id):
     msg = ""
     cmd = 'configure manager add ' + fmc_ip + ' ' + reg_id + ' ' + nat_id
     try:
          msg = send_cmd_and_wait_for_execution(channel, cmd)
     except Exception as e:
          print("ERROR: " + str(e))
     print("INFO: Configure Manager response: "+ msg)
     if "Manager successfully configured." in msg:
          print("INFO: MANAGER CONFIGURED")
          return
     if "already exists" in msg:
          print("INFO: MANAGER ALREADY EXISTS")
          return
     return

def check_ftdv_reg_status(channel):
     msg = ""
     cmd = "show managers"
     try:
          msg = send_cmd_and_wait_for_execution(channel, cmd)
     except Exception as e:
          raise Exception("ERROR: " + str(e))
          
     if "Completed" in msg:
          return "COMPLETED"
     elif "Pending" in msg:
          return "PENDING"
     elif "No managers" in msg:
          return "NO MANAGERS"
     elif "In progress" in msg:
          return "IN PROGRESS"
     else:
          return "FAILED"

def check_reg_status(fmc, channel, task_id, minutes=2):
     """
     Purpose:    To poll both NGFW & FMCv for registration status
     Parameters: FirepowerManagementCenter class object, Minutes
     Returns:    SUCCESS, PARTIAL, FAILED
     Raises:
     """
     status_in_ftdv = ''
     status_in_fmc = ''
     try:
          status_in_ftdv = check_ftdv_reg_status(channel)
     except Exception as e:
          raise Exception("ERROR: " + str(e))
     try:
          status_in_fmc = fmc.check_task_status_from_fmc(task_id)
     except Exception as e:
          raise Exception("ERROR: " + str(e))
     
     if status_in_ftdv == "COMPLETED" and status_in_fmc == 'DEVICE_SUCCESSFULLY_REGISTERED':
          return "SUCCESS"
     elif status_in_fmc == 'DEPLOYMENT_FAILED' or status_in_fmc == 'REGISTRATION_FAILED':
          return "FAILED"
     else:
          print("INFO: Registration status in FTDv: " + status_in_ftdv + " & status in FMC: " + status_in_fmc)
     if status_in_ftdv == "COMPLETED" or status_in_fmc == "SUCCESS":
          return "PARTIAL"
     return "FAILED"

def changePassword(channel, prev_password, new_password):
     """
     Purpose:    To change the password of FTDv
     Parameters: channel, old password, new password
     Returns:    
     Raises:
     """
     try:
          cmd = "configure password"
          msg = send_cmd_and_wait_for_execution(channel, cmd, '\n')
          time.sleep(3)
          #Enter Previous Password
          cmd = prev_password
          msg = send_cmd_and_wait_for_execution(channel, cmd, '\n')
          time.sleep(3)
          #Enter new Password
          cmd = new_password
          msg = send_cmd_and_wait_for_execution(channel, cmd, '\n')
          time.sleep(3)
          #Re-enter new Password
          cmd = new_password
          msg = send_cmd_and_wait_for_execution(channel, cmd, '\n')
          time.sleep(3)
          return
     except Exception as e:
          raise Exception("ERROR: " + str(e))

def secretCode(project_id, secret_id, version_id):
     client = secretmanager.SecretManagerServiceClient()
     name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
     response = client.access_secret_version(request={"name": name})
     return response.payload.data.decode("UTF-8")

def wait_multi_10sec(time_in_sec):
     for i in range(0, time_in_sec, 10):
          print(f"INFO: Waiting for {time_in_sec} seconds" + (f", {i} seconds elapsed" if i > 0 else ""))
          time.sleep(10)

def is_time_up(start_time, timeout_time):
     if time.time() - start_time > timeout_time:
          return True
     else:
          return False