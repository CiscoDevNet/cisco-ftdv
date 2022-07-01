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
from fmc_functions import FirepowerManagementCenter
from google.cloud import secretmanager

fmc = FirepowerManagementCenter()

def send_cmd_and_wait_for_execution(channel, command, wait_string):
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
     """
     Purpose:    To close ssh connection
     Parameters: ssh
     Returns:
     Raises:
     """
     ssh.close()

def establishingConnection(ip, user, password, minutes):
     """
     Purpose:    To establish connection between FTDv and Google Function using Paramiko
     Parameters: ip, username, password, timeout minutes
     Returns:    "SUCCESS", channel and ssh
     Raises:
     """
     print("Trying to Login to FTDv")
     ssh = paramiko.SSHClient()
     ssh.load_system_host_keys()
     ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
     for i in range(2*minutes):
          try:
               ssh.connect(ip, username=user, password=password, timeout=minutes)
               channel = ssh.invoke_shell()
               time.sleep(3)
               resp = channel.recv(9999)
               print(resp.decode("utf-8"))
               if "Configure firewall mode" in resp.decode("utf-8"):
                    channel.send("\n")
               if ">" in resp.decode("utf-8"):
                    return "SUCCESS",channel,ssh
               time.sleep(10)
          except paramiko.AuthenticationException as exc:
               print("Exception occurred: AuthenticationException {}".format(repr(exc)))
               print(str(i)+". Sleeping for 30 seconds")
               time.sleep(30)
          except paramiko.BadHostKeyException as exc:
               print("Exception(un-known) occurred: BadHostKeyException {}".format(repr(exc)))
               print(str(i)+". Sleeping for 30 seconds")
               time.sleep(30)
          except paramiko.SSHException as exc:
               print("Exception(un-known) occurred: SSHException {}".format(repr(exc)))
               print(str(i),". Sleeping for 30 seconds")
               time.sleep(30)
          except BaseException as exc:
               #for timeout
               #print("Exception(un-known) occurred: BaseException {}".format(repr(exc)))
               print(str(i)+". Sleeping for 30 seconds.BaseException")
               time.sleep(30)

     print("Timeout after ", minutes, " minutes.")
     return "TIMEOUT","",""

def checkConnection(channel):
     """
     Purpose:    To check the connection to FTDv
     Parameters: channel
     Returns:    'SUCCESS' or 'FAIL'
     Raises:
     """
     cmd = ''
     msg = send_cmd_and_wait_for_execution(channel, cmd, '>')
     if ">" in msg:
          print("Connection Alright")
          return 'SUCCESS'
          
     return 'FAIL'

def showVersion(channel):
     """
     Purpose:    To check the version of FTDv
     Parameters: channel
     Returns:    Version in format "a.b.c"
     Raises:
     """
     cmd = 'show version'
     msg = send_cmd_and_wait_for_execution(channel, cmd, '>')
     #print("Version : "+msg)
     pos = msg.find("Version ")
     version = msg[pos+len("Version "):pos+len("Version ")+len("a.b.c")] #format of version
     print("FTDv Version: " +version)
     return version


def changePassword(channel, prev_password, new_password):
     """
     Purpose:    To change the password of FTDv
     Parameters: channel, old password, new password
     Returns:    
     Raises:
     """
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
     
def configureManager(channel, fmc_ip, reg_id, nat_id):
     """
     Purpose:    To configure manager on FTDv
     Parameters: channel, fmc ip, reg id, nat id
     Returns:    
     Raises:
     """
     cmd = 'configure manager add ' + fmc_ip + ' ' + reg_id + ' ' + nat_id
     msg = send_cmd_and_wait_for_execution(channel, cmd, '>')

     print("MESSAGE: "+msg)
     
     if "Manager successfully configured." in msg:
          print("MANAGER CONFIGURED")
          return
     if "already exists" in msg:
          print("MANAGER ALREADY EXISTS")
          return
     return

def check_ftdv_reg_status(channel):
     """
     Purpose:    To check manager status on FTDv
     Parameters: channel
     Returns:    SUCCESS, PARTIAL, FAILED
     Raises:
     """
     cmd = "show managers"
     msg = send_cmd_and_wait_for_execution(channel, cmd, '>')

     if "Completed" in msg:
          return "COMPLETED"
     elif "Pending" in msg:
          return "PENDING"
     elif "No managers" in msg:
          return "NO MANAGERS"
     else:
          return "FAILED"

def ftdv_reg_polling(fmc, channel, vm_name, minutes=2):
     """
     Purpose:    To poll both NGFW & FMCv for registration status
     Parameters: FirepowerManagementCenter class object, Minutes, channel, VM name
     Returns:    SUCCESS, PARTIAL, FAILED
     Raises:
     """
     # Polling registration completion for specified 'minutes'
     status_in_ftdv = ''
     status_in_fmc = ''
     for i in range(1, 6*minutes):
          if i != ((2*minutes)-1):
               status_in_ftdv = check_ftdv_reg_status(channel)
               status_in_fmc = fmc.check_reg_status_from_fmc(vm_name)
               if status_in_ftdv == "COMPLETED" and status_in_fmc == 'SUCCESS':
                    return "SUCCESS"
               else:
                    print("Registration status in FTDv: " + status_in_ftdv + " in FMC: " + status_in_fmc)
                    print("Sleeping for 10 seconds")
                    time.sleep(10)
     if status_in_ftdv == "COMPLETED" or status_in_fmc == "SUCCESS":
          return "PARTIAL"
     return "FAILED"


def versionCheck(ftd_version, fmc_version):
     """
     Purpose:    To compare FTDv and FMCv version
     Parameters: FTDv version, FMCv version
     Returns:    'SUCCESS' when FMC and FTD is compatible, 'FAIL' otherwise
     Raises:
     """
     ftd_version = int(ftd_version.replace(".",""))
     fmc_version = int(fmc_version.replace(".",""))
     #print("fmcversion "+ str(fmc_version)+", ftdversion"+str(ftd_version))
     if fmc_version >= ftd_version:
          #print("FMC and FTD are compatible")
          return 'SUCCESS'
     else:
          print("ERROR: FMC version less than FTD")
          return 'FAIL'