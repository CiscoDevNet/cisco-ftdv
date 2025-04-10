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

Name:       cluster_utils.py
Purpose:    This python file has method for cluster operation.
"""

import os
import sys
import time
import paramiko
import logging as log

class ClusterUtils:
    def __init__(self,ftdv_ip, port, username, password):
        self.ftdv_ip = ftdv_ip
        self.port = port
        self.username = username
        self.password = password

    def establishConnection(self):
            ssh = paramiko.SSHClient()
            ssh.load_system_host_keys()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            failure_msg = ""
            try:
                ssh.connect(self.ftdv_ip, username=self.username, password=self.password, timeout=5)
                channel = ssh.invoke_shell()
                time.sleep(3)
                while not channel.recv_ready():
                    time.sleep(3)
                resp = channel.recv(9999).decode("utf-8")
                if "Configure firewall mode" in resp:
                    while not channel.send_ready():
                        time.sleep(3)
                    channel.send("\n")

                while ">" not in resp:
                    while not channel.recv_ready():
                        time.sleep(3)
                    resp = channel.recv(9999).decode("utf-8")

                if ">" in resp:
                    log.info("Successfully established the connection")
                    return "SUCCESS",channel,ssh
                else:
                    log.info("Unable to establish the SSH connection to the FTDv")
                    failure_msg = "FTDERROR: FTDv CLI not available for upto "
            except:
                log.info("Error occurred while establishing the ssh connection")
                failure_msg = "EXCEPTION: " + "Connection timed out"

            return "FAILED: Unable to ssh to the FTDv : Error : \n" + failure_msg, None, None


    def send_cmd_and_wait_for_execution(self, channel, command, wait_string='>'):
        channel.settimeout(60)
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


    def get_cluster_info(self):
        cmd = "show cluster info"
        for i in range(3):
            status, channel, ssh = self.establishConnection()
            log.debug("ClusterUtils:: SSH Status : {}".format(status))
            if channel is not None:
                break
            else:
                log.info("clusterutils:: Unable to establish the ssh connection. trying in 30 seconds...")
                time.sleep(30)

        if channel is None:
            return "SSH_FAILURE", "Unable to establish the SSH connection"

        status, msg = self.send_cmd_and_wait_for_execution(channel, cmd)
        if status == "FAILED":
            return status + ': ' + msg
        else:
            return status, msg

    def is_control_node(self, cluster_info):
        pos1 = cluster_info.find("This is")
        pos2 = cluster_info.find('\n',pos1)
        node_info_line = cluster_info[pos1:pos2]
        if "CONTROL_NODE" in node_info_line:
            return True
        else:
            return False
        
    def get_node_state(self, cluster_info):
        pos1 = cluster_info.find("This is")
        pos2 = cluster_info.find('\n',pos1)
        try:
            node_info_line = cluster_info[pos1:pos2]
            return node_info_line[node_info_line.rfind(" ")+1:].strip()
        except:
            return "ERROR"
        
    def disable_cluster(self):
        cmd = "cluster disable"
        status, channel, ssh = self.establishConnection()
        status, msg = self.send_cmd_and_wait_for_execution(channel, cmd)
        if status == "FAILED":
            return status + ": " + msg
        else:
            return status, msg 
