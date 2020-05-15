"""
Copyright (c) 2020 Cisco Systems Inc or its affiliates.

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
"""
import re
import time
import logging
import paramiko
import socket
import json
import constant as const
import utility as utl
from aws import Ec2Instance
from aws import ASG
"""
Name:       ngfw.py
Purpose:    This is contains ngfw class methods, SSH Paramiko class methods
"""
# Setup Logging
logger = utl.setup_logging(utl.e_var['DebugDisable'])


# FTDv related class
class NgfwInstance (Ec2Instance):
    def __init__(self, instance_id):
        super().__init__(instance_id)
        self.public_ip = self.get_public_ip()
        self.port = utl.j_var['NgfwSshPort']

        self.username = utl.e_var['NgfwUserName']
        self.password = utl.e_var['NgfwPassword']
        self.defaultPassword = utl.j_var['NgfwDefaultPassword']

        self.fmc_ip = utl.j_var['DeviceRegFmcIp']
        self.reg_id = utl.j_var['RegistrationId']
        self.nat_id = utl.j_var['NatId']
        self.license_caps = utl.j_var['LicenseCaps']

        self.COMMAND_RAN = 'COMMAND_RAN'
        self.SUCCESS = 'SUCCESS'
        self.FAIL = 'FAILURE'

    def connect_ngfw(self):
        """
        Purpose:    This provides object of ParamikoSSH class
        Parameters:
        Returns:    Class object
        Raises:
        """
        connect = ParamikoSSH(self.public_ip, self.port, self.username, self.password)
        return connect

    # Run an independent command on FTDv
    def run_ftdv_command(self, command):
        """
        Purpose:    To run a single command
        Parameters:
        Returns:    'FAILURE', 'COMMAND_RAN'
        Raises:
        """
        output, error = '', ''
        cnt_ngfw = self.connect_ngfw()
        try:
            status, output, error = cnt_ngfw.execute_cmd(command)
        except Exception as e:
            logger.error("Error occurred: {}".format(repr(e)))
            return self.FAIL, output, error
        if status == self.SUCCESS:
            return self.COMMAND_RAN, output, error
        else:
            logger.warn("Unable to run command output: %s error: %s" % (output, error))
            return self.FAIL, output, error

    # Checks FTDv if SSH possible AND can execute 'show managers' command
    def check_ftdv_ssh_status(self):
        """
        Purpose:    To check NGFW SSH is accessible
        Parameters:
        Returns:    SUCCESS, FAILURE
        Raises:
        """
        cnt_ngfw = self.connect_ngfw()
        status = cnt_ngfw.connect(self.username, self.password)
        if status == 'SUCCESS':
            return 'SUCCESS'
        elif status == 'Authentication Exception Occurred':
            status = cnt_ngfw.connect(self.username, self.defaultPassword)
            if status == 'SUCCESS':
                cnt_ngfw.close()  # As below function triggers interactive shell
                if self.change_ngfw_password(cnt_ngfw, self.defaultPassword, self.password) == 'SUCCESS':
                    return 'SUCCESS'
            else:
                logger.error("Unable to authenticate to NGFW instance, please check password!")
                return 'FAILURE'
        return 'FAILURE'

    # Checks registration by doing SSH to FTDv
    def check_ftdv_reg_status(self):
        """
        Purpose:    Check Registration status
        Parameters:
        Returns:    'FAILURE', 'PENDING', 'COMPLETED', 'NO_MANAGER'. 'TROUBLESHOOT'
        Raises:
        """
        r, output, error = self.show_managers()
        logger.debug("status: %s output: %s error: %s" % (r, output, error))

        if len(re.findall('pending', output)) == 1:
            logger.debug("Instance " + self.public_ip + ", is pending to register with FMC")
            return "PENDING"
        elif len(re.findall('Completed', output)) == 1:
            logger.debug("Instance " + self.public_ip + ", already registered with FMC")
            return "COMPLETED"
        elif len(re.findall('No managers', output)) == 1:
            logger.debug("Instance " + self.public_ip + ", SSH is up but not configured to register with FMC")
            return "NO_MANAGER"
        elif len(re.findall('local', output)) == 1:
            logger.debug("Instance " + self.public_ip + ", SSH is up but configured locally")
            return "TROUBLESHOOT"
        else:
            return 'FAILURE'

    # Polling connectivity to FTDv for specified 'minutes', ability to run 'show managers' command
    def poll_ftdv_ssh(self, minutes):
        """
        Purpose:    To poll NGFW for SSH accessibility
        Parameters: Minutes
        Returns:    SUCCESS, TIMEOUT
        Raises:
        """
        logger.info("Checking if instance SSH access is available!")
        if minutes <= 1:
            minutes = 2
        for i in range(1, 2 * minutes):
            if i != ((2 * minutes) - 1):
                status = self.check_ftdv_ssh_status()
                if status != "SUCCESS":
                    logger.debug(str(i) + " Sleeping for 30 seconds")
                    time.sleep(1 * 30)
                else:
                    return "SUCCESS"
        logger.info("Failed to connect to device retrying... ")
        return "TIMEOUT"

    def show_managers(self):
        """
        Purpose:    To run command 'show managers'
        Parameters:
        Returns:    'FAILURE', 'COMMAND_RAN', output and error
        Raises:
        """
        cmd = 'show managers'
        r, output, error = self.run_ftdv_command(cmd)
        logger.debug(output)
        return r, output, error

    # Function to configure manager
    def configure_manager(self):
        """
        Purpose:    To run command 'configure manager add'
        Parameters:
        Returns:    'FAILURE', 'COMMAND_RAN'
        Raises:
        """
        cmd = 'configure manager add ' + self.fmc_ip + ' ' + self.reg_id + ' ' + self.nat_id
        r, output, error = self.run_ftdv_command(cmd)
        logger.info(output)
        return r

    # Function to run configure manager delete
    def configure_manager_delete(self):
        """
        Purpose:    To run 'configure manager delete'
        Parameters:
        Returns:    'FAILURE', 'COMMAND_RAN'
        Raises:
        """
        cmd = 'configure manager delete'
        r, output, error = self.run_ftdv_command(cmd)
        logger.info(output)
        return r

    # function to set hostname
    def configure_hostname(self):
        """
        Purpose:    To configure hostname on NGFW
        Parameters:
        Returns:    'FAILURE', 'COMMAND_RAN'
        Raises:
        """
        cmd = 'configure network hostname' + ' ' + self.vm_name
        r, output, error = self.run_ftdv_command(cmd)
        logger.info("Instance hostname configuration: " + output)
        return r

    # function to change password(admin) from prev_password to new_password
    def change_ngfw_password(self, cnt_ngfw, prev_password, new_password):
        """
        Purpose:    To change password from default to user provided
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        command_set = {
            "cmd": [
                {
                    "command": "configure password",
                    "expect": "Enter current password:"
                },
                {
                    "command": prev_password,
                    "expect": "Enter new password:"
                },
                {
                    "command": new_password,
                    "expect": "Confirm new password:"
                },
                {
                    "command": new_password,
                    "expect": "Password Update successful"
                }
            ]
        }

        try:
            cnt_ngfw.handle_interactive_session(command_set, self.username, prev_password)
        except ValueError as e:
            logger.error("Error occurred: {}".format(repr(e)))
            return None
        else:
            return 'SUCCESS'

    def ftdv_reg_polling(self, fmc, minutes=2):
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
                status_in_ftdv = self.check_ftdv_reg_status()
                status_in_fmc = fmc.check_reg_status_from_fmc(self.vm_name)
                if status_in_ftdv == "COMPLETED" and status_in_fmc == 'SUCCESS':
                    return "SUCCESS"
                else:
                    logging.debug("Registration status in FTDv: " + status_in_ftdv + " in FMC: " + status_in_fmc)
                    logging.debug("Sleeping for 30 seconds")
                    time.sleep(1*30)
        if status_in_ftdv == "COMPLETED" or status_in_fmc == "SUCCESS":
            return "PARTIAL"
        return "FAILED"

    def send_registration_request(self, fmc, device_grp_id):
        """
        Purpose:    To send Device Registration request to FMC
        Parameters: FirepowerManagementCenter class object, Device Group
        Returns:    SUCCESS, FAIL
        Raises:
        """
        reg_task_id = fmc.register_ftdv(self.vm_name, self.public_ip, self.reg_id, self.nat_id, self.license_caps,
                                        device_grp_id)
        if reg_task_id is not None:
            reg_status = self.ftdv_reg_polling(fmc, 4)  # 4 minutes polling
            if reg_status == "PARTIAL":
                reg_status = self.ftdv_reg_polling(fmc, 3)  # 3 minutes extra polling if partial
            if reg_status == "FAILED":
                return 'FAIL'
            elif reg_status == "SUCCESS":
                return 'SUCCESS'
        return 'FAIL'

    def check_and_configure_routes(self, fmc):
        """
        Purpose:    Checks for Static Route if present, if not then creates the Static Route.
        Parameters: fmc object from caller function
        Returns:    Success or Fail
        Raises:
        """
        for fmcObject in utl.j_var['TrafficRoutes']:
            static_route = {
                "interface": "",
                "network": "",
                "gateway": "",
                "metric": ""
            }
            try:
                static_route['interface'] = fmcObject['interface']
                static_route['network'] = fmcObject['network']
                static_route['metric'] = fmcObject['metric']
                static_route['gateway'] = fmcObject['gateway']
            except KeyError as e:
                logger.error("Error occurred: {}".format(repr(e)))
                return 'FAIL'
            except Exception as e:
                logger.critical("Un-handled Error occurred: {}".format(repr(e)))
                return 'FAIL'

            if static_route['gateway'] == '':
                if static_route['interface'] == utl.j_var['InsideNicName']:
                    subnet_id = self.get_subnet_id_of_interface(const.INSIDE_ENI_NAME)
                    subnet_cidr = self.get_cidr_describe_subnet(subnet_id)
                    static_route['gateway'] = utl.get_gateway_from_cidr(subnet_cidr)
                elif static_route['interface'] == utl.j_var['OutsideNicName']:
                    subnet_id = self.get_subnet_id_of_interface(const.OUTSIDE_ENI_NAME)
                    subnet_cidr = self.get_cidr_describe_subnet(subnet_id)
                    static_route['gateway'] = utl.get_gateway_from_cidr(subnet_cidr)
            check_static_route_if_exists = fmc.check_static_route(self.vm_name, static_route['interface'],
                                                                  static_route['network'], static_route['gateway'])
            logger.debug("Route status: " + check_static_route_if_exists)
            if check_static_route_if_exists == 'UN-CONFIGURED':
                # Configure Static Route
                logger.info("Configuring Route: " + json.dumps(static_route, separators=(',', ':')))

                if fmc.get_host_objectid_by_name(static_route['network']) != '':
                    r = fmc.create_static_host_route(self.vm_name, static_route['interface'], static_route['network'],
                                                     static_route['gateway'], static_route['metric'])
                elif fmc.get_network_objectid_by_name(static_route['network']) != '':
                    r = fmc.create_static_network_route(self.vm_name, static_route['interface'],
                                                        static_route['network'],
                                                        static_route['gateway'], static_route['metric'])
                else:
                    logger.error("trafficRoutes.network value in Configuration json is not correct")
                    return 'FAIL'

                if r.status_code != 200 and r.status_code != 201:
                    logger.error("Route configuration failed: " + str(r.status_code))
                    logger.error("response: " + str(r.json()))
                    return 'FAIL'
                else:
                    logger.info("Static Host route configuration REST response {}".format(r.status_code))
        return 'SUCCESS'

    def check_and_configure_interface(self, fmc):
        """
        Purpose:    Checks interface configuration & create if necessary
        Parameters: fmc object from caller function
        Returns:    Success or Fail
        Raises:
        """
        deviceId = fmc.get_device_id_by_name(self.vm_name)

        if deviceId == '':
            logger.error("Device %s not available in FMC" % self.vm_name)
            return 'FAIL'

        var_i = 0
        securityZoneName = []
        zoneId = []
        ifname = []
        name = []
        nicId = []
        
        if const.NIC_CONFIGURE == "STATIC":  # Related to CSCvs17405
            ip = []
            netmask = []
            subnet_id = []

        for fmcObject in utl.j_var['InterfaceConfig']:
            try:
                managementOnly = fmcObject['managementOnly']
            except:
                managementOnly = 'false'
            try:
                MTU = fmcObject['MTU']
            except:
                MTU = 1500
            try:
                mode = fmcObject['mode']
            except:
                mode = 'NONE'
            try:
                ifname.append(fmcObject['ifname'])
            except:
                logger.error("In Configuration JSON file, interface ifname isn't available")
                return 'FAIL'
            try:
                securityZoneName.append(fmcObject['securityZone']['name'])
                zoneId.append(fmc.get_security_objectid_by_name(securityZoneName[var_i]))
                if zoneId[var_i] is None:
                    logger.warn("Security Zone %s not available in FMC" % securityZoneName[var_i])
                    return 'FAIL'
            except:
                logger.error("In Configuration JSON file, interface security zone isn't available")
                return 'FAIL'
            try:
                name.append(fmcObject['name'])
                nicId.append(fmc.get_nic_id_by_name(self.vm_name, name[var_i]))
                if nicId[var_i] is None:
                    logger.warn("Interface %s not available" % name[var_i])
                    return 'FAIL'
            except:
                logger.error("In Configuration JSON file, interface name "
                             "(Ex: GigabitEthernet0/0 or 0/1) isn't available")
                return 'FAIL'
            
            if const.NIC_CONFIGURE == "STATIC":
                if name[var_i] == "GigabitEthernet0/0":
                    nic_suffix = const.INSIDE_ENI_NAME
                elif name[var_i] == "GigabitEthernet0/1":
                    nic_suffix = const.OUTSIDE_ENI_NAME
                    
                ip.append(self.get_private_ip_of_interface(nic_suffix))
                subnet_id.append(self.get_subnet_id_of_interface(nic_suffix))
                netmask.append(self.get_subnet_mask_from_subnet_id(subnet_id[var_i]))
                
                # Check if configured when Static
                check_if_configured = fmc.get_nic_status(deviceId, name[var_i], nicId[var_i], ifname[var_i], zoneId[var_i], ip[var_i])
                
            elif const.NIC_CONFIGURE == "DHCP":
                # Check if configured when DHCP
                check_if_configured = fmc.get_nic_status(deviceId, name[var_i], nicId[var_i], ifname[var_i], zoneId[var_i])
            
            
            # Configure Nic if not CONFIGURED
            if check_if_configured == 'UN-CONFIGURED':
                try:
                    logger.info("Configuring Nic %s ..." % (name[var_i]))
                    if const.NIC_CONFIGURE == "STATIC":
                        r = fmc.configure_nic_static(self.vm_name, name[var_i], ifname[var_i], securityZoneName[var_i], MTU, ip[var_i], netmask[var_i])
                    elif const.NIC_CONFIGURE == "DHCP":
                        r = fmc.configure_nic_dhcp(self.vm_name, name[var_i], ifname[var_i], securityZoneName[var_i], MTU)
                    logger.info("Response: ")
                    logger.info(r)
                except Exception as e:
                    logger.error("Configuring Nic failed!")
                    logger.error(str(e))
            var_i += 1

        var_i = 0
        for fmcObject in utl.j_var['InterfaceConfig']:
            if const.NIC_CONFIGURE == "STATIC":
                # Check if configured when Static
                check_if_configured = fmc.get_nic_status(deviceId, name[var_i], nicId[var_i], ifname[var_i], zoneId[var_i], ip[var_i])
            elif const.NIC_CONFIGURE == "DHCP":
                # Check if configured when DHCP
                check_if_configured = fmc.get_nic_status(deviceId, name[var_i], nicId[var_i], ifname[var_i], zoneId[var_i])
                
            if check_if_configured == 'UN-CONFIGURED':
                return 'FAIL'
            else:
                logger.info(" %s is configured" % ifname[var_i])
            var_i += 1

        return 'SUCCESS'

    def ftdv_dereg_polling(self, fmc, minutes):
        """
        Purpose:    To poll device de-registration from FMC
        Parameters: FirepowerManagementCenter class object, Minutes
        Returns:    SUCCESS, FAILED
        Raises:
        """
        # Polling registration completion for specified 'minutes'
        if minutes <= 1:
            minutes = 2
        for i in range(1, 2*minutes):
            if i != ((2*minutes)-1):
                status_in_fmc = fmc.check_reg_status_from_fmc(self.vm_name)
                if status_in_fmc == 'FAILED':
                    return "SUCCESS"
                else:
                    logging.debug("De-registration polling, Sleeping for 30 seconds")
                    time.sleep(1*30)
            else:
                return "FAILED"
        return "FAILED"

    # Polling for policy deployment completion of FTDv
    def ftdv_deploy_polling(self, fmc, minutes):
        """
        Purpose:    To Poll for policy deployment completion of NGFW
        Parameters: FirepowerManagementCenter class object, Minutes
        Returns:    SUCCESS, FAILED
        Raises:
        """
        if minutes <= 1:
            minutes = 2
        for i in range(1, 4*minutes):
            if i != ((4*minutes)-1):
                status = fmc.check_deploy_status(self.vm_name)
                if status != "DEPLOYED":
                    logging.debug(str(i) + " Sleeping for 15 seconds")
                    time.sleep(1*15)
                else:
                    return "SUCCESS"
            else:
                return "FAILED"
        return "FAILED"

    def remove_from_fmc(self, fmc):
        """
        Purpose:    To de-register device from FMC
        Parameters: FirepowerManagementCenter class object
        Returns:    SUCCESS, FAILED
        Raises:
        """
        try:
            r = fmc.deregister_device(self.vm_name)
            logger.info("Instance de-registration from FMC response: " + str(r.json()))
        except Exception as e:
            logger.info("Instance de-registration received an error")
            logger.debug(str(e))
        pass
        r = self.ftdv_dereg_polling(fmc, 5)
        if r == "FAILED":
            return "FAILED"
        else:
            return "SUCCESS"

    def remove_from_asg(self, decrement_cap=False):
        """
        Purpose:    To remove device from Autoscale Group
        Parameters: ShouldCapacityDecrement parameter
        Returns:    SUCCESS, FAILED
        Raises:
        """
        asg = ASG()
        r = asg.remove_instance_asg(self.instance_id, decrement_cap)
        if r is None:
            logger.info("Unable to terminate the instance")
            return "FAILED"
        logger.info("Instance termination has been initiated: " + self.instance_id)
        return "SUCCESS"


class ParamikoSSH:
    """
        This Python class supposed to handle interactive SSH session
    """
    def __init__(self, server, port=22, username='admin', password=None):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.port = port
        self.server = server
        self.username = username
        self.password = password
        self.timeout = 30
        self.SUCCESS = 'SUCCESS'
        self.FAIL = 'FAILURE'
        self.AUTH_EXCEPTION = 'Authentication Exception Occurred'
        self.BAD_HOST_KEY_EXCEPTION = 'Bad Key Exception occurred'
        self.SSH_EXCEPTION = 'SSH Exception Occurred'

    def close(self):
        self.ssh.close()

    def verify_server_ip(self):
        try:
            socket.inet_aton(self.server)
            return self.SUCCESS
        except socket.error as e:
            logger.error("Exception occurred: {}".format(repr(e)))
            return self.FAIL
        except Exception as e:
            logger.error("Exception occurred: {}".format(repr(e)))
            return self.FAIL

    def connect(self, username, password):
        """
        Purpose:    Opens a connection to server
        Returns:    Success or failure, if failure then returns specific error
                    self.SUCCESS = 'SUCCESS'
                    self.FAIL = 'FAILURE'
                    self.AUTH_EXCEPTION = 'Authentication Exception Occurred'
                    self.BAD_HOST_KEY_EXCEPTION = 'Bad Key Exception occurred'
                    self.SSH_EXCEPTION = 'SSH Exception Occurred'
        """
        if self.verify_server_ip() == 'FAILURE':
            return self.FAIL
        try:
            self.ssh.connect(self.server, self.port, username, password, timeout=10)
            return self.SUCCESS
        except paramiko.AuthenticationException as exc:
            logger.error("Exception occurred: {}".format(repr(exc)))
            return self.AUTH_EXCEPTION
        except paramiko.BadHostKeyException as exc:
            logger.debug("Exception(un-known) occurred: {}".format(repr(exc)))
            return self.BAD_HOST_KEY_EXCEPTION
        except paramiko.SSHException as exc:
            logger.debug("Exception(un-known) occurred: {}".format(repr(exc)))
            return self.SSH_EXCEPTION
        except BaseException as exc:
            logger.debug("Exception(un-known) occurred: {}".format(repr(exc)))
            return self.FAIL

    def execute_cmd(self, command):
        """
        Purpose:    Performs an interactive shell action
        Parameters: Command
        Returns:    action status, output & error
        """
        if self.connect(self.username, self.password) != self.SUCCESS:
            raise ValueError("Unable to connect to server")
        try:
            ssh_stdin, ssh_stdout, ssh_stderr = self.ssh.exec_command(command, timeout=30)
        except paramiko.SSHException as exc:
            logger.error("Exception occurred: {}".format(repr(exc)))
            self.ssh.close()
            return self.FAIL, None, None
        else:
            output = ssh_stdout.readlines()
            error = ssh_stderr.readlines()
            logger.debug('SSH command output: ' + str(output))
            self.ssh.close()
            return self.SUCCESS, str(output), str(error)

    def invoke_interactive_shell(self):
        """
        Purpose:    Performs an interactive shell action
        Parameters:
        Returns:    a new Channel connected to the remote shell
        """
        try:
            shell = self.ssh.invoke_shell()
        except paramiko.SSHException as exc:
            logger.error("Exception occurred: {}".format(repr(exc)))
            self.ssh.close()
            return self.FAIL, None
        else:
            return self.SUCCESS, shell

    def handle_interactive_session(self, command_set, username, password):
        """
        Purpose:    Performs an interactive shell action
        Parameters:
            command_set: a dict of set of commands expressed in command & expect values
            Example:
                {
                  "cmd1": [
                    {
                      "command": "configure password",
                      "expect": "Enter current password:"
                    },
                    {
                      "command": "Cisco123789!",
                      "expect": "Enter new password:"
                    },
                    {
                      "command": "Cisco@123123",
                      "expect": "Confirm new password:"
                    },
                    {
                      "command": "Cisco@123123",
                      "expect": "Password Update successful"
                    }
                  ]
                }
        Returns:
        Raises:
            ValueError based on the error
        """
        # try:
        if self.connect(username, password) != self.SUCCESS:
            raise ValueError("Unable to connect to server")
        status, shell = self.invoke_interactive_shell()
        if status != self.SUCCESS:
            raise ValueError("Unable to invoke shell")
        if self.send_cmd_and_wait_for_execution(shell, '\n') is not None:
            for key in command_set:
                set = command_set[key]
                for i in range(0, len(set)):
                    command = set[i]['command'] + '\n'
                    expect = set[i]['expect']
                    if self.send_cmd_and_wait_for_execution(shell, command, expect) is not None:
                        pass
                    else:
                        raise ValueError("Unable to execute command: " + command)
        return

    def send_cmd_and_wait_for_execution(self, shell, command, wait_string='>'):
        """
        Purpose:    Sends command and waits for string to be received
        Parameters: command, wait_string
        Returns:    rcv_buffer or None
        Raises:
        """
        shell.settimeout(self.timeout)
        rcv_buffer = ''
        try:
            shell.send(command)
            while wait_string not in rcv_buffer:
                rcv_buffer = str(shell.recv(10000))
            return rcv_buffer
        except Exception as e:
            logger.error("Error occurred: {}".format(repr(e)))
            return None
