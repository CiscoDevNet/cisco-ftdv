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
--------------------------------------------------------------------------------

Name:       ngfw.py
Purpose:    This is contains ngfw class methods, SSH Paramiko class methods
"""

import re
import time
import logging
import paramiko
import socket
import json

import utility as utl
from cisco_oci import OCIInstance

logging.basicConfig(force=True, level="INFO")
logging.getLogger("paramiko").setLevel(logging.WARNING)
logger = logging.getLogger()

# FTDv related class
class NgfwInstance (OCIInstance):
    """
        NgfwInstance is a child class of OCIInstance, giving properties of NGFWv VM
    """
    def __init__(self, compartmentId, instanceId):
        super().__init__(compartmentId, instanceId)

        self.COMMAND_RAN = 'COMMAND_RAN'
        self.SUCCESS = 'SUCCESS'
        self.FAIL = 'FAILURE'

        self.public_ip = ''
        self.private_ip = ''
        self.port = 22

        self.username = ''
        self.password = ''
        self.defaultPassword = ''

        self.fmc_ip = ''
        self.reg_id = ''
        self.nat_id = ''

        self.USE_PUBLIC_IP_FOR_SSH = ''

    def connect_ngfw(self):
        """
        Purpose:    This provides object of ParamikoSSH class
        Parameters:
        Returns:    Class object
        Raises:
        """
        try: 
            if self.USE_PUBLIC_IP_FOR_SSH and self.public_ip != '':
                # To SSH FTDv Public IP
                ip_to_connect = self.public_ip
            else:
                if self.private_ip != '':
                    # To SSH FTDv Private IP
                    ip_to_connect = self.private_ip
                else:
                    logger.error("NGFW:connect_ngfw: None of Public or Private IP available to SSH the FTDv instance")
                    return None    
            connect = ParamikoSSH(ip_to_connect, self.port, self.username, self.password)
            logger.debug(connect)
            return connect
        except Exception as e: 
            raise Exception("NGFW: connect_ngfw  "+repr(e))
        
   
    # Run an independent command on FTDv
    def run_ftdv_command(self, command):
        """
        Purpose:    To run a single command
        Parameters:
        Returns:    'FAILURE', 'COMMAND_RAN'
        Raises:
        """
        try: 
            output, error = '', ''
            cnt_ngfw = self.connect_ngfw()
            try:
                status, output, error = cnt_ngfw.execute_cmd(command)
            except Exception as e:
                logger.error("NGFW:run_ftdv_command:Error occurred: {}".format(repr(e)))
                return self.FAIL, output, error
            if status == self.SUCCESS:
                return self.COMMAND_RAN, output, error
            else:
                logger.error("NGFW:run_ftdv_command: Unable to run command output: %s error: %s" % (output, error))
                return self.FAIL, output, error
        except Exception as e: 
            raise Exception("NGFW:run_ftdv_command:  "+repr(e))
        

    # Checks FTDv if SSH possible AND can execute 'show managers' command
    def check_ftdv_ssh_status(self):
        """
        Purpose:    To check NGFW SSH is accessible
        Parameters:
        Returns:    SUCCESS, FAILURE
        Raises:
        """
        try: 
            cnt_ngfw = self.connect_ngfw()
            status = cnt_ngfw.connect(self.username, self.password)
            if status == 'SUCCESS':
                cnt_ngfw.close()
                return 'SUCCESS'
            elif status == 'Authentication Exception Occurred':
                status = cnt_ngfw.connect(self.username, self.defaultPassword)
                if status == 'SUCCESS':
                    cnt_ngfw.close()  # As below function triggers interactive shell
                    if self.change_ngfw_password(cnt_ngfw, self.defaultPassword, self.password) == 'SUCCESS':
                        logger.info("NGFW:check_ftdv_ssh_status: Default Password has been updated successfully")
                        return 'SUCCESS'
                    else:
                        logger.info("NGFW:check_ftdv_ssh_status: Failed to update the password")
                else:
                    logger.error("NGFW:check_ftdv_ssh_status: Unable to authenticate to NGFW instance, please check password!")
                    return 'FAILURE'
            
            logger.error("NGFW:check_ftdv_ssh_status: Failed to get SSH access")
            return 'FAILURE'
        except Exception as e: 
            raise Exception("NGFW: check_ftdv_ssh_status  "+repr(e))
        

    # Checks registration by doing SSH to FTDv
    def check_ftdv_reg_status(self):
        """
        Purpose:    Check Registration status
        Parameters:
        Returns:    'FAILURE', 'PENDING', 'COMPLETED', 'NO_MANAGER'. 'TROUBLESHOOT'
        Raises:
        """
        try: 
            r, output, error = self.show_managers()
            logger.info("NGFW:check_ftdv_reg_status: status: %s output: %s error: %s" % (r, output, error))
    
            if len(re.findall('pending', output)) == 1:
                logger.debug("NGFW:check_ftdv_reg_status: Instance " + self.vm_name + ", is pending to register with FMC")
                return "PENDING"
            elif len(re.findall('Completed', output)) == 1:
                logger.debug("NGFW:check_ftdv_reg_status: Instance " + self.vm_name + ", already registered with FMC")
                return "COMPLETED"
            elif len(re.findall('No managers', output)) == 1:
                logger.debug("NGFW:check_ftdv_reg_status: Instance " + self.vm_name + ", SSH is up but not configured to register with FMC")
                return "NO_MANAGER"
            elif len(re.findall('local', output)) == 1:
                logger.debug("NGFW:check_ftdv_reg_status: Instance " + self.vm_name + ", SSH is up but configured locally")
                return "TROUBLESHOOT"
            else:
                return 'FAILURE'
        except Exception as e: 
            raise Exception("NGFW:check_ftdv_reg_status:  "+repr(e))
        

    # Polling connectivity to FTDv for specified 'minutes', ability to run 'show managers' command
    def poll_ftdv_ssh(self, minutes):
        """
        Purpose:    To poll NGFW for SSH accessibility
        Parameters: Minutes
        Returns:    SUCCESS, TIMEOUT
        Raises:
        """
        try: 
            logger.debug("NGFW:poll_ftdv_ssh: Checking for FTDv SSH access")
            for i in range(1, int(2 * minutes)+1):
                status = self.check_ftdv_ssh_status()
                if status != "SUCCESS":
                    logger.info("NGFW:poll_ftdv_ssh: RETRY: "+ str(i) + " Sleeping for 30 seconds")
                    time.sleep(1 * 30)
                else:
                    return "SUCCESS"
            
            logger.info("NGFW:poll_ftdv_ssh: SSH NOT ACCESSIBLE")
            return "TIMEOUT"
        except Exception as e: 
            raise Exception("NGFW: poll_ftdv_ssh  "+repr(e))
        

    def show_managers(self):
        """
        Purpose:    To run command 'show managers'
        Parameters:
        Returns:    'FAILURE', 'COMMAND_RAN', output and error
        Raises:
        """
        try: 
            cmd = 'show managers'
            r, output, error = self.run_ftdv_command(cmd)
            logger.debug(output)
            return r, output, error
        except Exception as e: 
            raise Exception("NGFW: show_managers  "+repr(e))
        

    # Function to configure manager
    def configure_manager(self):
        """
        Purpose:    To run command 'configure manager add'
        Parameters:
        Returns:    'FAILURE', 'COMMAND_RAN'
        Raises:
        """
        try: 
            cmd = 'configure manager add ' + self.fmc_ip + ' ' + self.reg_id + ' ' + self.nat_id
            r, output, error = self.run_ftdv_command(cmd)
            logger.info("NGFW:configure_manager: "+repr(output))
            return r
        except Exception as e: 
            raise Exception("NGFW: configure_manager  "+repr(e))
        

    # Function to run configure manager delete
    def configure_manager_delete(self):
        """
        Purpose:    To run 'configure manager delete'
        Parameters:
        Returns:    'FAILURE', 'COMMAND_RAN'
        Raises:
        """
        try: 
            cmd = 'configure manager delete'
            r, output, error = self.run_ftdv_command(cmd)
            logger.debug(output)
            return r
        except Exception as e: 
            raise Exception("NGFW: configure_manager_delete  "+repr(e))
        

    # function to set hostname
    def configure_hostname(self):
        """
        Purpose:    To configure hostname on NGFW
        Parameters:
        Returns:    'FAILURE', 'COMMAND_RAN'
        Raises:
        """
        try: 
            cmd = 'configure network hostname' + ' ' + self.vm_name
            r, output, error = self.run_ftdv_command(cmd)
            logger.debug("NGFW:configure_hostname: Instance hostname configuration: " + output)
            return r
        except Exception as e: 
            raise Exception("NGFW: configure_hostname  "+repr(e))
        

    # function to change password(admin) from prev_password to new_password
    def change_ngfw_password(self, cnt_ngfw, prev_password, new_password):
        """
        Purpose:    To change password from default to user provided
        Parameters: ParamikoSSH class object, Default password, New Password
        Returns:    SUCCESS, None
        Raises:
        """
        try: 
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
                logger.error("NGFW:change_ngfw_password: Error occurred: {}".format(repr(e)))
                return None
            else:
                return 'SUCCESS'
            finally:
                cnt_ngfw.close()
        except Exception as e: 
            raise Exception("NGFW: change_ngfw_password  "+repr(e))
        

# FTDv Managed by FMC type
class ManagedDevice(NgfwInstance):
    """
        ManagedDevice is child class of NgfwInstance, giving FMC managed device property to NGFWv instance
    """
    def __init__(self, compartment_id, instance_id, fmc):
        super().__init__(compartment_id, instance_id)
        # Will be available from json
        self.l_caps = ''
        self.performance_tier = ''
        self.traffic_routes = []
        self.interface_config = []
        self.in_nic = ''
        self.out_nic = ''
        self.in_nic_name = ''
        self.out_nic_name = ''

        # Will be instantiated during run-time
        self.fmc = fmc

        # will be take from environment variable
        self.USE_PUBLIC_IP_FOR_FMC_CONN = ''
        self.NIC_CONFIGURE = 'STATIC'

        #OCI Specific
        self.begin_time = 0

        # Will be fetched by a method
        self.device_id = ''
        self.mgmt_ip = ''
        self.in_nic_id = ''
        self.out_nic_id = ''
        self.in_nic_zone = ''
        self.out_nic_zone = ''
        self.in_nic_zone_id = ''
        self.out_nic_zone_id = ''
        
        # Only if STATIC
        self.in_nic_ip = ''
        self.in_nic_subnet_id = ''
        self.in_nic_netmask = ''
        self.out_nic_ip = ''
        self.out_nic_subnet_id = ''
        self.out_nic_netmask = ''
        self.in_nic_cidr = ''
        self.out_nic_cidr = ''

        # status of the device
        # [ PENDING, ON-GOING, COMPLETED, FAILED ]
        self.ready_sts = 'PENDING'
        self.reg_sts = 'PENDING'
        self.int_config_sts = 'PENDING'
        self.rt_config_sts = 'PENDING'
        self.config_sts = 'PENDING'
        self.deploy_sts = 'PENDING'

    def update_device_configuration(self):
        """
        Purpose:        To update ManagedDevice Cls variable
        Parameters:
        Returns:
        Raises:
        """
        # Update device Configuration
        if self.USE_PUBLIC_IP_FOR_FMC_CONN and self.public_ip != '':
            self.mgmt_ip = self.public_ip
        else:
            self.mgmt_ip = self.private_ip

        # Updating Private Ip and netmasks of Inside and Outside VNIC
        self.interface_info = self.get_instance_interface_info(self.in_nic_name, self.out_nic_name)
        self.in_nic_ip = self.interface_info[self.in_nic_name+"_ip"]
        self.in_nic_netmask = self.interface_info[self.in_nic_name+"_netmask"]
        self.out_nic_ip = self.interface_info[self.out_nic_name+"_ip"]
        self.out_nic_netmask = self.interface_info[self.out_nic_name+"_netmask"]
        self.in_nic_cidr = self.interface_info[self.in_nic_name+"_cidr"]
        self.out_nic_cidr = self.interface_info[self.out_nic_name+"_cidr"]

        if self.int_config_sts == 'COMPLETED' and self.rt_config_sts == 'COMPLETED':
            self.config_sts = 'COMPLETED'
        if self.int_config_sts == 'FAILED' and self.rt_config_sts == 'FAILED':
            self.config_sts = 'FAILED'
        if self.int_config_sts == 'ON-GOING' and self.rt_config_sts == 'ON-GOING':
            self.config_sts = 'ON-GOING'

        try:
            self.device_id = self.fmc.get_device_id_by_name(self.vm_name)
        except Exception as e:
            logger.exception(e)
        if self.device_id != '':
            self.reg_sts = 'COMPLETED'
            try:
                self.in_nic_id = self.fmc.get_nic_id_by_name(self.device_id, self.in_nic)
                self.out_nic_id = self.fmc.get_nic_id_by_name(self.device_id, self.out_nic)
                if self.in_nic_id is None:
                    logger.error("NGFW:update_device_configuration: unable to get Nic ID for " + self.in_nic)
                    self.in_nic_id = ''
                if self.out_nic_id is None:
                    logger.error("NGFW:update_device_configuration: unable to get Nic ID for " + self.out_nic)
                    self.out_nic_id = ''
                for interface in self.interface_config:
                    if interface['ifname'] == self.in_nic_name:
                        self.in_nic_zone = interface['securityZone']['name']
                        self.in_nic_zone_id = self.fmc.get_security_objectid_by_name(self.in_nic_zone)
                    if interface['ifname'] == self.out_nic_name:
                        self.out_nic_zone = interface['securityZone']['name']
                        self.out_nic_zone_id = self.fmc.get_security_objectid_by_name(self.out_nic_zone)
            except Exception as e:
                logger.exception(e)
        else:
            logger.debug("NGFW:update_device_configuration: No device_id found in FMC for instance: " + self.vm_name)

    def ftdv_reg_polling(self, minutes=2):
        """
        Purpose:    To poll both NGFW & FMCv for registration status
        Parameters: FirepowerManagementCenter class object, Minutes
        Returns:    SUCCESS, PARTIAL, FAILED
        Raises:
        """
        # Polling registration completion for specified 'minutes'
        try: 
            status_in_ftdv = ''
            status_in_fmc = ''
            for i in range(0, 2*minutes):
                if (int(time.time()-self.begin_time)) > 230:
                    self.reg_sts = 'FAILED'
                    return 'FAILED'
                status_in_ftdv = self.check_ftdv_reg_status()
                status_in_fmc = self.fmc.check_reg_status_from_fmc(self.vm_name)
                if status_in_ftdv == "COMPLETED" and status_in_fmc == 'SUCCESS':
                    self.reg_sts = 'COMPLETED'
                    return "SUCCESS"
                else:
                    logging.debug("NGFW:ftdv_reg_polling: Registration status in FTDv: " + status_in_ftdv + " in FMC: " + status_in_fmc)
                    logging.debug("NGFW:ftdv_reg_polling: Sleeping for 30 seconds")
                    time.sleep(1*30)
            if status_in_ftdv == "COMPLETED" or status_in_fmc == "SUCCESS":
                self.reg_sts = 'ON-GOING'
                return "PARTIAL"
            self.reg_sts = 'FAILED'
            return "FAILED"
        except Exception as e: 
            raise Exception("NGFW: ftdv_reg_polling  "+repr(e))
        

    def send_registration_request(self):
        """
        Purpose:    To send Device Registration request to FMC
        Parameters: FirepowerManagementCenter class object, Device Group
        Returns:    SUCCESS, FAIL
        Raises:
        """
        try: 
            reg_task_id = self.fmc.register_ftdv(self.vm_name, self.mgmt_ip, self.reg_id, self.nat_id, self.l_caps, self.performance_tier)
            if reg_task_id is not None:
                self.ftdv_reg_polling(2)
                if self.reg_sts == 'ONGOING':
                    self.ftdv_reg_polling(1)
                if self.reg_sts == "COMPLETED":
                    return 'SUCCESS'
            return 'FAIL'
        
        except Exception as e:
            raise Exception("NGFW: send_registration_request  "+repr(e))
        

    def check_and_configure_routes(self):
        """
        Purpose:    Checks for Static Route if present, if not then creates the Static Route.
        Parameters: fmc object from caller function
        Returns:    Success or Fail
        Raises:
        """
        try:
            self.update_gw_stat_route()
            for static_route in self.traffic_routes:
                check_s_route_ = self.fmc.check_static_route(self.device_id, static_route['interface'],
                                                             static_route['network'], static_route['gateway'])
                logger.debug("NGFW:check_and_configure_routes: Route status: " + check_s_route_)
                if check_s_route_ == 'UN-CONFIGURED':
                    # Configure Static Route
                    logger.debug("NGFW:check_and_configure_routes: Configuring Route: " + json.dumps(static_route, separators=(',', ':')))
                    if self.fmc.get_host_objectid_by_name(static_route['network']) != '':
                        rt_type = 'Host'
                        net_id = self.fmc.get_host_objectid_by_name(static_route['network'])
                    elif self.fmc.get_network_objectid_by_name(static_route['network']) != '':
                        rt_type = 'Network'
                        net_id = self.fmc.get_network_objectid_by_name(static_route['network'])
                    else:
                        logger.error("NGFW:check_and_configure_routes: trafficRoutes.network value in Configuration json is not correct")
                        return 'FAIL'
                    r = self.fmc.conf_static_rt(self.device_id, static_route['interface'],
                                                rt_type, static_route['network'], net_id,
                                                static_route['gateway'], static_route['metric'])
                    if r.status_code != 200 and r.status_code != 201:
                        logger.error("NGFW:check_and_configure_routes: Route configuration failed: " + str(r.status_code))
                        logger.error("NGFW:check_and_configure_routes: response: " + str(r.json()))
                        return 'FAIL'
                    else:
                        logger.debug("NGFW:check_and_configure_routes: Static Host route configuration REST response {}".format(r.status_code))
        except KeyError as e:
            logger.exception(e)
            logger.error("NGFW:check_and_configure_routes: Looks like Configuration.json file missing")
            return 'FAIL'
        except Exception as e:
            logger.critical(e)
            return 'FAIL'
        return 'SUCCESS'

    def check_interface_config(self, interface):
        """
        Purpose:        To check if an interface configuration exists
        Parameters:     interface
                        {
                          "managementOnly": "false",
                          "MTU": "1500",
                          "securityZone": {
                            "name": "Outside-sz"
                          },
                          "mode": "NONE",
                          "ifname": "outside",
                          "name": "GigabitEthernet0/1"
                        }
        Returns:        SUCCESS, FAIL
        Raises:
        """
        try: 
            check_if_configured = 'UN-CONFIGURED'
            if self.NIC_CONFIGURE == "STATIC":
                if interface['name'] == self.in_nic:
                    # Check if configured when Static
                    check_if_configured = self.fmc.get_nic_status(self.device_id, self.in_nic, self.in_nic_id,
                                                                  self.in_nic_name, self.in_nic_zone_id,
                                                                  self.in_nic_ip)
                elif interface['name'] == self.out_nic:
                    # Check if configured when Static
                    check_if_configured = self.fmc.get_nic_status(self.device_id, self.out_nic, self.out_nic_id,
                                                                  self.out_nic_name, self.out_nic_zone_id,
                                                                  self.out_nic_ip)
    
                if check_if_configured == 'CONFIGURED':
                    logger.debug(" %s is configured" % interface['ifname'])
                    pass
                else:
                    logger.info(" %s is not configured" % interface['ifname'])
                    return 'FAIL'
    
            elif self.NIC_CONFIGURE == "DHCP":
                # Check if configured when DHCP
                if interface['name'] == self.in_nic:
                    check_if_configured = self.fmc.get_nic_status(self.device_id, self.in_nic, self.in_nic_id,
                                                                  self.in_nic_name, self.in_nic_zone_id)
                elif interface['name'] == self.out_nic:
                    check_if_configured = self.fmc.get_nic_status(self.device_id, self.out_nic, self.out_nic_id,
                                                                  self.out_nic_name, self.out_nic_zone_id)
                if check_if_configured == 'CONFIGURED':
                    logger.debug(" %s is configured" % interface['ifname'])
                    pass
                else:
                    logger.debug(" %s is not configured" % interface['ifname'])
                    return 'FAIL'
    
            return 'SUCCESS'
        except Exception as e: 
            raise Exception("NGFW: check_interface_config"+repr(e))
        

    def check_and_configure_interface(self):
        """
        Purpose:    Checks interface configuration & create if necessary
        Parameters: fmc object from caller function
        Returns:    Success or Fail
        Raises:
        """
        try: 
            for interface in self.interface_config:
                if self.check_interface_config(interface) == 'FAIL':
                    try:
                        logger.debug("NGFW:: Configuring Nic %s ..." % (interface['name']))
                        r = None
                        if self.NIC_CONFIGURE == "STATIC":
                            if interface['name'] == self.in_nic:
                                r = self.fmc.configure_nic_static(self.device_id, self.in_nic_id, self.in_nic,
                                                                  self.in_nic_name, interface['managementOnly'],
                                                                  interface['mode'], self.in_nic_zone_id,
                                                                  interface['MTU'], self.in_nic_ip, self.in_nic_netmask)
                            elif interface['name'] == self.out_nic:
                                r = self.fmc.configure_nic_static(self.device_id, self.out_nic_id, self.out_nic,
                                                                  self.out_nic_name, interface['managementOnly'],
                                                                  interface['mode'], self.out_nic_zone_id,
                                                                  interface['MTU'], self.out_nic_ip, self.out_nic_netmask)
                        elif self.NIC_CONFIGURE == "DHCP":
                            if interface['name'] == self.in_nic:
                                r = self.fmc.configure_nic_dhcp(self.device_id, self.in_nic_id, self.in_nic,
                                                                self.in_nic_name, interface['managementOnly'],
                                                                interface['mode'], self.in_nic_zone_id, interface['MTU'])
                            elif interface['name'] == self.out_nic:
                                r = self.fmc.configure_nic_dhcp(self.device_id, self.out_nic_id, self.out_nic,
                                                                self.out_nic_name, interface['managementOnly'],
                                                                interface['mode'], self.out_nic_zone_id, interface['MTU'])
                        logger.info("NGFW:check_and_configure_interface: Response: "+repr(r))
                    except Exception as e:
                        logger.exception(e)
                        logger.error("NGFW:: Configuring Nic failed!")
    
            status = 'SUCCESS'
            for interface in self.interface_config:
                status = self.check_interface_config(interface)
                if status == 'FAIL':
                    return status
            return status
        except Exception as e: 
            raise Exception("NGFW: check_and_configure_interface  "+repr(e))
        

    def ftdv_dereg_polling(self, minutes):
        """
        Purpose:    To poll device de-registration from FMC
        Parameters: FirepowerManagementCenter class object, Minutes
        Returns:    SUCCESS, FAILED
        Raises:
        """
        # Polling registration completion for specified 'minutes'
        try: 
            for i in range(0, 2*minutes):
                status_in_fmc = self.fmc.check_reg_status_from_fmc(self.vm_name)
                if status_in_fmc == 'FAILED':
                    return "SUCCESS"
                else:
                    logging.debug("NGFW:ftdv_dereg_polling: De-registration polling, Sleeping for 30 seconds")
                    time.sleep(1*30)
            return "FAILED"
        except Exception as e: 
            raise Exception("NGFW: ftdv_dereg_polling  "+repr(e))
        

    # Polling for policy deployment completion of FTDv
    def ftdv_deploy_polling(self, minutes):
        """
        Purpose:    To Poll for policy deployment completion of NGFW
        Parameters: FirepowerManagementCenter class object, Minutes
        Returns:    SUCCESS, FAILED
        Raises:
        """
        try: 
            for i in range(0, 2*minutes):
                if (int(time.time()-self.begin_time))>230:
                    return "FAILED"
                status = self.fmc.check_deploy_status(self.vm_name)
                if status != "DEPLOYED":
                    logging.debug("NGFW:ftdv_deploy_polling: "+ str(i) + " Sleeping for 30 seconds")
                    time.sleep(30)
                else:
                    return "SUCCESS"    
            return "FAILED"
        except Exception as e: 
            raise Exception("NGFW: ftdv_deploy_polling  "+repr(e))
        

    def remove_from_fmc(self):
        """
        Purpose:    To de-register device from FMC
        Parameters: FirepowerManagementCenter class object
        Returns:    SUCCESS, FAILED
        Raises:
        """
        try:
            r = self.fmc.deregister_device(self.vm_name)
            logger.debug("Instance de-registration from FMC response: " + str(r.json()))
        except Exception as e:
            logger.debug("Instance de-registration received an error")
            logger.debug(str(e))
        pass
        r = self.ftdv_dereg_polling(2)
        if r == "FAILED":
            return "FAILED"
        else:
            return "SUCCESS"

    def update_gw_stat_route(self):
        """
        Purpose:    To update Gateway in static route
        Parameters:
        Returns:
        Raises:
        """
        try: 
            for static_route in self.traffic_routes:
                if static_route['gateway'] == '':
                    if static_route['interface'] == self.in_nic_name:
                        static_route['gateway'] = utl.get_gateway_from_cidr(self.in_nic_cidr)
                    elif static_route['interface'] == self.out_nic_name:
                        static_route['gateway'] = utl.get_gateway_from_cidr(self.out_nic_cidr)
                logger.debug(json.dumps(static_route, separators=(',', ':')))
            return
        except Exception as e: 
            raise Exception("NGFW: update_gw_stat_route  "+repr(e))
        

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
            logger.exception(e)
            logger.error("NGFW:verify_server_ip: returning : " + self.FAIL)
            return self.FAIL
        except Exception as e:
            logger.exception(e)
            logger.error("NGFW:verify_server_ip: returning : " + self.FAIL)
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
            logger.warning("NGFW:connect: Exception occurred: {}".format(repr(exc)))
            return self.AUTH_EXCEPTION
        except paramiko.BadHostKeyException as exc:
            logger.warning("NGFW:connect: Exception occurred: {}".format(repr(exc)))
            return self.BAD_HOST_KEY_EXCEPTION
        except paramiko.SSHException as exc:
            logger.warning("NGFW:connect: Exception occurred: {}".format(repr(exc)))
            return self.SSH_EXCEPTION
        except BaseException as exc:
            logger.warning("NGFW:connect: Exception occurred: {}".format(repr(exc)))
            return self.FAIL

    def execute_cmd(self, command):
        """
        Purpose:    Performs an interactive shell action
        Parameters: Command
        Returns:    action status, output & error
        """
        if self.connect(self.username, self.password) != self.SUCCESS:
            raise ValueError("NGFW:execute_cmd: Unable to connect to server")
        try:
            ssh_stdin, ssh_stdout, ssh_stderr = self.ssh.exec_command(command, timeout=30)
        except paramiko.SSHException as exc:
            logger.error("NGFW:execute_cmd: Exception occurred: {}".format(repr(exc)))
            self.ssh.close()
            return self.FAIL, None, None
        else:
            output = ssh_stdout.readlines()
            error = ssh_stderr.readlines()
            logger.debug('NGFW:execute_cmd: SSH command output: ' + str(output))
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
            logger.error("NGFW:invoke_interactive_shell: Exception occurred: {}".format(repr(exc)))
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
            raise ValueError("NGFW:handle_interactive_session: Unable to connect to server")
        status, shell = self.invoke_interactive_shell()
        if status != self.SUCCESS:
            raise ValueError("NGFW:handle_interactive_session: Unable to invoke shell")
        if self.send_cmd_and_wait_for_execution(shell, '\n') is not None:
            for key in command_set:
                set_ = command_set[key]
                for i in range(0, len(set_)):
                    command = set_[i]['command'] + '\n'
                    expect = set_[i]['expect']
                    if self.send_cmd_and_wait_for_execution(shell, command, expect) is not None:
                        pass
                    else:
                        raise ValueError("NGFW:handle_interactive_session: Unable to execute command: " + command)
        else:
            raise ValueError("NGFW:handle_interactive_session: Unable to execute command: " + repr("\n"))

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
            logger.error("NGFW:send_cmd_and_wait_for_execution: Error occurred: {}".format(repr(e)))
            return None
