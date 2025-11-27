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

Name:       FMC_Operations.py
Purpose:    This python file has fmc methods to configure the ftdv
"""

import time
from urllib3 import response
import requests
import logging as log
import json
import os

from azure.mgmt.compute import ComputeManagementClient
from azure.identity import ManagedIdentityCredential

# Custom classe for FMC communication
from Utils import FMC,FtdSshClient

class FTDAutoScaleManager:
    def __init__(self):
        self.fmc_ip = "https://" + os.environ.get("FMC_IP")
        self.domain_uuid = os.environ.get("FMC_DOMAIN_UUID")
        self.policy_name = os.environ.get("POLICY_NAME")
        self.reg_key = os.environ.get("REG_KEY")
        self.nat_id = os.environ.get("NAT_ID")
        self.dev_group_name = os.environ.get("DEVICE_GROUP_NAME")
        self.license = os.environ.get("LICENSE_CAPABILITY")
        self.fmc_username = os.environ.get("FMC_USERNAME")
        self.fmc_password = os.environ.get("FMC_PASSWORD")
        self.fmc = FMC(self.fmc_username, self.fmc_password, self.policy_name)

    def DeviceRegister(self, ftdv_name, ftdv_public_ip):
        # FMC URLs for REST API's
        fmc_registration_url = "httsp://" + self.fmc_ip + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/devices/devicerecords"
        log.warning("DeviceRegister:::: Received Request to Register FTD with FMC")
        log.info("DeviceRegister:::: FTD Public IP : {}".format(ftdv_public_ip))
        log.info("DeviceRegister:::: FTD Instance Name : {}".format(ftdv_name))
        log.info("DeviceRegister:::: FMC IP : {}".format(self.fmc_ip))
        log.info("DeviceRegister:::: Policy Name : {}".format(self.policy_name))

        # ---------------------------Get Policy ID by name------------------------------------------
        log.info("DeviceRegister:::: Getting Access policy ID")
        policy_id = self.fmc.getAccessPolicyIdByName(self.policy_name)

        if policy_id == "ERROR" or len(policy_id) == 0:
            log.error("DeviceRegister:::: Unable to get Policy ID from Policy Name {}".format(self.policy_name))
            return "Unable to get Policy ID" # need to change
        
        log.info("DeviceRegister:::: Found Policy {} ID : {} ".format(self.policy_name, policy_id))

        # ---------------------------Register FTD------------------------------------------
        # Orchestrator will retry if failed
        log.info("DeviceRegister:::: Registering FTD with FMC")
        log.warning("Grouping this FTD under Device Group :{} ".format(self.dev_group_name))
        dev_group_id = self.fmc.getDevGroupIdByName(self.dev_group_name)
        if dev_group_id == "ERROR":
            log.error("Unable to get Device Group ID")
            return "Unable to get Device Group ID"  # need to change
        log.info("Device group name : {}, ID: {}".format(self.dev_group_name, dev_group_id))
        log.warning("License detailed entered by user : {}", license)
        license = license.replace(" ", "")
        license = license.replace(",", "\",\"")
        license = "\"" + license + "\""
        license = license.split(",")
        log.warning("License after formatting: {}".format(license))

        post_data = {
            "name": ftdv_name, 
            "hostName": ftdv_public_ip,
            "regKey": self.reg_key ,
            "natID": self.nat_id ,
            "type": "Device",
            "license_caps": license,
            "accessPolicy": {
                "id": policy_id ,
                "type": "AccessPolicy"
            },
            "deviceGroup": {
                "id": dev_group_id ,
                "type": "DeviceGroup"
            }
        }

        log.info("DeviceRegister:::: Registration Content : {}".format(post_data))
        r = self.fmc.rest_post(fmc_registration_url, post_data)

        if not (200 <= r.status_code <= 300):
            log.error("DeviceRegister:::: Failed Device Registration")
            return "Device Registration Failed" # need to change
        ret_val = { "ftdDevName" : ftdv_name }
        return ret_val
    
    def DeviceDeRegister(self, ftdv_name, ftdv_public_ip):
        fmc_registration_url = "httsp://" + self.fmc_ip + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/devices/devicerecords"

        log.warning("DeviceDeRegister:::: Received Request to De-Register FTD from FMC")
        log.info("DeviceDeRegister:::: FTD Public IP : {}".format(ftdv_public_ip))
        log.info("DeviceDeRegister:::: FMC IP : {}".format(ftdv_name))

        # ---------------------------Get Device ID by name------------------------------------------
        log.info("DeviceDeRegister:::: Getting FTD Device ID by name")
        dev_id = self.fmc.getDevIdByName(ftdv_name, "FTD")
        if dev_id == "ERROR":
            log.error("DeviceDeRegister:::: Failed to get Device ID")
            return "Unable to get Device Group ID"  # need to change
        
        # ---------------------------De-Register FTD------------------------------------------
        # Orchestrator will retry if this fails
        log.info("DeviceDeRegister:::: De-Registering FTD")
        fmc_deregister_url = fmc_registration_url + "/" + dev_id
        r = self.fmc.rest_delete(fmc_deregister_url)
        if not (200 <= r.status_code <= 300):
            log.error("DeviceDeRegister:::: DeRegistration failed")
            return "DeRegistration failed"  # need to change
        
        log.info("DeviceDeRegister:::: De-Registeration Status : {}".format(r.content))
        return "SUCCESS" # need to change

    def ConfigureFtdInterfaces(self, ftdv_name):
        fmc_inside_zone = os.environ.get("INSIDE_ZONE")
        fmc_inside_nic_name = os.environ.get("INSIDE_NIC_NAME")
        fmc_inside_nic = os.environ.get("INSIDE_NIC_INTERFACE")
        fmc_outside_zone = os.environ.get("OUTSIDE_ZONE")
        fmc_outside_nic_name = os.environ.get("OUTSIDE_NIC_NAME")
        fmc_outside_nic = os.environ.get("OUTSIDE_NIC_INTERFACE")
        fmc_registration_url = "httsp://" + self.fmc_ip + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/devices/devicerecords"

        log.warning("ConfigureFtdInterfaces:::: Started Device Configuration for {}", ftdv_name)

        # ------------Get resource Ids------------------------------------------
        log.info("ConfigureFtdInterfaces:::: Getting FTD device ID")
        dev_id = self.fmc.getDevIdByName(ftdv_name, "FTD")
        if (dev_id == "ERROR"):
            log.error("ConfigureFtdInterfaces:::: Failed to get Device ID")
            return "Unable to get Device Group ID"  # need to change

        log.info("ConfigureFtdInterfaces:::: Getting Inside NIC ID")
        inside_nic_id = self.fmc.getDevIdByName(fmc_inside_nic, "NIC", dev_id)
        if inside_nic_id == "ERROR":
            log.error("ConfigureFtdInterfaces:::: Failed to get Inside NIC Id")
            return "Failed to get Inside NIC Id" # need to change

        log.info("ConfigureFtdInterfaces:::: Inside NIC ID : {}".format(inside_nic_id))


        log.info("ConfigureFtdInterfaces:::: Getting Outside NIC ID")
        outside_nic_id = self.fmc.getDevIdByName(outside_nic_id, "NIC", dev_id)
        if outside_nic_id == "ERROR":
            log.error("ConfigureFtdInterfaces:::: Failed to get Outside NIC Id")
            return "Failed to get Outside NIC Id" # need to change

        log.info("ConfigureFtdInterfaces:::: Outside NIC ID : {}".format(outside_nic_id))

        # ------------Get zone Id by name------------------------------------------
        inside_zone_id = self.fmc.getDevIdByName(fmc_inside_zone, "ZONE")
        if inside_zone_id == "ERROR":
            log.error("ConfigureFtdInterfaces:::: Failed to get inside zone Id")
            return "Failed to get Inside Zone Id" # need to change

        log.info("ConfigureFtdInterfaces:::: Inside zone ID : {}".format(inside_zone_id))

        outside_zone_id = self.fmc.getDevIdByName(fmc_outside_zone, "ZONE")
        if outside_zone_id == "ERROR":
            log.error("ConfigureFtdInterfaces:::: Failed to get outside zone Id")
            return "Failed to get Outside Zone Id" # need to change

        log.info("ConfigureFtdInterfaces:::: OUTside zone ID : {}".format(outside_zone_id))

        # -------------------Configure inside interface
        url = fmc_registration_url + dev_id + "/physicalinterfaces/" + inside_nic_id
        post_data = { 
            "type": "PhysicalInterface",  
            "managementOnly": False, 
            "MTU": 1500, 
            "ipv4": { 
                "dhcp": { 
                    "enableDefaultRouteDHCP": False,  
                    "dhcpRouteMetric": 1  
                }  
            },  
            "securityZone": {  
                "id": inside_zone_id,  
                "type": "SecurityZone"  
            }, 
            "mode": None,  
            "ifname":fmc_inside_nic_name ,  
            "enabled": True,  
            "name": fmc_inside_nic,  
            "id": inside_nic_id 
        }

        r = self.fmc.rest_post(url, post_data)
        
        if not (200 <= r.status_code <= 300):
            log.error("ConfigureFtdInterfaces:::: Failed to configure inside interface")
            log.info("ConfigureFtdInterfaces::::  Configure inside interface status - {}".format(r.content))
            return "Failed to configure inside interface" # need to change
        
        log.info("ConfigureFtdInterfaces:::: Successfully configured Inside Interface")

        # -------------------Configure outside interface
        url = fmc_registration_url + dev_id + "/physicalinterfaces/" + outside_nic_id
        post_data = { 
            "type": "PhysicalInterface",  
            "managementOnly": False, 
            "MTU": 1500, 
            "ipv4": { 
                "dhcp": { 
                    "enableDefaultRouteDHCP": False,  
                    "dhcpRouteMetric": 1  
                }  
            },  
            "securityZone": {  
                "id": outside_zone_id,  
                "type": "SecurityZone"  
            }, 
            "mode": None,  
            "ifname":fmc_outside_nic_name ,  
            "enabled": True,  
            "name": fmc_outside_nic,  
            "id": outside_nic_id 
        }

        r = self.fmc.rest_post(fmc_registration_url, post_data)
        
        if not (200 <= r.status_code <= 300):
            log.error("ConfigureFtdInterfaces:::: Failed to configure outside interface")
            log.info("ConfigureFtdInterfaces::::  Configure outside interface status - {}".format(r.content))
            return "Failed to configure outside interface" # need to change
        
        log.info("ConfigureFtdInterfaces:::: Successfully configured Outside Interface")

        log.info("ConfigureFtdInterfaces:::: Successfully configured Outside Interface")
        return "SUCCESS" # need to change

    def CreateStaticRoutes(self, ftdv_name, ftdv_private_ip):
        fmc_inside_nic_name = os.environ.get("INSIDE_NIC_NAME")
        fmc_outside_nic_name = os.environ.get("OUTSIDE_NIC_NAME")

        outside_gw = os.environ.get("OUTSIDE_GW_OBJ_NAME")
        inside_gw = os.environ.get("INSIDE_GW_OBJ_NAME")
        cidr = os.environ.get("NETWORK_CIDR")
        out_gw = os.environ.get("OUT_NET_GW")
        in_gw = os.environ.get("IN_NET_GW")
        azure_utility_ip = os.environ.get("AZURE_UTILITY_IP")
        azure_utility_ip_name = os.environ.get("AZURE_UTILITY_IP_NAME")
        any_ipv4_name = os.environ.get("ANY_IPV4_NAME")
        network_name = os.environ.get("NETWORK_NAME")

        log.warning("CreateStaticRoutes:::: Creating static routes {} : {}".format(ftdv_name, ftdv_private_ip))

        # ----------------Create Host Object--------
        log.info("CreateStaticRoutes:::: Creating objects")

        # Orchestrator will retry if failed
        r = self.fmc.fmcHostObjectCreate(outside_gw, out_gw, "Host Object for outside gateway")
        r = self.fmc.fmcHostObjectCreate(inside_gw, in_gw, "Host Object for inside gateway")
        r = self.fmc.fmcHostObjectCreate(azure_utility_ip_name, azure_utility_ip, "Host Object for azure_utility_ip")

        # Create Network objects
        r = self.fmc.fmcNetworkObjectCreate(any_ipv4_name, "0.0.0.0/0", "network object for any ip")
        r = self.fmc.fmcNetworkObjectCreate(network_name, cidr, "network object for local net cidr")

        log.info("CreateStaticRoutes:::: --------Creating Static routes-------------")
        dev_id = self.fmc.getDevIdByName(ftdv_name, "FTD")
        in_gw_obj_id = self.fmc.getObjIdByName(inside_gw, "HOST")
        out_gw_obj_id = self.fmc.getObjIdByName(outside_gw, "HOST")
        azure_obj_id = self.fmc.getObjIdByName(azure_utility_ip_name, "HOST")
        vnet_obj_id = self.fmc.getObjIdByName(network_name, "NETWORK")
        anyip_obj_name = self.fmc.getObjIdByName(any_ipv4_name, "NETWORK")

        route_creation_error = 0

        if dev_id == "ERROR" or in_gw_obj_id == "ERROR" or out_gw_obj_id == "ERROR" or azure_obj_id == "ERROR" or vnet_obj_id == "ERROR" or anyip_obj_name == "ERROR":
            log.error("CreateStaticRoutes:::: Failed to get Device ID")
            log.error("CreateStaticRoutes:::: devId={}, inGwObjId={}, outGwObjId={}, azureObjId={}, vnetObjId={}, anyipObjName={}", dev_id, in_gw_obj_id, out_gw_obj_id, azure_obj_id, vnet_obj_id, anyip_obj_name)
            return "Unable to get Object Ids"  # need to change
        
        if self.fmc.fmcCreateHostRoutes(dev_id, fmc_inside_nic_name, network_name, vnet_obj_id, inside_gw, in_gw_obj_id, "1") == "ERROR":
            log.error("CreateStaticRoutes:::: Failed to create route-1")
            route_creation_error = 1
        
        if self.fmc.fmcCreateHostRoutes(dev_id, fmc_outside_nic_name, any_ipv4_name, anyip_obj_name, outside_gw, out_gw_obj_id, "2") == "ERROR":
            log.error("CreateStaticRoutes:::: Failed to create route-2")
            route_creation_error = 1

        if self.fmc.fmcCreateHostRoutes(dev_id, fmc_inside_nic_name, azure_utility_ip_name, azure_obj_id, inside_gw, in_gw_obj_id, "3") == "ERROR":
            log.error("CreateStaticRoutes:::: Failed to create route-3")
            route_creation_error = 1

        if route_creation_error == 1:
            return "Failed to create route"    # need to change
            
        log.info("CreateStaticRoutes:::: Successfully created static routes")
        return "SUCCESS" # need to change

    def CreateNatRules(self, ftdv_name):
        fmc_inside_zone = os.environ.get("INSIDE_ZONE")
        fmc_outside_zone = os.environ.get("OUTSIDE_ZONE")
        azure_utility_ip_name = os.environ.get("AZURE_UTILITY_IP_NAME")
        any_ipv4_name = os.environ.get("ANY_IPV4_NAME")
        app_obj_name = os.environ.get("APPLICATION_NAME")
        traffic_app_protocol = os.environ.get("TRAFFIC_APP_PROTOCOL")

        nat_policy_name = ftdv_name + "_NAT_Plolicy"
        log.warning("CreateNatRules:::: Creating NAT policy {} for {} ".format(nat_policy_name, ftdv_name))
        log.info("CreateNatRules:::: Creating NAT policy")
        if self.fmc.fmcCreateNATpolicy(nat_policy_name, "Nat Policy for vmss instance"):
            log.error("CreateNatRules:::: Failed to cerate NAT policy") # Orchestrator will retry
        
        device_id = self.fmc.getDevIdByName(ftdv_name, "FTD")
        policy_id = self.fmc.getDevIdByName(nat_policy_name, "NAT")

        if device_id == "ERROR" or policy_id == "ERROR":
            log.error("CreateNatRules:::: Failed to get resource ID, deviceId={}, policyId={}".format(device_id, policy_id))
            return "Failed to get resource ID"  # need to change
        
        log.info("CreateNatRules:::: Associate NAT policy {}:{} with device {}".format(nat_policy_name, policy_id, ftdv_name))
        if self.fmc.fmcAssociateNATpolicyWithDevice(nat_policy_name, policy_id, ftdv_name, device_id) == "ERROR":
            log.error("CreateNatRules:::: Failed to attach NAT policy to FTD")  # Orchestrator will retry
        
        in_zone_id = self.fmc.getDevIdByName(fmc_inside_zone, "ZONE")
        out_zone_id = self.fmc.getDevIdByName(fmc_outside_zone, "ZONE")
        src_obj = self.fmc.getObjIdByName(azure_utility_ip_name,  "HOST")
        dest_obj_mgmt = self.fmc.getObjIdByName(ftdv_name + "_mgmtIp", "HOST")
        connection = self.fmc.getObjIdByName("SSH",  "PORT")
        anyip = self.fmc.getObjIdByName(any_ipv4_name, "NETWORK")
        app_protocol = self.fmc.getObjIdByName(traffic_app_protocol, "PORT")
        dest_obj_app = self.fmc.getObjIdByName(app_obj_name, "HOST")

        nat_rule_creation_error = 0
        if in_zone_id == "ERROR" or out_zone_id == "ERROR" or src_obj == "ERROR" or dest_obj_mgmt == "ERROR" or connection == "ERROR" or anyip == "ERROR" or app_protocol == "ERROR" or dest_obj_app == "ERROR":
            log.error("CreateNatRules:::: Failed to get resource ID")
            log.error("CreateNatRules:::: inZoneId={}, outZoneId={}, srcObj={}, destObjMgmt={}, connection={}, anyip={}, appProtocol={}, destObjApp={}".format(in_zone_id, out_zone_id, src_obj, dest_obj_mgmt, connection, anyip, app_protocol, dest_obj_app))
            return "Failed to get resource ID"  # need to change
        
        log.info("CreateNatRules:::: Creating NAT rule-1")
        if self.fmc.fmcCreateNatRules(policy_id, "DYNAMIC", out_zone_id, in_zone_id, src_obj, connection, dest_obj_mgmt, connection, "Host") == "ERROR":
            log.error("CreateNatRules:::: Failed to cerate NAT rule-1")
            nat_rule_creation_error = 1
        
        log.info("CreateNatRules:::: Creating NAT rule-2")
        if self.fmc.fmcCreateNatRules(policy_id, "DYNAMIC", in_zone_id, out_zone_id, src_obj, connection, dest_obj_mgmt, connection, "Host") == "ERROR":
            log.error("CreateNatRules:::: Failed to cerate NAT rule-2")
            nat_rule_creation_error = 1
        
        log.info("CreateNatRules:::: Creating NAT rule-3")
        if self.fmc.fmcCreateNatRules(policy_id, "DYNAMIC", out_zone_id, in_zone_id, anyip, app_protocol, dest_obj_app, app_protocol, "Network") == "ERROR":
            log.error("CreateNatRules:::: Failed to cerate NAT rule-3")
            nat_rule_creation_error = 1
        
        log.info("CreateNatRules:::: Creating NAT rule-4 : Auto NAT")
        if self.fmc.fmcCreateAutoNatRules(policy_id, "DYNAMIC", in_zone_id, out_zone_id, anyip) == "ERROR":
            log.error("CreateNatRules:::: Failed to cerate NAT rule-4")
            nat_rule_creation_error = 1

        if nat_rule_creation_error == 1:
            return "Failed to create NAT rules"  # need to change
        
        log.info("CreateNatRules:::: Successfully created NAT policy and rules")
        return "SUCCESS" # need to change

    def CreateExtendedNatRules(self,ftdv_name):
        extended_nat_rules = os.environ.get("EXTENDED_NAT_RULES")
        if extended_nat_rules == "NA":
            log.warning("CreateExtendedNatRules:::: Extended NAT rule creation is disabled")
            return "SUCCESS" # need to change
        
        nat_policy_name = ftdv_name + "_NAT_Plolicy"
        policy_id = self.fmc.getDevIdByName(nat_policy_name, "NAT")
        if policy_id == "ERROR":
            log.error("CreateExtendedNatRules:::: Unable to get NAT Policy ID for {}".format(nat_policy_name))
            return "Failed to get NAT policy id" # need to change
        
        rule_count = 1
        try:
            for item in extended_nat_rules.json()["ExtendedNatRules"]:
                log.warning("CreateExtendedNatRules:::: Extended NAT Rule-{} details".format(rule_count))
                log.info("CreateExtendedNatRules:::: Description : {}".format(str(item["description"])))
                log.info("CreateExtendedNatRules:::: type : {}".format(str(item["type"])))
                log.info("CreateExtendedNatRules:::: natType: {}".format(str(item["natType"])))
                log.info("CreateExtendedNatRules:::: sourceZoneName: {}".format(str(item["sourceZoneName"])))
                log.info("CreateExtendedNatRules:::: destZoneName: {}".format(str(item["destZoneName"])))
                log.info("CreateExtendedNatRules:::: originalSourceObjectName: {}".format(str(item["originalSourceObjectName"])))
                log.info("CreateExtendedNatRules:::: originalSourceObjectType: {}".format(str(item["originalSourceObjectType"])))

                if str(item["type"]) == "MANUAL":
                    log.info("CreateExtendedNatRules:::: originalDestinationPortObjectName: {}".format(str(item["originalDestinationPortObjectName"])))
                    log.info("CreateExtendedNatRules:::: translatedDestinationObjectType: {}".format(str(item["translatedDestinationObjectType"])))
                    log.info("CreateExtendedNatRules:::: translatedDestinationObjectName: {}".format(str(item["translatedDestinationObjectName"])))
                    log.info("CreateExtendedNatRules:::: translatedDestinationPortObjectName: {}".format(str(item["translatedDestinationPortObjectName"])))

                nat_type = str(item["natType"])
                src_obj_type = str(item["originalSourceObjectType"]) 
                src_zone_id = self.fmc.getDevIdByName(str(item["sourceZoneName"]), "ZONE") 
                dest_zone_id = self.fmc.getDevIdByName(str(item["destZoneName"]), "ZONE")
                if src_obj_type == "Host":
                    log.info("CreateExtendedNatRules:::: Trying to get ID for {} with HOST type".format(str(item["originalSourceObjectName"])))
                    src_obj = self.fmc.getObjIdByName(str(item["originalSourceObjectName"]), "HOST")
                elif src_obj_type == "Network":
                    log.info("CreateExtendedNatRules:::: Trying to get ID for {} with Network type".format(str(item["originalSourceObjectName"])))
                    src_obj = self.fmc.getObjIdByName(str(item["originalSourceObjectName"]), "NETWORK")
                
                if str(item["type"]) == "MANUAL":
                    log.warning("CreateExtendedNatRules:::: Creating Extended Manual NAT rule-{}".format(rule_count))
                    original_port = self.fmc.getObjIdByName(str(item["originalDestinationPortObjectName"]), "PORT")
                    translated_port = self.fmc.getObjIdByName(str(item["translatedDestinationPortObjectName"]), "PORT")
                    dest_obj_type = str(item["translatedDestinationObjectType"])

                    if dest_obj_type == "Host":
                        log.info("CreateExtendedNatRules:::: Getting ID for {} with Host type".format(str(item["translatedDestinationObjectName"])))
                        dest_obj = self.fmc.getObjIdByName(str(item["translatedDestinationObjectName"]), "HOST")
                    elif dest_obj_type == "Network":
                        log.info("CreateExtendedNatRules:::: Getting ID for {} with Network type".format(str(item["translatedDestinationObjectName"])))
                        dest_obj = self.fmc.getObjIdByName(str(item["translatedDestinationObjectName"]), "NETWORK")
                    
                    if src_zone_id == "ERROR" or dest_zone_id == "ERROR" or src_obj == "ERROR" or original_port == "ERROR" or translated_port == "ERROR" or dest_obj == "ERROR":
                        log.error("CreateExtendedNatRules:::: Unable to get resource id")
                        return "Failed to get resource ID"  # need to change
                    
                    if self.fmc.fmcCreateNatRules(policy_id, nat_type, src_zone_id, dest_zone_id, src_obj, original_port, dest_obj, translated_port, src_obj_type) == "ERROR":
                        log.error("CreateExtendedNatRules:::: Failed to cerate Extended NAT rule-{}".format(rule_count))
                        return "Failed to create Extended NAT rule"  # need to change
                    
                    log.info("CreateExtendedNatRules:::: Created Extended NAT rule-{}".format(rule_count))

                elif str(item["type"]) == "AUTO":
                    log.warning("CreateExtendedNatRules:::: Auto NAT rule creation is not supported")
                    continue

                rule_count += 1

        except:
            log.info("CreateExtendedNatRules:::: Exception in creating Extended NAT rule {}".format(rule_count))
            return "Failed to create Extended NAT rule"  # need to change
        
        return "SUCCESS" # need to change

    def DeployConfiguration(self, ftdv_name):
        url = "https://" + self.fmc_ip + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/deployment/deploymentrequests"

        log.warning("DeployConfiguration:::: Deployment Started")
        device_id = self.fmc.getDevIdByName(ftdv_name, "FTD")
        post_data = { 
            "type": "DeploymentRequest", 
            "version": "0000000000", 
            "forceDeploy": True, 
            "ignoreWarning": True, 
            "deviceList": [device_id] 
        }

        r = self.fmc.rest_post(url, post_data)

        if not (200 <= r.status_code <= 300):
            log.error("DeployConfiguration:::: Deployment failed with status code {}".format(r.status_code))
            log.error("DeployConfiguration::::  Deployment falied status - {}".format(r.content))
            return "Deployment failed"  # need to change
            
        return "SUCCESS" # need to change
    
    def DisableHealthProbe(self, ftdv_name):
        fmc_inside_nic_name = os.environ.get("INSIDE_NIC_NAME")
        fmc_outside_nic_name = os.environ.get("OUTSIDE_NIC_NAME")
        azure_utility_ip_name = os.environ.get("AZURE_UTILITY_IP_NAME")
        outside_gw = os.environ.get("OUTSIDE_GW_OBJ_NAME")

        route_creation_error = 0
        log.warning("DisableHealthProbe:::: Disabling health Probe ")

        device_id = self.fmc.getDevIdByName(ftdv_name, "FTD")
        azure_obj_id = self.fmc.getObjIdByName(azure_utility_ip_name, "HOST")
        out_gw_obj_id = self.fmc.getObjIdByName(outside_gw, "HOST")

        if device_id == "ERROR" or azure_obj_id == "ERROR" or out_gw_obj_id == "ERROR":
            log.error("CreateStaticRoutes:::: Failed to get Device ID")
            log.error("CreateStaticRoutes:::: outGwObjId={}, azureObjId={} ".format(out_gw_obj_id, azure_obj_id))
            return "Failed to get resource ID"  # need to change
        
        '''
        if self.fmc.fmcCreateHostRoutes(device_id, fmc_outside_nic_name, azure_utility_ip_name, azure_obj_id, azure_utility_ip_name, azure_obj_id, "1") == "ERROR":
            log.error("CreateStaticRoutes:::: Failed to create route to disable HP of ELB")
            route_creation_error = 1
        if self.fmc.fmcCreateHostRoutes(device_id, fmc_inside_nic_name, azure_utility_ip_name, azure_obj_id, outside_gw, out_gw_obj_id, "2") == "ERROR":
            log.error("CreateStaticRoutes:::: Failed to create route to disable HP of ILB")
            route_creation_error = 1
        '''

        return "SUCCESS" # need to change
    
    def DeleteResources(self, ftdv_name):
        nat_policy_name = ftdv_name + "_NAT_Policy"
        log.warning("DeleteResources:::: Delete all the resources of {}".format(ftdv_name))

        policy_id = self.fmc.getDevIdByName(nat_policy_name, "NAT")
        log.info("DeleteResources:::: policy id : {}".format(policy_id))

        mgmt_obj_id = self.fmc.getObjIdByName(ftdv_name + "_mgmtIp", "HOST")
        log.info("DeleteResources:::: Mngt ip object id : {}".format(mgmt_obj_id))

        log.warning("DeleteResources:::: Deleting NAT policy")
        r1 = self.fmc.fmcDeleteNatPolicy(policy_id)

        log.warning("DeleteResources:::: Delete Management IP Object {}".format(ftdv_name + "_mgmtIp"))
        r2 = self.fmc.fmcDeleteHostObj(mgmt_obj_id)

        if r1 == "ERROR" or r2 == "ERROR":
            log.error("DeleteResources:::: Failed to delete NAT rule :{}  or Management IP Object : {}".format(r1, r2))
            return "ERROR"  # need to change
        
        log.info("DeleteResources:::: Resource deletion is successful")
        return "SUCCESS" # need to change
    
    def WaitForDeploymentTask(self, ftdv_name, ftdv_public_ip):
        fmc_inside_nic = os.environ.get("INSIDE_NIC_INTERFACE")

        log.warning("WaitForDeploymentTask:::: Waiting till Deployment task is finished for {}".format(ftdv_name))
        log.warning("WaitForDeploymentTask:::: Checking Deployment state")

        device_id = self.fmc.getDevIdByName(ftdv_name, "FTD")
        if device_id == "ERROR":
            log.warning("WaitForDeploymentTask:::: FTD {} still not registered in FMC.. waiting".format(ftdv_name))
            return "INPROGRESS" # need to change
        
        inside_nic_id = self.fmc.getDevIdByName(fmc_inside_nic, "NIC", device_id)
        if inside_nic_id == "ERROR":
            log.warning("WaitForDeploymentTask:::: FTD {} still not registered in FMC.. waiting".format(ftdv_name))
            return "INPROGRESS" # need to change

        ftd_ssh_client = FtdSshClient() 
        res = ftd_ssh_client.ftdSsh(ftdv_public_ip, "Completed")

        if res != "AVAILABLE":
            return "INPROGRESS" # need to change
        
        url = "https://" + self.fmc_ip + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/deployment/deployabledevices"
        r = self.fmc.rest_get(url)
        if not (200 <= r.status_code <= 300):
            log.error("WaitForDeploymentTask:::: Failed get Policy ID (Status Code : {}".format(r.status_code))
            # return "ERROR : Failed deployable device list"
        
        log.info("WaitForDeploymentTask:::: Successfully got Response for deployment status ")
        try:
            for item in r.json()["items"]:
                if str(item["type"]) == "DeployableDevice" and str(item["name"]) == ftdv_name:
                    log.info("WaitForDeploymentTask:::: Deployment is still in progress for {}".format(ftdv_name))
                    return "INPROGRESS" # need to change
        except:
            log.info("WaitForDeploymentTask:::: Deployment completed for {}".format(ftdv_name))
            return "COMPLETED" # need to change
        
        log.info("WaitForDeploymentTask:::: Deployment completed for {}".format(ftdv_name))
        return "COMPLETED" # need to change

    def WaitForFtdToComeUp(self, ftdv_name, ftdv_public_ip):
        set_unique_host_name = os.environ.get("SET_UNIQUE_HOST_NAME")
        ftd_ssh_client = FtdSshClient()
        res = ftd_ssh_client.ftdSsh(ftdv_public_ip, "pending")
        if res == "AVAILABLE":
            if set_unique_host_name == "YES":
                log.info("Setting host name to {}".format(ftdv_name))
                ftd_ssh_client.ftdSshSetHostName(ftdv_public_ip, ftdv_name)
            return "READY"  # need to change

        return "WAITING" # need to change
    
    def MinimumConfigVerification(self):
        fmc_inside_zone = os.environ.get("INSIDE_ZONE")
        fmc_outside_zone = os.environ.get("OUTSIDE_ZONE")
        subscription_id = os.environ.get("SUBSCRIPTION_ID", "11111111-1111-1111-1111-111111111111")

        # ---------------------------Get Policy ID by name------------------------------------------

        # Check if policy is present in FMC
        log.info("MinimumConfigVerification:::: Getting Access policy ID")
        fmc_policy_url = "https://" + self.fmc_ip + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/policy/accesspolicies"
        r = self.fmc.rest_get(fmc_policy_url)
        try:
            if 200 <= r.status_code <= 300:
                for item in r.json()["items"]:
                    if str(item["name"] == self.policy_name):
                        policy_id = str(item["id"])
                        break
                if len(policy_id) == 0:
                    log.error("MinimumConfigVerification:::: Unable to get Policy ID from Policy Name({})".format(self.policy_name))
                    log.error("MinimumConfigVerification:::: Contents received from FMC : {}", r.content)
                    return "ERROR: Unable to get Policy ID from Policy Name"  # need to change
            else:
                log.error("MinimumConfigVerification:::: Policy {} is not present in FMC".format(self.policy_name))
                return "ERROR: Unable to get Policy"  # need to change
        except:
            log.error("MinimumConfigVerification:::: Exception occoured")
            return "ERROR: Unable to get Policy ID from Policy Name"  # need to change
        
        log.info("MinimumConfigVerification:::: Found Policy({}) ID : {} ".format(self.policy_name, policy_id))

        in_zone_id = self.fmc.getDevIdByName(fmc_inside_zone, "ZONE")
        if in_zone_id == "ERROR":
            log.error("MinimumConfigVerification:::: Failed to get inside zone Id")
            return "ERROR : Failed get  inside zone Id" # need to change
        
        log.info("MinimumConfigVerification:::: inside zone ID : {}".format(in_zone_id))

        out_zone_id = self.fmc.getDevIdByName(fmc_outside_zone, "ZONE")
        if out_zone_id == "ERROR":
            log.error("MinimumConfigVerification:::: Failed to get outside zone Id")
            return "ERROR : Failed get  outside zone Id" # need to change
        
        log.info("MinimumConfigVerification:::: outside zone ID : {}".format(out_zone_id))

        dev_group_id = self.fmc.getDevGroupIdByName(self.dev_group_name)
        if dev_group_id == "ERROR":
            log.error("MinimumConfigVerification:::: Unable to get Device Group ID")
            return "ERROR : Failed get Device Group Id" # need to change

        collect_garbage = os.environ.get("GARBAGE_COLLECTOR")
        if collect_garbage == "ON":
            log.warning("MinimumConfigVerification:::: Garbage collector is ON, detecting orphan FTDs in Azure")
            resource_group_name = os.environ.get("RESOURCE_GROUP_NAME")
            vm_scle_set_name = os.environ.get("VMSS_NAME")
            credentials = ManagedIdentityCredential()
            compute_client = ComputeManagementClient(credentials, subscription_id)
            vmss = compute_client.virtual_machine_scale_set_vms.list(resource_group_name,vm_scle_set_name,expand="instanceView")
            log.warning("MinimumConfigVerification:::: FTD count : {}".format(len(vmss)))

            if len(vmss) != 0:
                for vm in vmss:
                    log.info("MinimumConfigVerification:::: Check if {} is present in FMC".format(vm.name))

                    if self.fmc.getDevIdByName(vm.name, "FTD") == "ERROR":
                        log.warning("MinimumConfigVerification:::: FTD {} is only present in Azure and not present in FMC...Deleting it".format(vm.name))
                        operation_delay = 30000  # 30sec
                        delay = compute_client.virtual_machine_scale_set_vms.begin_delete(resource_group_name, vm_scle_set_name, vm.instance_id)
                        delay.wait(operation_delay)
                        log.warning("MinimumConfigVerification:::: Deleted FTD {}".format(vm.name))
                        return "DELETED Garbage FTD" # need to change
        else:
            log.warning("MinimumConfigVerification:::: Considering Garbage collector is OFF..")

        return "SUCCESS" # need to change
    
    def DeleteUnRegisteredFTD(self,ftdv_name):
        del_bad_ftd = os.environ.get("DELETE_FAULTY_FTD")
        subscription_id = os.environ.get("SUBSCRIPTION_ID","11111111-1111-1111-1111-111111111111")

        if del_bad_ftd != "YES":
            log.error("DeleteUnRegisteredFTD:::: Failed to get Auth token")
            return "ERROR: Failed to get Auth Token" # need to change

        log.warning("DeleteUnRegisteredFTD:::: Checking if {} is registered to FMC".format(ftdv_name))

        ftd_id = self.fmc.getDevIdByName(ftdv_name, "FTD")
        if ftd_id == "ERROR":
            log.error("DeleteUnRegisteredFTD:::: FTD {} is not registered to FMC.. Deleting it from Azure".format(ftdv_name))
            resource_group_name = os.environ.get("RESOURCE_GROUP_NAME")
            vm_scle_set_name = os.environ.get("VMSS_NAME")
            credentials = ManagedIdentityCredential()
            compute_client = ComputeManagementClient(credentials, subscription_id)
            vmss = compute_client.virtual_machine_scale_set_vms.list(resource_group_name,vm_scle_set_name,expand="instanceView")
            for vm in vmss:
                if vm.name == ftdv_name:
                    log.warning("DeleteUnRegisteredFTD:::: Found {} in Azure, Azure instance Id : {1}".format(vm.name, vm.instance_id))
                    operation_delay = 30000 # 30sec
                    delay = compute_client.virtual_machine_scale_set_vms.begin_delete(resource_group_name, vm_scle_set_name, vm.instance_id)
                    delay.wait(operation_delay)
                    log.warning("DeleteUnRegisteredFTD:::: Deleted FTD {}".format(vm.name))
                    return "DELETED Unregistered FTD"
            
            log.error("DeleteUnRegisteredFTD:::: Unable to find {} in Azure VMSS".format(ftdv_name))
            return "Unable to find this FTD in Azure" # need to change
        else:
            log.warning("DeleteUnRegisteredFTD:::: FTD {} is registered to FMC".format(ftdv_name))
        
        return "SUCCESS" # need to change

            

        