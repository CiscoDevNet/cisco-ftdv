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

Name:       Utils.py
Purpose:    This python file is used for managing the FTDv interfaces.
"""


import time
import requests
import logging as log
import json
import os
import paramiko
import socket

class FMC:
    def __init__(self):
        self.server = 'https://' + os.environ.get('FMC_IP')
        self.username = os.environ.get('FMC_USERNAME')
        self.password = os.environ.get('FMC_PASSWORD')
        self.headers = []
        self.domain_uuid = "e276abec-e0f2-11e3-8169-6d9ed49b625f"
        self.authTokenTimestamp = 0
        self.authTokenMaxAge = 15*60  # seconds - 30 minutes is the max without using refresh
        self.accessPolicyName = os.environ.get('POLICY_NAME')

# ======================================= REST methods ==========================================   
    def rest_get(self, url):
        """
        Purpose:    Issue REST get to the specified URL
        Parameters: url
        Returns:    r.text is the text response (r.json() is a python dict version of the json response)
                    r.status_code = 2xx on success
        Raises:
        """
        # if the token is too old then get another
        if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
            log.debug("Getting a new authToken")
            self.getFmcAuthToken()
        try:
            # REST call with SSL verification turned off:
            #debug
            log.info("Request: " + url)
            r = requests.get(url, headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            log.info("Response status_code: " + str(status_code))
            log.info("Response body: " + str(resp))
            if 200 <= status_code <= 300:
                pass
            else:
                r.raise_for_status()
                raise Exception("Error occurred in Get -->"+resp)
        except requests.exceptions.HTTPError as err:
            raise Exception("Error in connection --> "+str(err))
        finally:
            if r: r.close()
            return r
    
    def rest_post(self, url, post_data):
        """
        Purpose:    Issue REST post to the specified url with the post_data provided
        Parameters: url, post data
        Returns:    This function will return 'r' which is the response from the post:
                    r.text is the text response (r.json() is a python dict version of the json response)
                    r.status_code = 2xx on success
        Raises:     Error occurred in post
        """
        if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
            log.debug("Getting a new authToken")
            self.getFmcAuthToken()
        try:
            # REST call with SSL verification turned off:
            log.info("Request: " + url)
            log.info("Post_data " + str(post_data))
            r = requests.post(url, data=json.dumps(post_data), headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            log.info("Response status_code: " + str(status_code))
            log.info("Response body: " + str(resp))
            # logging.debug("Status code is: "+str(status_code))
            if 201 <= status_code <= 202:
                pass
            else:
                r.raise_for_status()
                raise Exception("Error occurred in POST --> "+resp)
        except requests.exceptions.HTTPError as err:
            raise Exception("Error in connection --> "+str(err))
        finally:
            if r: r.close()
            return r

    def rest_put(self, url, put_data):
        """
        Purpose:    Issue REST put to specific url with the put_data provided
        Parameters: url, put data
        Returns:    This function will return 'r' which is the response from the put:
                    r.text is the text response (r.json() is a python dict version of the json response)
                    r.status_code = 2xx on success
        Raises:
        """
        if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
            log.debug("Getting a new authToken")
            self.getFmcAuthToken()
        try:
            # REST call with SSL verification turned off:
            log.info("Request: " + url)
            log.info("Put_data: " + str(put_data))
            r = requests.put(url, data=json.dumps(put_data), headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            log.info("Response status_code: " + str(status_code))
            log.info("Response body: " + str(resp))
            if status_code == 200:
                pass
            else:
                r.raise_for_status()
                raise Exception("Error occurred in put -->" + resp)
        except requests.exceptions.HTTPError as err:
            raise Exception("Error in connection --> "+str(err))
        finally:
            if r: r.close()
            return r

    def rest_delete(self, url):
        """
        Purpose:    Issue REST delete to the specified URL
        Parameters: url
        Returns:    This function will return 'r' which is the response to the request:
                    r.text is the text response (r.json() is a python dict version of the json response)
                    r.status_code = 2xx on success
        Raises:
        """
        if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
            log.debug("Getting a new authToken")
            self.getFmcAuthToken()

        try:
            # REST call with SSL verification turned off:
            log.debug("Request: " + url)
            r = requests.delete(url, headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            log.info("Response status_code: " + str(status_code))
            log.info("Response body: " + str(resp))
            if 200 <= status_code <= 300:
                pass
            else:
                r.raise_for_status()
                raise Exception("Error occurred in Delete -->"+resp)
        except requests.exceptions.HTTPError as err:
            raise Exception("Error in connection --> "+str(err))
        finally:
            if r: r.close()
            return r

# ========================================= Get functions ==================================================  
    def getFmcAuthToken(self):
        """
        Purpose:    get a new REST authentication token
                    update the 'headers' variable
                    set a timestamp for the header (tokens expire)
        Parameters:
        Returns:
        Raises:
        """
        self.headers = {'Content-Type': 'application/json'}
        api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
        auth_url = self.server + api_auth_path
        try:
            # 2 ways of making a REST call are provided:
            # One with "SSL verification turned off" and the other with "SSL verification turned on".
            # The one with "SSL verification turned on" is commented out. If you like to use that then
            # comment the line where verify=False and uncomment the line with verify='/path/to/ssl_certificate'
            # REST call with SSL verification turned off:
            r = requests.post(auth_url, headers=self.headers,
                              auth=requests.auth.HTTPBasicAuth(self.username, self.password), verify=False)
            auth_headers = r.headers
            auth_token = auth_headers.get('X-auth-access-token', default=None)
            self.headers['X-auth-access-token'] = auth_token
            self.authTokenTimestamp = int(time.time())
            if auth_token is None:
                log.debug("auth_token not found. Exiting...")
            else:
                return auth_token
        except Exception as err:
            log.error("Error in generating auth token --> " + str(err))
        return "ERROR"
    
    def getAccessPolicyIdByName(self, name):
        """
        Purpose:    Get Access Policy Id by its name
        Parameters: Access policy name
        Returns:    Access Policy Id, None
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/" + self.domain_uuid + "/policy/accesspolicies"
        url = self.server + api_path + '?offset=0&limit=10000'
        r = self.rest_get(url)
        # Search for policy by name
        if 'items' in r.json():
            for item in r.json()['items']:
                if item['name'] == name:
                    return str(item['id'])
        return "ERROR"

    def getDevIdByName(self, name, cmd, optional_dev_Id=None):
        """
        Purpose:    Get Device Id by its name
        Parameters: Device Name, type of device, device_id of device incase of NIC
        Returns:    Device Id or ERROR
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/"+ self.domain_uuid +"/devices/devicerecords"
        if cmd == "FTD":
            log.info("util:::: Getting FTD ID for {}".format(name))
        elif cmd == "NIC":
            log.info("util:::: Getting NIC ID for {}".format(name))
            api_path = api_path + "/" + optional_dev_Id + "/physicalinterfaces"
        elif cmd == "ZONE":
            log.info("util:::: Getting ZONE ID for {}".format(name))
            api_path = "/api/fmc_config/v1/domain/" + self.domain_uuid + "/object/securityzones"
        elif cmd == "NAT":
            log.info("util:::: Getting NAT ID for {}".format(name))
            api_path = "/api/fmc_config/v1/domain/" + self.domain_uuid + "/policy/ftdnatpolicies"
        else:
            log.info("util:::: Unknown command")
            return "ERROR"
        url = self.server + api_path + '?offset=0&limit=10000'
        r = self.rest_get(url)
        
        if 'items' in r.json():
            for item in r.json()['items']:
                if item['name'] == name:
                    return str(item['id'])
        # or return empty string
        return "ERROR"

    def getAllDevID(self):
        """
        Purpose:    To get ids of all the devices
        Returns:    dictionary of device names and device ids
        Raises:
        """
        devices = {}
        api_path = "/api/fmc_config/v1/domain/" + self.domain_uuid + "/devices/devicerecords"
        url = self.server + api_path
        r = self.rest_get(url)

        for item in r.json()['items']:
            devices[item['name']] = item['id']
         
        return devices
    
    def getDevGroupIdByName(self, name):
        """
        Purpose:    To get device group id by passing name of the group
        Parameters: Name of device group
        Returns:    Group Id or None
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devicegroups/devicegrouprecords"
        url = self.server + api_path + '?offset=0&limit=1000'
        r = self.rest_get(url)
        if 'items' in r.json():
            for item in r.json()['items']:
                if item['name'] == name:
                    return str(item['id'])
        return "ERROR"
    
    def getObjIdByName(self, objName, cmd):
        """
        Purpose:    Get object Id by Name
        Parameters: Object Name, Object type
        Returns:    Object Id or ERROR
        Raises:
        """
        type = ""
        regUrl = "/api/fmc_config/v1/domain/" + self.domain_uuid + "/object/"
        if cmd == "HOST":
            log.info("util:::: Getting Host obj {} ID".format(objName))
            regUrl = regUrl + "hosts"
            type = "Host"
        elif cmd == "PORT":
            log.info("util:::: Getting Port obj {} ID".format(objName))
            regUrl = regUrl + "protocolportobjects"
            type = "ProtocolPortObject"
        elif cmd == "NETWORK":
            log.info("util:::: Getting Network obj {} ID".format(objName))
            regUrl = regUrl + "networkaddresses"
            type = "Network"
        else:
            log.error("util:::: Unknown command")
            return "ERROR"
        
        url = self.server + regUrl + '?offset=0&limit=1000'
        r = self.rest_get(url)

        for item in r.json()['items']:
            if item['type'] == type and item['name'] == objName:
                return str(item['id'])
        
        return "ERROR"

    def getFtdMetricsFromFmc(self, devId):
        """
        Purpose:    Fetch Memory Metric
        Parameters: device id
        Returns:
        Raises:
        """
        try:
            # New Health Monitoring API
            api_path = f'/api/fmc_config/v1/domain/{self.domain_uuid}/health/metrics'
            # Values are fetched from last one minute at interval of 10 sec (step).
            end_time = int(time.time())
            start_time = end_time - 60
            step_size = 10
            regex_filter = "used_percentage_system_and_swap"
            api_suffix = \
                f'?offset=0&limit=100&filter=deviceUUIDs%3A{devId}%3Bmetric%3Amem%3B' + \
                f"startTime%3A{start_time}%3BendTime%3A{end_time}%3Bstep%3A{step_size}%3B" + \
                f"regexFilter%3A{regex_filter}&expanded=true"
            url = self.server + api_path + api_suffix

            r = self.rest_get(url)
            log.debug("util:::: response : {0}".format(r.content))
            resp = r.text
            return json.loads(resp)
        except Exception as e:
            log.info("util::::Error getting memory : {}".format(e))
            return None
    
# =================================== Create functions =========================================   
    def fmcHostObjectCreate(self, objName, ip, description=""):
        """
        Purpose:    To create Host Object
        Parameters: object name, ip, description
        Returns:    SUCCESS or ERROR
        Raises:
        """
        url = self.server + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/object/hosts"
        post_data = {
            "name": objName, 
            "type": "Host", 
            "value": ip, 
            "description": description
        }
        log.info("util:::: Creating host object : {}".format(objName))

        r = self.rest_post(url, post_data)
        if 201 <= r.status_code <= 202:
            return "SUCCESS"
        else:
            log.error("util:::: Failed to create HOST Object : {} .. probably already existing".format(objName))
            return "ERROR"
    
    def fmcNetworkObjectCreate(self, objName, ip, description=""):
        """
        Purpose:    To create Network Object
        Parameters: object name, ip, description
        Returns:    SUCCESS or ERROR
        Raises:
        """
        url = self.server + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/object/networks"
        post_data = {
            "name": objName, 
            "type": "Network", 
            "value": ip, 
            "description": description,
            "overridable": "false"
        }
        log.info("util:::: Creating Network object : {}".format(objName))

        r = self.rest_post(url, post_data)
        if 201 <= r.status_code <= 202:
            return "SUCCESS"
        else:
            log.error("util:::: Failed to create Network Object : {} .. probably already existing".format(objName))
            return "ERROR"
    
    def fmcPortObjectCreate(self, objName, port, protocol, description=""):
        """
        Purpose:    To create Port Object
        Parameters: object name, ip, description
        Returns:    SUCCESS or ERROR
        Raises:
        """
        url = self.server + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/object/protocolportobjects"
        post_data = {
            "name": objName, 
            "type": "ProtocolPortObject", 
            "port": port,
            "protocol": protocol,
            "description": description,
        }
        log.info("util:::: Creating Port object : {}".format(objName))

        r = self.rest_post(url, post_data)
        if 201 <= r.status_code <= 202:
            return "SUCCESS"
        else:
            log.error("util:::: Failed to create Port Object : {} .. probably already existing".format(objName))
            return "ERROR"

    def fmcCreateHostRoutes(self, device_id, interface_name, _object_name, _object_id, gateway_name, gateway_id, metric):
        """
        Purpose:    To create static route on device
        Parameters: Device, Interface Name, Host, Gateway, Metric
        Returns:    SUCCESS or ERROR
        Raises:
        """

        api_path = "/api/fmc_config/v1/domain/"+ self.domain_uuid +"/devices/devicerecords/" + device_id + "/routing/ipv4staticroutes" 
        url = self.server + api_path

        post_data = {
            "interfaceName": interface_name,
            "selectedNetworks": [
                {
                    "type": "Host",
                    "id": _object_id,
                    "name": _object_name
                }
            ],
            "gateway": { 
                "object": { 
                    "type": "Host",
                    "id": gateway_id, 
                    "name":  gateway_name  
                } 
            },
            "metricValue": metric,
            "type": "IPv4StaticRoute",
            "isTunneled": "false"
        }

        log.info("util:::: Creating host route for {}:{}".format(_object_name, gateway_id))
        r = self.rest_post(url, post_data)
        if 201 <= r.status_code <= 202:
            return "SUCCESS"
        else:
            log.error("util:::: Failed to create Host Route :  {}:{} ".format(_object_name, gateway_id))
            return "ERROR"

    def fmcCreateNATpolicy(self, policyName, description):
        """
        Purpose:    To create NAT policy
        Parameters: policy name, description
        Returns:    SUCCESS or ERROR
        Raises:
        """
        url = self.server + "/api/fmc_config/v1/domain/"+ self.domain_uuid +"/policy/ftdnatpolicies"
        post_data = {
            "type": "FTDNatPolicy", 
            "name": policyName , 
            "description": description 
        }

        log.info("util:::: Creating NAT policy {}".format(policyName))
        r = self.rest_post(url, post_data)
        if 201 <= r.status_code <= 202:
            return "SUCCESS"
        else:
            log.error("util:::: Failed to create NAT policy {}".format(policyName))
            return "ERROR"

    def fmcCreateNatRules(self, natPolicyId, natType, sourceZoneId, destZoneId, originalSourceIpObjectId, originalDestPortObjectId, translatedDestIpObjectId, translatedDestinationPortObjectId, types):
        """
        Purpose:    To create NAT rules
        Parameters: policy id, nat type, source zone id, destination zone id, original source ip object id, original destination ip object id, translated destination ip object id, translated destination port object id, types
        Returns:    SUCCESS or ERROR
        Raises:
        """
        url = self.server + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/policy/ftdnatpolicies/" + natPolicyId + "/manualnatrules"
        post_data = { 
            "originalDestinationPort": { 
                "type": "ProtocolPortObject", 
                "id":  originalDestPortObjectId 
            }, 
            "originalSource": { 
                "type": types , 
                "id": originalSourceIpObjectId
            }, 
            "translatedDestination": {  
                "type": "Host", 
                "id": translatedDestIpObjectId 
            }, 
            "translatedDestinationPort": { 
                "type": "ProtocolPortObject", 
                "id": translatedDestinationPortObjectId 
            },     
            "unidirectional": "true", 
            "interfaceInOriginalDestination": "true", 
            "interfaceInTranslatedSource": "true", 
            "type": "FTDManualNatRule", 
            "enabled": "true", 
            "natType":natType, 
            "interfaceIpv6": "false",  
            "fallThrough": "false", 
            "dns": "false", 
            "routeLookup": "false", 
            "noProxyArp": "false", 
            "netToNet": "false",     
            "sourceInterface": { 
                "id": sourceZoneId,  
                "type": "SecurityZone" 
            },  
            "destinationInterface": { 
                "id": destZoneId , 
                "type": "SecurityZone" 
            } ,  
            "description": ""   
        }

        log.info("util:::: Creating  NAT rule")
        r = self.rest_post(url, post_data)
        if 201 <= r.status_code <= 202:
            return "SUCCESS"
        else:
            log.error("util:::: Failed to create NAT rule")
            return "ERROR"
    
    def fmcCreateAutoNatRules(self, natPolicyId, natType, sourceZoneId, destZoneId, originalNetworkObjectId):
        """
        Purpose:    To create NAT rules
        Parameters: nat policy id, nat type, source zone id, destination zone id, original network object id
        Returns:    SUCCESS or ERROR
        Raises:
        """
        url = self.server + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/policy/ftdnatpolicies/" + natPolicyId + "/autonatrules"
        post_data = { 
            "type": "FTDAutoNatRule",  
            "originalNetwork": {   
                "type": "Network",   
                "id": originalNetworkObjectId 
            },  
            "originalPort": 0, 
            "translatedPort": 0,   
            "interfaceInTranslatedNetwork": "true", 
            "dns": "false",   
            "routeLookup": "false",  
            "noProxyArp": "false",    
            "netToNet": "false",   
            "destinationInterface": { 
                "id": destZoneId ,    
                "type": "SecurityZone"   
            },  
            "interfaceIpv6": "false",  
            "fallThrough": "false",   
            "natType": "DYNAMIC",   
            "sourceInterface": { 
                "id": sourceZoneId ,   
                "type": "SecurityZone"   
            },    
            "description": "" 
        }

        log.info("util:::: Creating Auto NAT rule")
        r = self.rest_post(url, post_data)
        if 201 <= r.status_code <= 202:
            return "SUCCESS"
        else:
            log.error("util:::: Failed to create Auto NAT rule")
            return "ERROR"
    
    def fmcCreateDeviceGroup(self, devGroupName):
        """
        Purpose:    To create device group
        Parameters: device group name
        Returns:    SUCCESS or ERROR
        Raises:
        """
        url = self.server + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/devicegroups/devicegrouprecords"
        post_data = { 
            "name": devGroupName , 
            "type": "DeviceGroup" 
        }
        log.info("util:::: Creating Device Group : {}..".format(devGroupName))

        r = self.rest_post(url, post_data)
        if 201 <= r.status_code <= 202:
            return "SUCCESS"
        else:
            log.error("util:::: Failed to create Device Group {}".format(devGroupName))
            return "ERROR"

 
    def fmcAssociateNATpolicyWithDevice(self, policyName, policyId, deviceName, deviceId):
        """
        Purpose:    To Associate NAT policy to the device
        Parameters: policy name, policy id, ngfwv name, ngfwv id, 
        Returns:    SUCCESS or ERROR
        Raises:
        """
        url = self.server + "/api/fmc_config/v1/domain/"+ self.domain_uuid +"/assignment/policyassignments"
        post_data = { 
            "type": "PolicyAssignment", 
            "policy": { 
                "type": "FTDNatPolicy",  
                "id": policyId 
            }, 
            "targets": [ 
                {  
                    "id": deviceId, 
                    "type": "Device"  
                }  
            ]   
        }

        log.info("util:::: Associating NAT policy {} with Device {}".format(policyName, deviceName))
        r = self.rest_post(url, post_data)
        if 201 <= r.status_code <= 202:
            return "SUCCESS"
        else:
            log.error("util:::: Failed to Associate NAT policy".format(policyName))
            return "ERROR"

# ======================================= Delete functions =================================================
    def fmcDeleteHPNatRules(self, natPolicyId):
        """
        Purpose:    To delete Health Probe nat rules
        Parameters: nat policy id
        Returns:    SUCCESS or ERROR
        Raises:
        """
        url = self.server + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/policy/ftdnatpolicies/" + natPolicyId + "/manualnatrules"
        log.info("util:::: Deleting HP NAT rule..Started")

        r = self.rest_get(url)
        if r.status_code != 200:
            log.error("util:::: Failed get NAT rules details from NAT policy")
            return "ERROR"
        
        try:
            hpNatId = str(r.json()['items'][0]["id"])
            if len(hpNatId) == 0:
                log.LogError("util:::: Failed to get NAT rule id")
                return "ERROR"
            
            log.info("util:::: Gathered HB NAT rule id : {}".format(hpNatId))
            url = url + "/" + hpNatId

            r = self.rest_delete(url)
            if 200 <= r.status_code <= 300:
                log.error("util:::: Failed to delete NAT rule")
                return "ERROR"
        except:
            log.error("util:::: Exception occoured")
            return "ERROR"
        
        log.info("util:::: Deleted NAT rule for Health Probe")
        return "SUCCESS"

    def fmcDeleteNatPolicy(self, natPolicyId):
        """
        Purpose:    To delete nat policy
        Parameters: nat policy id
        Returns:    SUCCESS or ERROR
        Raises:
        """
        url = self.server + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/policy/ftdnatpolicies/" + natPolicyId
        log.info("util:::: Deleting NAT Policy Started..")

        r = self.rest_delete(url)
        if 200 <= r.status_code <= 300:
            return "SUCCESS"
        else:
            log.error("util:::: Failed to delete NAT policy")
            return "ERROR"

    def fmcDeleteHostObj(self, objId):
        """
        Purpose:    To delete host object
        Parameters: object id
        Returns:    SUCCESS or ERROR
        Raises:
        """
        url = self.server + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/object/hosts/" +  objId
        log.info("util:::: Deleting Host Object..")

        r = self.rest_delete(url)
        if 200 <= r.status_code <= 300:
            return "SUCCESS"
        else:
            log.error("util:::: Failed to delete Host Object")
            return "ERROR"
        

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
            log.exception(e)
            log.error("returning : " + self.FAIL)
            return self.FAIL
        except Exception as e:
            log.exception(e)
            log.error("returning : " + self.FAIL)
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
            log.error("Exception occurred: {}".format(repr(exc)))
            return self.AUTH_EXCEPTION
        except paramiko.BadHostKeyException as exc:
            log.debug("Exception occurred: {}".format(repr(exc)))
            return self.BAD_HOST_KEY_EXCEPTION
        except paramiko.SSHException as exc:
            log.debug("Exception occurred: {}".format(repr(exc)))
            return self.SSH_EXCEPTION
        except BaseException as exc:
            log.debug("Exception occurred: {}".format(repr(exc)))
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
            log.error("Exception occurred: {}".format(repr(exc)))
            self.ssh.close()
            return self.FAIL, None, None
        else:
            output = ssh_stdout.readlines()
            error = ssh_stderr.readlines()
            log.debug('SSH command output: ' + str(output))
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
            log.error("Exception occurred: {}".format(repr(exc)))
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
                set_ = command_set[key]
                for i in range(0, len(set_)):
                    command = set_[i]['command'] + '\n'
                    expect = set_[i]['expect']
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
            log.error("Error occurred: {}".format(repr(e)))
            return None


class FtdSshClient:
    def __init__(self):
        self.ftdUserName = os.environ.get("FTD_USERNAME")
        self.ftdPassword = os.environ.get("FTD_PASSWORD")
        self.port = 22
        self.SUCCESS = 'SUCCESS'
        self.FAIL = 'FAILURE'
    def ftdSsh(self, ftdPublicIp, lookFor):
        try:
            connect = ParamikoSSH(ftdPublicIp, self.port, self.ftdUserName, self.ftdPassword)
        except:
            log.error("util:::: SSH exception")
            return "UNAVAILABLE"

        try:
            status, output, error = connect.execute_cmd("show managers")
            connect.close()
        except Exception as e:
            log.error("Error occurred: {}".format(repr(e)))
            return "UNAVAILABLE"

        if status == self.SUCCESS and lookFor in output:
            return "AVAILABLE"
        else:
            log.warning("util:::: Unable to run command output: {} error: {}".format(output, error))
            return "UNAVAILABLE"
        
    def ftdSshSetHostName(self, ftdIp, hostname):
        try:
            connect = ParamikoSSH(ftdIp, self.port, self.ftdUserName, self.ftdPassword)
        except:
            log.error("util:::: SSH exception")
            return "ERROR"

        try:
            cmd = 'configure network hostname' + ' ' + hostname
            r, output, error = self.run_ftdv_command(cmd)
            log.info("Instance hostname configuration: " + output)
            return "SUCCESS"
        except:
            return "ERROR"