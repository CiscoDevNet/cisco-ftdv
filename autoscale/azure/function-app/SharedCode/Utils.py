"""
Copyright (c) 2026 Cisco Systems Inc or its affiliates.

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
Purpose:    This python file is used for shared FMC and FTD utility helpers.
"""

import time
import requests
import logging as log
import json
import os
import re
import paramiko
import socket
# import utility as utl
# from requests.packages.urllib3.exceptions import InsecureRequestWarning
# requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def getVmssInstanceSuffix(ftdv_name):
    """
    Purpose:    Extract VMSS instance suffix from FTD device name.
    Parameters: FTD VMSS instance name
    Returns:    Numeric suffix or empty string
    Raises:
    """
    if not ftdv_name:
        return ""

    for separator in ("_", "-"):
        suffix = ftdv_name.rsplit(separator, 1)[-1]
        if suffix.isdigit():
            return suffix

    return ""


def getInstanceNatId(base_nat_id, ftdv_name):
    """
    Purpose:    Return the FMC NAT ID used by both day0 and FMC registration.
    Parameters: Base NAT ID and FTD VMSS instance name
    Returns:    Stack NAT ID
    Raises:
    """
    return base_nat_id or ""


def getFtdRegistrationIp(req_body):
    """
    Purpose:    Select the FTD address FMC should use for registration.
    Parameters: Function request body
    Returns:    Public or private FTD IP
    Raises:
    """
    ftdv_public_ip = req_body.get("ftdPublicIp")
    ftdv_private_ip = req_body.get("ftdPrivateIp")
    registration_using_public_fmc_ip = (os.environ.get("REGISTRATION_USING_PUBLIC_FMC_IP") or "NO").upper()

    if registration_using_public_fmc_ip == "YES":
        return ftdv_public_ip or ftdv_private_ip
    return ftdv_private_ip or ftdv_public_ip


def getFtdSshIps(req_body):
    """
    Purpose:    Return FTD SSH candidate IPs without changing FMC registration identity.
    Parameters: Function request body
    Returns:    Ordered FTD SSH IP list
    Raises:
    """
    candidates = []
    for candidate_ip in (
        getFtdRegistrationIp(req_body),
        req_body.get("ftdPrivateIp"),
        req_body.get("ftdPublicIp"),
    ):
        if candidate_ip and candidate_ip not in candidates:
            candidates.append(candidate_ip)
    return candidates


def normalizeMacAddress(mac_address):
    if not mac_address:
        return ""
    return re.sub(r"[^0-9a-fA-F]", "", mac_address).lower()


def getVmssInstanceIdFromName(ftdv_name):
    from SharedCode import azure_utils as azutils

    for vm in azutils.get_vmss_vm_list():
        if vm.name == ftdv_name:
            return vm.instance_id
    return None


def getVmssNicInfo(ftdv_name, azure_nic_name):
    from SharedCode import azure_utils as azutils

    instance_id = getVmssInstanceIdFromName(ftdv_name)
    if instance_id is None:
        log.error("util:::: Unable to find VMSS instance ID for {}".format(ftdv_name))
        return None

    for intf in azutils.get_vmss_intf_list():
        if intf.name != azure_nic_name:
            continue

        intf_id_parts = intf.id.split("/")
        try:
            current_instance_id = intf_id_parts[intf_id_parts.index("virtualMachines") + 1]
        except (ValueError, IndexError):
            log.error("util:::: Unable to parse VMSS NIC ID {}".format(intf.id))
            continue

        if current_instance_id != str(instance_id):
            continue

        private_ip = ""
        if intf.ip_configurations:
            private_ip = intf.ip_configurations[0].private_ip_address
        mac_address = getattr(intf, "mac_address", None)

        return {
            "name": intf.name,
            "instance_id": instance_id,
            "mac": mac_address,
            "normalized_mac": normalizeMacAddress(mac_address),
            "private_ip": private_ip,
        }

    log.error("util:::: Unable to find Azure NIC {} for {}".format(azure_nic_name, ftdv_name))
    return None


def getFtdShowInterfaceCommandName(interface_name):
    return re.sub(r"^([A-Za-z]+)(\d+/\d+)$", r"\1 \2", interface_name or "")


def parseFtdShowInterfaceOutput(output):
    if not output:
        return {}

    interface_match = re.search(r"Interface\s+([A-Za-z]+\d+/\d+)", output)
    mac_match = re.search(r"MAC address\s+([0-9a-fA-F.:-]+)", output)
    ip_match = re.search(r"IP address\s+(\d+\.\d+\.\d+\.\d+)", output)

    return {
        "name": interface_match.group(1) if interface_match else "",
        "mac": mac_match.group(1) if mac_match else "",
        "normalized_mac": normalizeMacAddress(mac_match.group(1) if mac_match else ""),
        "ip": ip_match.group(1) if ip_match else "",
        "output": output,
    }


def parseFtdShowInterfacesOutput(output):
    """
    Purpose:    Parse `show interface` output into individual interface records.
    Parameters: FTD show interface command output
    Returns:    List of parsed interface dictionaries
    Raises:
    """
    if not output:
        return []

    blocks = re.split(r"(?=^Interface\s+[A-Za-z]+\d+/\d+)", output, flags=re.MULTILINE)
    interfaces = []
    for block in blocks:
        if not block.strip().startswith("Interface "):
            continue
        parsed_interface = parseFtdShowInterfaceOutput(block)
        if parsed_interface.get("name"):
            interfaces.append(parsed_interface)
    return interfaces


def getFtdIdentityCandidates(req_body):
    candidates = []
    for candidate in (
        req_body.get("ftdDevName"),
        getFtdRegistrationIp(req_body),
        req_body.get("ftdPublicIp"),
        req_body.get("ftdPrivateIp"),
    ):
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    return candidates


def getFtdDeviceId(fmc, req_body):
    """
    Purpose:    Resolve an FMC FTD device by stable VMSS name first, then registration IP.
    Parameters: FMC object and Function request body
    Returns:    Device ID or ERROR
    Raises:
    """
    candidates = getFtdIdentityCandidates(req_body)
    for candidate in candidates:
        device_id = fmc.getDevIdByName(candidate, "FTD")
        if device_id != "ERROR":
            if candidate != req_body.get("ftdDevName"):
                log.info("util:::: Resolved FTD {} by alternate identity {}".format(req_body.get("ftdDevName"), candidate))
            return device_id

    log.warning("util:::: Unable to resolve FTD device from candidates {}".format(candidates))
    return "ERROR"


class FMC:
    def __init__(self):
        self.server = 'https://' + os.environ.get('FMC_IP')
        self.username = os.environ.get('FMC_USERNAME')
        self.password = os.environ.get('FMC_PASSWORD')
        self.headers = {}
        self.domain_uuid = os.environ.get("FMC_DOMAIN_UUID", "e276abec-e0f2-11e3-8169-6d9ed49b625f")
        self.authTokenTimestamp = 0
        self.authTokenMaxAge = 15*60  # seconds - 30 minutes is the max without using refresh
        self.accessPolicyName = os.environ.get('POLICY_NAME')

    # ======================================= REST methods ==========================================
    def _request_with_token_retry(self, request_method, url, **kwargs):
        r = request_method(url, headers=self.headers, verify=False, **kwargs)
        if r.status_code == 401:
            log.warning("FMC access token rejected, refreshing token and retrying request")
            r.close()
            self.getFmcAuthToken()
            r = request_method(url, headers=self.headers, verify=False, **kwargs)
        return r

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
        r = None
        try:
            # REST call with SSL verification turned off:
            #debug
            log.info("Request: " + url)
            r = self._request_with_token_retry(requests.get, url)
            status_code = r.status_code
            resp = r.text
            log.info("Response status_code: " + str(status_code))
            log.info("Response body: " + str(resp))
            if 200 <= status_code <= 300:
                # logging.debug("GET successful. Response data --> ")
                # json_resp = json.loads(resp)
                # logging.debug(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
                pass
            else:
                r.raise_for_status()
                raise Exception("Error occurred in Get -->"+resp)
        except requests.exceptions.HTTPError as err:
            raise Exception("Error in connection --> "+str(err))
        finally:
            if r:
                r.close()
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
        r = None
        try:
            # REST call with SSL verification turned off:
            log.info("Request: " + url)
            log.info("Post_data " + str(post_data))
            r = self._request_with_token_retry(requests.post, url, data=json.dumps(post_data))
            # REST call with SSL verification turned on:
            # r = requests.post(url,data=json.dumps(post_data), headers=self.headers, verify='/path/to/ssl_certificate')
            status_code = r.status_code
            resp = r.text
            log.info("Response status_code: " + str(status_code))
            log.info("Response body: " + str(resp))
            # logging.debug("Status code is: "+str(status_code))
            if 200 <= status_code <= 300:
                # json_resp = json.loads(resp)
                # logging.debug(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
                pass
            else:
                r.raise_for_status()
                raise Exception("Error occurred in POST --> "+resp)
        except requests.exceptions.HTTPError as err:
            response_body = ""
            if err.response is not None:
                response_body = err.response.text
            raise Exception("Error in connection --> {} {}".format(str(err), response_body))
        finally:
            if r:
                r.close()
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
        r = None
        try:
            # REST call with SSL verification turned off:
            log.info("Request: " + url)
            log.info("Put_data: " + str(put_data))
            r = self._request_with_token_retry(requests.put, url, data=json.dumps(put_data))
            # REST call with SSL verification turned on:
            # r = requests.put(url, data=json.dumps(put_data), headers=headers, verify='/path/to/ssl_certificate')
            status_code = r.status_code
            resp = r.text
            log.info("Response status_code: " + str(status_code))
            log.info("Response body: " + str(resp))
            if 200 <= status_code <= 300:
                pass
            else:
                r.raise_for_status()
                raise Exception("Error occurred in put -->" + resp)
        except requests.exceptions.HTTPError as err:
            raise Exception("Error in connection --> "+str(err))
        finally:
            if r:
                r.close()
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

        r = None
        try:
            # REST call with SSL verification turned off:
            log.debug("Request: " + url)
            r = self._request_with_token_retry(requests.delete, url)
            # REST call with SSL verification turned on:
            # r = requests.delete(url, headers=headers, verify='/path/to/ssl_certificate')
            status_code = r.status_code
            resp = r.text
            log.info("Response status_code: " + str(status_code))
            log.info("Response body: " + str(resp))
            if 200 <= status_code <= 300:
                # logging.debug("GET successful. Response data --> ")
                # json_resp = json.loads(resp)
                # logging.debug(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
                pass
            else:
                r.raise_for_status()
                raise Exception("Error occurred in Delete -->"+resp)
        except requests.exceptions.HTTPError as err:
            raise Exception("Error in connection --> "+str(err))
        finally:
            if r:
                r.close()
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
            # REST call with SSL verification turned on: Download SSL certificates
            # from your FMC first and provide its path for verification.
            # r = requests.post(auth_url, headers=self.headers,
            #                   auth=requests.auth.HTTPBasicAuth(username,password), verify='/path/to/ssl_certificate')
            log.info("FMC auth response status_code: " + str(r.status_code))
            if not 200 <= r.status_code <= 204:
                r.raise_for_status()
                raise Exception("FMC authentication failed")

            auth_headers = r.headers
            auth_token = auth_headers.get('X-auth-access-token')
            domain_uuid = auth_headers.get('DOMAIN_UUID') or auth_headers.get('domain_uuid')
            if domain_uuid:
                self.domain_uuid = domain_uuid

            if auth_token is None:
                raise Exception("FMC authentication succeeded but access token was not returned")

            self.headers['X-auth-access-token'] = auth_token
            self.authTokenTimestamp = int(time.time())
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
                if item.get('name') == name or item.get('ifname') == name:
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
                if item.get('name') == name or (cmd == "FTD" and item.get('hostName') == name):
                    return str(item['id'])
        # or return empty string
        return "ERROR"

    def getPhysicalInterfaces(self, device_id):
        """
        Purpose:    Get all physical interfaces for an FMC device record.
        Parameters: Device ID
        Returns:    Physical interface item list
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/" + self.domain_uuid + "/devices/devicerecords/" + device_id + "/physicalinterfaces"
        url = self.server + api_path + '?expanded=true&offset=0&limit=10000'
        r = self.rest_get(url)
        if not (200 <= r.status_code <= 300):
            log.error("util:::: Failed to get physical interfaces for {}".format(device_id))
            return []
        return r.json().get("items", [])

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
        api_path = "/api/fmc_config/v1/domain/" + self.domain_uuid + "/devicegroups/devicegrouprecords"
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

    def fmcGetNetworkObjectId(self, objName):
        """
        Purpose:    Get Network Object Id by Name (from /object/networks endpoint)
        Parameters: Object Name
        Returns:    Object Id or ERROR
        Raises:
        """
        log.info("util:::: Getting Network object {} ID".format(objName))
        url = self.server + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/object/networks?offset=0&limit=1000"
        r = self.rest_get(url)

        if r.status_code == 200 and 'items' in r.json():
            for item in r.json()['items']:
                if item['name'] == objName:
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
            # api_path = '/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/'
            # api_suffix = '/operational/metrics?filter=metric%3Amemory&offset=0&limit=1&expanded=true'
            # url = self.server + api_path + device_id + api_suffix

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

        if self.getObjIdByName(objName, "HOST") != "ERROR":
            log.info("util:::: Host object {} already exists".format(objName))
            return "SUCCESS"

        try:
            r = self.rest_post(url, post_data)
        except Exception as e:
            log.error("util:::: Failed to create HOST Object {}: {}".format(objName, e))
            return "ERROR"
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

        if self.getObjIdByName(objName, "NETWORK") != "ERROR":
            log.info("util:::: Network object {} already exists".format(objName))
            return "SUCCESS"

        try:
            r = self.rest_post(url, post_data)
        except Exception as e:
            log.error("util:::: Failed to create Network Object {}: {}".format(objName, e))
            return "ERROR"
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

    def fmcCreateHostRoutes(self, device_id, interface_name, _object_name, _object_id, gateway_name, gateway_id, metric, selected_network_type="Host"):
        """
        Purpose:    To create static route on device
        Parameters: Device, Interface Name, Host, Gateway, Metric
        Returns:    SUCCESS or ERROR
        Raises:
        """

        api_path = "/api/fmc_config/v1/domain/"+ self.domain_uuid +"/devices/devicerecords/" + device_id + "/routing/ipv4staticroutes"
        url = self.server + api_path

        def route_exists():
            try:
                r = self.rest_get(url + "?expanded=true&offset=0&limit=1000")
                routes = r.json().get("items", [])
            except Exception as e:
                log.info("util:::: Failed to check existing Host Route {}:{}: {}".format(_object_name, gateway_id, e))
                return False

            for route in routes:
                selected_networks = route.get("selectedNetworks", [])
                gateway_object = route.get("gateway", {}).get("object", {})
                if (
                    route.get("interfaceName") == interface_name
                    and str(route.get("metricValue")) == str(metric)
                    and gateway_object.get("id") == gateway_id
                    and any(
                        network.get("id") == _object_id
                        and network.get("type") == selected_network_type
                        for network in selected_networks
                    )
                ):
                    return True
            return False

        if route_exists():
            log.info("util:::: Host Route already exists for {}:{}".format(_object_name, gateway_id))
            return "SUCCESS"

        post_data = {
            "interfaceName": interface_name,
            "selectedNetworks": [
                {
                    "type": selected_network_type,
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
        try:
            r = self.rest_post(url, post_data)
        except Exception as e:
            log.error("util:::: Failed to create Host Route {}:{}: {}".format(_object_name, gateway_id, e))
            return "ERROR"
        if 201 <= r.status_code <= 202:
            return "SUCCESS"
        elif route_exists():
            log.info("util:::: Host Route already exists after create attempt for {}:{}".format(_object_name, gateway_id))
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

# ======================================================================================================   
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

    def fmcCreatePlatformSettingsPolicy(self, rule_name):
        """
        Purpose:    To create a Platform Settings Policy
        Parameters: rule_name - Name for the platform settings policy
        Returns:    UUID of created policy or ERROR
        Raises:
        """
        existing_policy_id = self.fmcGetPlatformSettingsPolicyId(rule_name)
        if existing_policy_id != "ERROR":
            log.info("util:::: Platform Settings Policy already exists: {}".format(rule_name))
            return existing_policy_id

        url = self.server + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/policy/ftdplatformsettingspolicies"
        post_data = {
            "type": "FTDPlatformSettingsPolicy",
            "name": rule_name,
            "description": "Platform Settings for Health Check"
        }
        log.info("util:::: Creating Platform Settings Policy: {}".format(rule_name))

        try:
            r = self.rest_post(url, post_data)
        except Exception as e:
            existing_policy_id = self.fmcGetPlatformSettingsPolicyId(rule_name)
            if existing_policy_id != "ERROR":
                log.info("util:::: Platform Settings Policy already exists after create attempt: {}".format(rule_name))
                return existing_policy_id
            log.error("util:::: Failed to create Platform Settings Policy: {}: {}".format(rule_name, e))
            return "ERROR"

        if 200 <= r.status_code <= 202:
            try:
                return r.json().get('id', 'ERROR')
            except:
                return "ERROR"
        else:
            log.error("util:::: Failed to create Platform Settings Policy: {} .. probably already existing".format(rule_name))
            return "ERROR"

    def fmcGetPlatformSettingsPolicyId(self, policy_name):
        """
        Purpose:    Get Platform Settings Policy Id by name
        Parameters: policy_name - Name of the platform settings policy
        Returns:    Policy Id or ERROR
        Raises:
        """
        url = self.server + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/policy/ftdplatformsettingspolicies"
        url = url + '?offset=0&limit=1000'
        log.info("util:::: Getting Platform Settings Policy ID for: {}".format(policy_name))

        r = self.rest_get(url)
        if r.status_code == 200:
            try:
                if 'items' in r.json():
                    for item in r.json()['items']:
                        if item['name'] == policy_name:
                            return str(item['id'])
            except:
                pass
        return "ERROR"

    def fmcUpdatePlatformSettingsHttpAccess(self, policy_id, port, inside_zone_id, outside_zone_id, inside_zone_name="inside", outside_zone_name="outside"):
        """
        Purpose:    To update platform settings with HTTP access for health check using public API
        Parameters: policy_id - Platform settings policy ID
                    port - Health check port number
                    inside_zone_id - Inside security zone ID
                    outside_zone_id - Outside security zone ID
                    inside_zone_name - Inside security zone name
                    outside_zone_name - Outside security zone name
        Returns:    SUCCESS or ERROR
        Raises:
        """
        any_ipv4_id = self.fmcGetNetworkObjectId("any-ipv4")
        if any_ipv4_id == "ERROR":
            log.error("util:::: Failed to get any-ipv4 network object ID")
            return "ERROR"

        interface_objects = []
        if inside_zone_id:
            interface_objects.append({
                "name": inside_zone_name,
                "id": inside_zone_id,
                "type": "SecurityZone"
            })
        if outside_zone_id:
            interface_objects.append({
                "name": outside_zone_name,
                "id": outside_zone_id,
                "type": "SecurityZone"
            })
        if not interface_objects:
            log.error("util:::: No security zones provided for HTTP Access Settings")
            return "ERROR"

        http_configuration = [
            {
                "ipAddress": {
                    "name": "any-ipv4",
                    "id": any_ipv4_id,
                    "type": "Network"
                },
                "interfaces": {
                    "objects": interface_objects
                }
            }
        ]

        url = self.server + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/policy/ftdplatformsettingspolicies/" + policy_id + "/httpaccesssettings/" + policy_id
        payload = {
            "id": policy_id,
            "enableHttpServer": True,
            "port": int(port),
            "httpConfiguration": http_configuration
        }

        log.info("util:::: Updating Platform Settings HTTP Access with public API on port: {}".format(port))
        r = self.rest_put(url, payload)
        if 200 <= r.status_code <= 202:
            log.info("util:::: Successfully updated HTTP Access Settings with zones and network")
            return "SUCCESS"
        else:
            log.error("util:::: Failed to update HTTP Access Settings: {}".format(r.text))
            return "ERROR"

    def fmcAssignPlatformSettingsToDeviceGroup(self, policy_id, policy_name, target_id, target_type="DeviceGroup"):
        """
        Purpose:    To assign platform settings policy to a device group
        Parameters: policy_id - Platform settings policy ID
                    policy_name - Platform settings policy name
                    target_id - Device group ID
                    target_type - Type of target
        Returns:    SUCCESS or ERROR
        Raises:
        """
        url = self.server + "/api/fmc_config/v1/domain/" + self.domain_uuid + "/assignment/policyassignments"

        def get_policy_assignment():
            try:
                r = self.rest_get(url + "?expanded=true&offset=0&limit=1000")
                assignments = r.json().get("items", [])
            except Exception as e:
                log.info("util:::: Failed to check existing Platform Settings assignment: {}".format(e))
                return None

            for assignment in assignments:
                policy = assignment.get("policy", {})
                if policy.get("id") == policy_id:
                    return assignment
            return None

        def target_matches(target):
            return target.get("id") == target_id and target.get("type") == target_type

        def target_payload(target=None):
            payload = {
                "id": (target or {}).get("id", target_id),
                "type": (target or {}).get("type", target_type)
            }
            if (target or {}).get("name"):
                payload["name"] = target.get("name")
            return payload

        def update_assignment(assignment, keep_existing_targets=True):
            assignment_id = assignment.get("id") or policy_id
            existing_targets = assignment.get("targets", []) if keep_existing_targets else []
            merged_targets = []
            seen_targets = set()

            for target in existing_targets:
                if not target.get("id") or not target.get("type"):
                    continue
                target_key = (target.get("id"), target.get("type"))
                if target_key in seen_targets:
                    continue
                seen_targets.add(target_key)
                merged_targets.append(target_payload(target))

            target_key = (target_id, target_type)
            if target_key not in seen_targets:
                merged_targets.append(target_payload())

            put_data = {
                "id": assignment_id,
                "type": assignment.get("type", "PolicyAssignment"),
                "policy": assignment.get("policy") or {
                    "type": "FTDPlatformSettingsPolicy",
                    "id": policy_id,
                    "name": policy_name
                },
                "targets": merged_targets
            }

            log.info("util:::: Updating Platform Settings Policy assignment {} for {} ({})".format(assignment_id, target_type, target_id))
            r = self.rest_put(url + "/" + assignment_id, put_data)
            if 200 <= r.status_code <= 202:
                return "SUCCESS"
            log.error("util:::: Failed to update Platform Settings assignment: {}".format(r.text))
            return "ERROR"

        assignment = get_policy_assignment()
        if assignment:
            targets = assignment.get("targets", [])
            if any(target_matches(target) for target in targets):
                log.info("util:::: Platform Settings Policy already assigned to {} ({})".format(target_type, target_id))
                return "SUCCESS"
            try:
                return update_assignment(assignment, keep_existing_targets=True)
            except Exception as e:
                log.error("util:::: Failed to merge Platform Settings assignment targets: {}".format(e))
                try:
                    return update_assignment(assignment, keep_existing_targets=False)
                except Exception as retry_error:
                    log.error("util:::: Failed to repair Platform Settings assignment targets: {}".format(retry_error))
                    return "ERROR"

        post_data = {
            "type": "PolicyAssignment",
            "policy": {
                "type": "FTDPlatformSettingsPolicy",
                "id": policy_id,
                "name": policy_name
            },
            "targets": [
                {
                    "id": target_id,
                    "type": target_type
                }
            ]
        }
        log.info("util:::: Assigning Platform Settings Policy {} to {} ({})".format(policy_name, target_type, target_id))

        try:
            r = self.rest_post(url, post_data)
        except Exception as e:
            assignment = get_policy_assignment()
            if assignment:
                try:
                    return update_assignment(assignment, keep_existing_targets=True)
                except Exception as retry_error:
                    log.error("util:::: Failed to repair Platform Settings assignment after create attempt: {}".format(retry_error))
            log.error("util:::: Failed to assign Platform Settings: {}".format(e))
            return "ERROR"

        if 200 <= r.status_code <= 202:
            log.info("util:::: Successfully assigned Platform Settings Policy")
            return "SUCCESS"
        elif r.status_code == 406 and "already has some assignments" in r.text:
            log.info("util:::: Policy already has assignments, trying PUT to update...")
            assignment = get_policy_assignment()
            if assignment:
                try:
                    return update_assignment(assignment, keep_existing_targets=True)
                except Exception as e:
                    log.error("util:::: Failed to update existing Platform Settings assignment: {}".format(e))
                    try:
                        return update_assignment(assignment, keep_existing_targets=False)
                    except Exception as retry_error:
                        log.error("util:::: Failed to repair existing Platform Settings assignment: {}".format(retry_error))
                        return "ERROR"
            log.info("util:::: Policy assignment already exists but could not be fetched")
            return "ERROR"
        else:
            log.error("util:::: Failed to assign Platform Settings: {}".format(r.text))
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
            ssh_stdin, ssh_stdout, ssh_stderr = self.ssh.exec_command(command, timeout=30, get_pty=True)
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

    def execute_interactive_cmd(self, command, wait_string='>'):
        """
        Purpose:    Performs a command through an interactive shell.
        Parameters: Command
        Returns:    action status, output & error
        """
        if self.connect(self.username, self.password) != self.SUCCESS:
            raise ValueError("Unable to connect to server")
        try:
            status, shell = self.invoke_interactive_shell()
            if status != self.SUCCESS:
                return self.FAIL, None, None
            self.send_cmd_and_wait_for_execution(shell, '\n', wait_string)
            output = self.send_cmd_and_wait_for_execution(shell, command + '\n', wait_string)
        except paramiko.SSHException as exc:
            log.error("Exception occurred: {}".format(repr(exc)))
            self.ssh.close()
            return self.FAIL, None, None
        finally:
            self.ssh.close()

        if output is None:
            return self.FAIL, None, None
        return self.SUCCESS, output, ""

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
        command_marker = command.strip()
        deadline = time.time() + self.timeout
        try:
            shell.send(command)
            while time.time() < deadline:
                rcv_buffer += shell.recv(10000).decode("utf-8", errors="ignore")
                if wait_string not in rcv_buffer:
                    continue
                if not command_marker:
                    return rcv_buffer
                if command_marker in rcv_buffer or len(rcv_buffer.strip()) > len(wait_string):
                    return rcv_buffer
            log.error("Timed out waiting for command output: {}".format(command_marker))
            return None
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
            status, output, error = connect.execute_interactive_cmd("show managers")
            connect.close()
        except Exception as e:
            log.error("Error occurred: {}".format(repr(e)))
            return "UNAVAILABLE"

        if status == self.SUCCESS and (
            lookFor in output
            or "Completed" in output
            or "No managers configured" in output
        ):
            return "AVAILABLE"
        else:
            log.warning("util:::: Unable to run command output: {} error: {}".format(output, error))
            return "UNAVAILABLE"

    def ftdSshConfigureManager(self, ftdIp, managerHost, regKey, natId):
        def get_manager_field(output, field_name):
            for line in output.splitlines():
                if line.strip().lower().startswith(field_name.lower() + ":"):
                    return line.split(":", 1)[1].strip()
            return ""

        try:
            connect = ParamikoSSH(ftdIp, self.port, self.ftdUserName, self.ftdPassword)
        except:
            log.error("util:::: SSH exception")
            return "ERROR"

        try:
            status, output, error = connect.execute_interactive_cmd("show managers")
            connect.close()
        except Exception as e:
            log.error("util:::: Error checking FTD manager before add: {}".format(repr(e)))
            return "ERROR"

        if status == self.SUCCESS:
            manager_output = output.lower()
            expected_host = (managerHost or "").lower()
            expected_nat_id = (natId or "").lower()
            if "registration" in manager_output and "completed" in manager_output:
                log.info("util:::: FTD manager is already registered. output: {}".format(output))
                return "SUCCESS"
            if expected_host in manager_output and expected_nat_id in manager_output:
                if "pending" in manager_output:
                    log.info("util:::: FTD manager is configured but registration is still pending. output: {}".format(output))
                    return "PENDING"
                log.info("util:::: FTD manager already configured with host {} and NAT ID {}".format(managerHost, natId))
                return "SUCCESS"

            old_host = get_manager_field(output, "Host")
            old_nat_id = get_manager_field(output, "Identifier")
            if old_host or old_nat_id:
                log.info("util:::: Existing FTD manager differs from expected host {} NAT ID {}; reconfiguring. output: {}".format(managerHost, natId, output))
                try:
                    connect = ParamikoSSH(ftdIp, self.port, self.ftdUserName, self.ftdPassword)
                    connect.execute_cmd("configure manager delete")
                    connect.close()
                except Exception as e:
                    log.error("util:::: Unable to delete existing FTD manager before add: {}".format(repr(e)))
                    return "ERROR"
        else:
            log.info("util:::: Unable to inspect current manager output: {} error: {}".format(output, error))

        try:
            connect = ParamikoSSH(ftdIp, self.port, self.ftdUserName, self.ftdPassword)
            cmd = "configure manager add {} {} {}".format(managerHost, regKey, natId)
            status, output, error = connect.execute_interactive_cmd(cmd)
            connect.close()
        except Exception as e:
            log.error("util:::: Error configuring FTD manager: {}".format(repr(e)))
            return "ERROR"

        if status == self.SUCCESS and "successfully configured" in output.lower():
            log.info("util:::: FTD manager configured with host {} and NAT ID {}".format(managerHost, natId))
            return "PENDING"
        if "manager with this name is already added" in str(output).lower():
            log.info("util:::: FTD manager {} is already configured; waiting for registration to complete".format(managerHost))
            return "PENDING"

        log.error("util:::: Failed to configure FTD manager output: {} error: {}".format(output, error))
        return "ERROR"

    def ftdSshShowInterface(self, ftdIp, interface_name):
        interface_command = getFtdShowInterfaceCommandName(interface_name)
        try:
            connect = ParamikoSSH(ftdIp, self.port, self.ftdUserName, self.ftdPassword)
            status, output, error = connect.execute_interactive_cmd("show interface {}".format(interface_command))
            connect.close()
        except Exception as e:
            log.error("util:::: Error showing FTD interface {}: {}".format(interface_name, repr(e)))
            return self.FAIL, "", repr(e)

        normalized_output = (output or "").lower()
        normalized_error = (error or "").lower()
        if (
            status != self.SUCCESS
            or "syntax error" in normalized_output
            or "illegal command line" in normalized_output
            or "syntax error" in normalized_error
            or "illegal command line" in normalized_error
        ):
            log.error("util:::: Unable to show interface {} output: {} error: {}".format(interface_name, output, error))
            return self.FAIL, output, error

        return self.SUCCESS, output, error

    def ftdSshShowInterfaces(self, ftdIp):
        try:
            connect = ParamikoSSH(ftdIp, self.port, self.ftdUserName, self.ftdPassword)
            status, output, error = connect.execute_interactive_cmd("show interface")
            connect.close()
        except Exception as e:
            log.error("util:::: Error showing FTD interfaces: {}".format(repr(e)))
            return self.FAIL, "", repr(e)

        normalized_output = (output or "").lower()
        normalized_error = (error or "").lower()
        if (
            status != self.SUCCESS
            or "syntax error" in normalized_output
            or "illegal command line" in normalized_output
            or "syntax error" in normalized_error
            or "illegal command line" in normalized_error
        ):
            log.error("util:::: Unable to show FTD interfaces output: {} error: {}".format(output, error))
            return self.FAIL, output, error

        return self.SUCCESS, output, error

    def ftdSshValidateInterface(self, ftdIp, interface_name, ifname=None):
        if not interface_name:
            log.info("util:::: No interface name supplied for validation")
            return self.SUCCESS

        interface_commands = [getFtdShowInterfaceCommandName(interface_name)]
        if interface_name not in interface_commands:
            interface_commands.append(interface_name)

        expected_ifname = (ifname or "").lower()
        failed_markers = (
            "administratively down",
            "available but not configured via nameif",
            "mtu not set",
        )

        for attempt in range(1, 7):
            try:
                connect = ParamikoSSH(ftdIp, self.port, self.ftdUserName, self.ftdPassword)
                validation_results = []
                for interface_command in interface_commands:
                    status, output, error = connect.execute_interactive_cmd("show interface {}".format(interface_command))
                    validation_results.append((interface_command, status, output, error))
                    normalized_output = (output or "").lower()
                    normalized_error = (error or "").lower()
                    if (
                        status == self.SUCCESS
                        and "syntax error" not in normalized_output
                        and "illegal command line" not in normalized_output
                        and "syntax error" not in normalized_error
                        and "illegal command line" not in normalized_error
                    ):
                        break
            except Exception as e:
                log.error("util:::: Error validating FTD interface {}: {}".format(interface_name, repr(e)))
                status, output, error = self.FAIL, "", repr(e)
                validation_results = []
            finally:
                try:
                    connect.close()
                except Exception:
                    pass

            if status != self.SUCCESS:
                log.error("util:::: Failed to validate interface {} output: {} error: {}".format(interface_command, output, error))
            else:
                normalized_output = (output or "").lower()
                normalized_error = (error or "").lower()
                if (
                    "syntax error" in normalized_output
                    or "illegal command line" in normalized_output
                    or "syntax error" in normalized_error
                    or "illegal command line" in normalized_error
                ):
                    log.error("util:::: Unable to show interface {}. Tried: {}".format(interface_name, validation_results))
                elif any(marker in normalized_output for marker in failed_markers):
                    log.error("util:::: Interface {} failed validation: {}".format(interface_name, output))
                elif expected_ifname and expected_ifname not in normalized_output:
                    log.error("util:::: Interface {} does not show ifname {}: {}".format(interface_name, ifname, output))
                else:
                    log.info("util:::: Interface {} validation passed".format(interface_name))
                    return self.SUCCESS

            if attempt < 6:
                log.info("util:::: Retrying interface {} validation; attempt {}/6".format(interface_name, attempt + 1))
                time.sleep(10)

        log.error("util:::: Interface {} validation failed after retries".format(interface_name))
        return self.FAIL
        
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


def resolveFmcInterfaceForAzureNic(fmc, device_id, req_body, azure_nic_name, role_name):
    """
    Purpose:    Resolve the FMC physical interface matching an Azure VMSS NIC.
    Parameters: FMC client, device ID, request body, Azure NIC name, role label
    Returns:    FMC physical interface item or None
    Raises:
    """
    ftdv_name = req_body.get("ftdDevName")
    azure_nic = getVmssNicInfo(ftdv_name, azure_nic_name)
    if not azure_nic:
        return None

    ftd_ips = getFtdSshIps(req_body)
    physical_interfaces = fmc.getPhysicalInterfaces(device_id)
    if not physical_interfaces:
        log.error("util:::: No FMC physical interfaces found for {}".format(ftdv_name))
        return None

    ftd_ssh_client = FtdSshClient()
    physical_interfaces_by_name = {
        interface.get("name"): interface
        for interface in physical_interfaces
        if interface.get("name")
    }
    bulk_observed_interfaces = []
    for ftd_ip in ftd_ips:
        status, output, error = ftd_ssh_client.ftdSshShowInterfaces(ftd_ip)
        if status != ftd_ssh_client.SUCCESS:
            bulk_observed_interfaces.append({
                "ip": ftd_ip,
                "error": error,
            })
            continue

        parsed_interfaces = parseFtdShowInterfacesOutput(output)
        bulk_observed_interfaces.extend([
            {
                "ip": ftd_ip,
                "name": parsed_interface.get("name"),
                "mac": parsed_interface.get("mac"),
                "ip_address": parsed_interface.get("ip"),
            }
            for parsed_interface in parsed_interfaces
        ])
        for parsed_interface in parsed_interfaces:
            if azure_nic.get("normalized_mac") and parsed_interface.get("normalized_mac") == azure_nic.get("normalized_mac"):
                matched_interface = physical_interfaces_by_name.get(parsed_interface.get("name"))
                if matched_interface:
                    log.info(
                        "util:::: Mapped Azure {} NIC {} to FMC interface {} by bulk MAC {}".format(
                            role_name, azure_nic_name, parsed_interface.get("name"), azure_nic.get("mac")
                        )
                    )
                    return matched_interface

                log.error(
                    "util:::: Matched Azure {} NIC {} to FTD interface {} by MAC, but FMC has no matching physical interface item".format(
                        role_name, azure_nic_name, parsed_interface.get("name")
                    )
                )

    observed_interfaces = []
    ip_fallback_match = None

    for interface in physical_interfaces:
        interface_name = interface.get("name")
        interface_id = interface.get("id")
        if not interface_name or not interface_id:
            continue

        status, output, error = ftd_ssh_client.FAIL, "", ""
        for ftd_ip in ftd_ips:
            status, output, error = ftd_ssh_client.ftdSshShowInterface(ftd_ip, interface_name)
            if status == ftd_ssh_client.SUCCESS:
                break
        if status != ftd_ssh_client.SUCCESS:
            observed_interfaces.append({
                "name": interface_name,
                "id": interface_id,
                "error": error,
            })
            continue

        parsed_interface = parseFtdShowInterfaceOutput(output)
        observed_interfaces.append({
            "name": interface_name,
            "id": interface_id,
            "mac": parsed_interface.get("mac"),
            "ip": parsed_interface.get("ip"),
        })

        if azure_nic.get("normalized_mac") and parsed_interface.get("normalized_mac") == azure_nic.get("normalized_mac"):
            log.info(
                "util:::: Mapped Azure {} NIC {} to FMC interface {} by MAC {}".format(
                    role_name, azure_nic_name, interface_name, azure_nic.get("mac")
                )
            )
            return interface

        if azure_nic.get("private_ip") and parsed_interface.get("ip") == azure_nic.get("private_ip"):
            ip_fallback_match = interface

    if ip_fallback_match:
        log.info(
            "util:::: Mapped Azure {} NIC {} to FMC interface {} by IP {}".format(
                role_name, azure_nic_name, ip_fallback_match.get("name"), azure_nic.get("private_ip")
            )
        )
        return ip_fallback_match

    log.error(
        "util:::: Failed to map Azure {} NIC {} for {}. Azure NIC: {}. Bulk FTD interfaces: {}. FMC interface probes: {}".format(
            role_name, azure_nic_name, ftdv_name, azure_nic, bulk_observed_interfaces, observed_interfaces
        )
    )
    return None


def validateFtdInterfaceDeployment(fmc, device_id, req_body, azure_nic_name, expected_ifname):
    if not expected_ifname:
        log.info("util:::: Interface validation skipped; expected ifname is missing")
        return "SUCCESS"

    outside_interface = resolveFmcInterfaceForAzureNic(
        fmc, device_id, req_body, azure_nic_name, expected_ifname
    )
    if outside_interface is None:
        log.error("util:::: Failed to map Azure {} NIC to FMC interface for validation".format(azure_nic_name))
        return "ERROR"

    fmc_interface_name = outside_interface.get("name")
    ftd_ssh_client = FtdSshClient()
    for candidate_ip in getFtdSshIps(req_body):
        if ftd_ssh_client.ftdSsh(candidate_ip, "Completed") != "AVAILABLE":
            continue

        return ftd_ssh_client.ftdSshValidateInterface(
            candidate_ip, fmc_interface_name, expected_ifname
        )

    log.error("util:::: Unable to SSH to FTD for interface validation")
    return "ERROR"
