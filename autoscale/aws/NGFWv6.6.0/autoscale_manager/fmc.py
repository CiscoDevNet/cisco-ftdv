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
import time
import requests
import logging
import json
import utility as utl
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
"""
Name:       fmc
Purpose:    This is contains fmc related REST methods
"""
# Setup Logging
logger = utl.setup_logging(utl.e_var['DebugDisable'])


class FirepowerManagementCenter:
    def __init__(self):
        self.server = 'https://' + utl.e_var['FmcIp']
        self.username = utl.e_var['FmcUserName']
        self.password = utl.e_var['FmcPassword']
        self.headers = []
        self.domain_uuid = ""
        self.authTokenTimestamp = 0
        self.authTokenMaxAge = 15*60  # seconds - 30 minutes is the max without using refresh
        self.accessPolicyName = utl.j_var['AccessPolicyName']

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
            logging.debug("Getting a new authToken")
            self.get_auth_token()
        try:
            # REST call with SSL verification turned off:
            logging.debug("Request: " + url)
            r = requests.get(url, headers=self.headers, verify=False)
            # REST call with SSL verification turned on:
            # r = requests.get(url, headers=headers, verify='/path/to/ssl_certificate')
            status_code = r.status_code
            resp = r.text
            logging.debug("Response status_code: " + str(status_code))
            logging.debug("Response body: " + str(resp))
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
            logging.debug("Getting a new authToken")
            self.get_auth_token()
        try:
            # REST call with SSL verification turned off:
            logging.debug("Request: " + url)
            logging.debug("Post_data " + str(post_data))
            r = requests.post(url, data=json.dumps(post_data), headers=self.headers, verify=False)
            # REST call with SSL verification turned on:
            # r = requests.post(url,data=json.dumps(post_data), headers=self.headers, verify='/path/to/ssl_certificate')
            status_code = r.status_code
            resp = r.text
            logging.info("Response status_code: " + str(status_code))
            logging.info("Response body: " + str(resp))
            # logging.debug("Status code is: "+str(status_code))
            if 201 <= status_code <= 202:
                # json_resp = json.loads(resp)
                # logging.debug(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
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
            logging.debug("Getting a new authToken")
            self.get_auth_token()
        try:
            # REST call with SSL verification turned off:
            logging.info("Request: " + url)
            logging.info("Put_data: " + str(put_data))
            r = requests.put(url, data=json.dumps(put_data), headers=self.headers, verify=False)
            # REST call with SSL verification turned on:
            # r = requests.put(url, data=json.dumps(put_data), headers=headers, verify='/path/to/ssl_certificate')
            status_code = r.status_code
            resp = r.text
            logging.info("Response status_code: " + str(status_code))
            logging.info("Response body: " + str(resp))
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
            logging.debug("Getting a new authToken")
            self.get_auth_token()

        try:
            # REST call with SSL verification turned off:
            logging.debug("Request: " + url)
            r = requests.delete(url, headers=self.headers, verify=False)
            # REST call with SSL verification turned on:
            # r = requests.delete(url, headers=headers, verify='/path/to/ssl_certificate')
            status_code = r.status_code
            resp = r.text
            logging.info("Response status_code: " + str(status_code))
            logging.info("Response body: " + str(resp))
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
            if r: r.close()
            return r

    def get_auth_token(self):
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
            # The one with "SSL verification turned off" is commented out. If you like to use that then
            # uncomment the line where verify=False and comment the line with =verify='/path/to/ssl_certificate'
            # REST call with SSL verification turned off:
            r = requests.post(auth_url, headers=self.headers,
                              auth=requests.auth.HTTPBasicAuth(self.username, self.password), verify=False)
            # REST call with SSL verification turned on: Download SSL certificates
            # from your FMC first and provide its path for verification.
            # r = requests.post(auth_url, headers=self.headers,
            #                   auth=requests.auth.HTTPBasicAuth(username,password), verify='/path/to/ssl_certificate')
            auth_headers = r.headers
            auth_token = auth_headers.get('X-auth-access-token', default=None)
            self.domain_uuid = auth_headers.get('domain_uuid', default=None)
            self.headers['X-auth-access-token'] = auth_token
            self.authTokenTimestamp = int(time.time())
            # logging.debug("Acquired AuthToken: " + auth_token)
            # logging.debug("domain_uuid: " + domain_uuid)
            if auth_token is None:
                logging.debug("auth_token not found. Exiting...")
                # raise Exception("Error occurred in get auth token ")
        except Exception as err:
            logger.error("Error in generating auth token --> " + str(err))
        return

    def get_device_grp_id_by_name(self, name):
        """
        Purpose:    To get device group id by passing name of the group
        Parameters: Name of device group
        Returns:    Group Id or None
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devicegroups/devicegrouprecords"
        url = self.server + api_path + '?offset=0&limit=9000'
        r = self.rest_get(url)
        if 'items' in r.json():
            for item in r.json()['items']:
                if item['name'] == name:
                    return str(item['id'])
        return None

    def get_security_objectid_by_name(self, name):
        """
        Purpose:    Get Zone ID from it's name
        Parameters: Zone Name
        Returns:    Zone ID, None
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/securityzones"
        url = self.server + api_path + '?offset=0&limit=9000'
        r = self.rest_get(url)
        if 'items' in r.json():
            for item in r.json()['items']:
                if item['name'] == name:
                    return str(item['id'])
        return None

    # Get network objects (all network and host objects)
    def get_network_objectid_by_name(self, name):
        """
        Purpose:    Get Network object Id by its name
        Parameters: Object Name
        Returns:    Object Id
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkaddresses"
        url = self.server + api_path + '?offset=0&limit=10000'
        r = self.rest_get(url)
        for item in r.json()['items']:
            if item['type'] == 'Network' and item['name'] == name:
                return str(item['id'])
        # raise Exception('network object with name ' + name + ' was not found')
        return ''

    def get_port_objectid_by_name(self, name):
        """
        Purpose:    Get Port object Id by its name
        Parameters: Object Name
        Returns:    Object Id
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/protocolportobjects"
        url = self.server + api_path + '?offset=0&limit=10000'
        r = self.rest_get(url)
        for item in r.json()['items']:
            if item['type'] == 'ProtocolPortObject' and item['name'] == name:
                return str(item['id'])
        # raise Exception('network port with name ' + name + ' was not found')
        return ''

    def get_host_objectid_by_name(self, name):
        """
        Purpose:    Get Host object Id by Name
        Parameters: Object Name
        Returns:    Object Id
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/hosts"
        url = self.server + api_path + '?offset=0&limit=10000'
        r = self.rest_get(url)
        for item in r.json()['items']:
            if item['type'] == 'Host' and item['name'] == name:
                return str(item['id'])
        # raise Exception('host object with name ' + name + ' was not found')
        return ''

    def get_device_id_by_name(self, name):
        """
        Purpose:    Get Device Id by its name
        Parameters: Device Name
        Returns:    Device Id
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords"
        url = self.server + api_path + '?offset=0&limit=10000'
        r = self.rest_get(url)
        if 'items' in r.json():
            for item in r.json()['items']:
                if item['name'] == name:
                    return str(item['id'])
        # or return empty string
        return ''

    def get_access_policy_id_by_name(self, name):
        """
        Purpose:    Get Access Policy Id by its name
        Parameters: Access policy name
        Returns:    Access Policy Id, None
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies"
        url = self.server + api_path + '?offset=0&limit=10000'
        r = self.rest_get(url)
        # Search for policy by name
        if 'items' in r.json():
            for item in r.json()['items']:
                if item['name'] == name:
                    return str(item['id'])
        return None

    def get_nic_id_by_name(self, device_name, nic_name):
        """
        Purpose:    Get Nic Id by device & nic name
        Parameters: Device Name, Nic name
        Returns:    Nic Id, None
        Raises:
        """
        if nic_name != 'GigabitEthernet0/0' and nic_name != 'GigabitEthernet0/1':
            logging.debug("warning - nic name must be GigabitEthernet0/0 or GigabitEthernet0/1. "
                          "The argument name was " + nic_name)
        device_id = self.get_device_id_by_name(device_name)
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + \
                   device_id + "/physicalinterfaces"
        url = self.server + api_path
        r = self.rest_get(url)
        if 'items' in r.json():
            for item in r.json()['items']:
                if item['name'] == nic_name:
                    return str(item['id'])
        return None

    def get_time_stamp(self):
        """
        Purpose:    Get time stamp
        Parameters:
        Returns:    Audit time stamp
        Raises:
        """
        api_path = "/api/fmc_platform/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/audit/auditrecords"
        url = self.server + api_path
        r = self.rest_get(url)
        return r.json()['items'][0]['time']*1000

    def get_deployable_devices(self):
        """
        Purpose:    Get list of deployable devices
        Parameters:
        Returns:    List of devices, pending to be deployed
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/deployment/deployabledevices"
        url = self.server + api_path
        r = self.rest_get(url)
        logging.debug("deployable devices:" + str(r.json()))
        device_list = []
        if 'items' in r.json():
            for item in r.json()['items']:
                if item['type'] == 'DeployableDevice':
                    device_list.append(item['name'])
        return device_list

    def get_nic_status(self, device_id, nic, nic_id, ifname, zone_id, ip=None):
        """
        Purpose:    To check whether Nic is configured or not configured
        Parameters: Device Id, Nic, Nic Id, Interface Name, Zone Id, Ip
        Returns:    CONFIGURED, MIS-CONFIGURED, UN-CONFIGURED
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + \
                   device_id + "/physicalinterfaces/" + nic_id
        url = self.server + api_path
        r = self.rest_get(url)
        flag1, flag2 = 0, 0
        try:
            if 'ipv4' in r.json():
                item = dict.copy(r.json()['ipv4']['static'])
                if item['address'] == ip:
                    flag1 = 1
        except:
            try:
                if 'ipv4' in r.json():
                    item = dict.copy(r.json()['ipv4']['dhcp'])
                    flag1 = 1
            except:
                flag1 = 0
        try:
            if r.json()['name'] == nic:
                if r.json()['ifname'] == ifname:
                    flag2 = 1
            if r.json()['securityZone']['id'] != zone_id:
                flag2 = 0
        except:
            flag2 = 0

        if flag1 == 1 and flag2 == 1:
            return "CONFIGURED"
        elif (flag1 == 1 and flag2 == 0) or (flag1 == 0 and flag2 == 1):
            logger.critical("Interface Mis-Configured! ")

        return "UN-CONFIGURED"

    def check_static_route(self, device, interface_name, network_name, host_object_name_gw):
        """
        Purpose:    Check if a static route exists on a device
        Parameters: Device, Interface name, Network, Gateway
        Returns:    CONFIGURED, UN-CONFIGURED
        Raises:
        """
        ngfwid = self.get_device_id_by_name(device)
        if ngfwid == '':
            return "NO-DEVICE"
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + ngfwid + \
                   "/routing/ipv4staticroutes"
        url = self.server + api_path + '?offset=0&limit=10000'
        r = self.rest_get(url)
        if 'items' in r.json():
            for key1 in r.json()['items']:
                id = key1['id']
                url = self.server + api_path + '/' + id
                r = self.rest_get(url)
                if r.json()['interfaceName'] == interface_name:
                    for key2 in r.json()['selectedNetworks']:
                        if key2['name'] == network_name:
                            try:
                                element = dict.copy(r.json()['gateway']['object'])
                                if element['name'] == host_object_name_gw:
                                    return "CONFIGURED"
                            except:
                                pass
                            try:
                                element = dict.copy(r.json()['gateway']['literal'])
                                if element['value'] == host_object_name_gw:
                                    return "CONFIGURED"
                            except:
                                pass
        return "UN-CONFIGURED"

    def configure_nic_dhcp(self, device_name, nic, nic_name, zone, mtu):
        """
        Purpose:    Configure an Nic interface as DHCP
        Parameters: Device Name, Nic, Nic name, Zone, MTU
        Returns:    REST put response
        Raises:
        """
        device_id = self.get_device_id_by_name(device_name)
        nic_id = self.get_nic_id_by_name(device_name, nic)
        zone_id = self.get_security_objectid_by_name(zone)

        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + \
                   device_id + "/physicalinterfaces/" + nic_id
        url = self.server + api_path
        put_data = {
                "type": "PhysicalInterface",
                "managementOnly": "false",
                "MTU": int(mtu),
                "ipv4": {
                    "dhcp": {
                        "enableDefaultRouteDHCP": "false",
                        "dhcpRouteMetric": 1
                        }
                },
                "securityZone": {
                    "id": zone_id,
                    "type": "SecurityZone"
                },
                "mode": "NONE",
                "ifname": nic_name,
                "enabled": "true",
                "name": nic,
                "id": nic_id
                }
        r = self.rest_put(url, put_data)
        return r

    def configure_nic_static(self, device_name, nic, nic_name, zone, mtu, ip, netmask):
        """
        Purpose:    Configure an Nic interface as Static
        Parameters: Device Name, Nic, Nic name, Zone, IP, Netmask
        Returns:    REST put response
        Raises:
        """
        device_id = self.get_device_id_by_name(device_name)
        nic_id = self.get_nic_id_by_name(device_name, nic)
        zone_id = self.get_security_objectid_by_name(zone)

        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + \
                   device_id + "/physicalinterfaces/" + nic_id
        url = self.server + api_path
        put_data = {
                "type": "PhysicalInterface",
                "managementOnly": "false",
                "MTU": mtu,
                "ipv4": {
                    "static": {
                        "address": ip,
                        "netmask": netmask
                    }
                },
                "securityZone": {
                    "id": zone_id,
                    "type": "SecurityZone"
                },
                "mode": "NONE",
                "ifname": nic_name,
                "enabled": "true",
                "name": nic,
                "id": nic_id
                }
        r = self.rest_put(url, put_data)
        return r

    def create_static_network_route(self, device, interface_name, network_object_name, host_object_name_gw, metric):
        """
        Purpose:    To create static network route on device
        Parameters: Device, Interface Name, Network, Gateway, Metric
        Returns:    REST response
        Raises:
        """
        ngfwid = self.get_device_id_by_name(device)
        network_object_id = self.get_network_objectid_by_name(network_object_name)
        host_object_id_gw = self.get_host_objectid_by_name(host_object_name_gw)
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + ngfwid + \
                   "/routing/ipv4staticroutes"
        url = self.server + api_path
        if host_object_id_gw != '':
            gate_way = {
                "object": {
                    "type": "Host",
                    "id": host_object_id_gw,
                    "name": host_object_name_gw
                }
            }
        else:
            gate_way = {
                "literal": {
                    "type": "Host",
                    "value": host_object_name_gw
                }
            }
        post_data = {
            "interfaceName": interface_name,
            "selectedNetworks": [
                {
                    "type": "Network",
                    "id": network_object_id,
                    "name": network_object_name
                }
            ],
            "gateway": gate_way,
            "metricValue": metric,
            "type": "IPv4StaticRoute",
            "isTunneled": False
        }
        r = self.rest_post(url, post_data)
        return r

    def create_static_host_route(self, device, interface_name, host_object_name, host_object_name_gw, metric):
        """
        Purpose:    To create static host route on device
        Parameters: Device, Interface Name, Host, Gateway, Metric
        Returns:    REST response
        Raises:
        """
        ngfwid = self.get_device_id_by_name(device)
        host_object_id = self.get_host_objectid_by_name(host_object_name)
        host_object_id_gw = self.get_host_objectid_by_name(host_object_name_gw)
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + \
                   ngfwid + "/routing/ipv4staticroutes"  # param
        url = self.server + api_path

        if host_object_id_gw != '':
            gate_way = {
                "object": {
                    "type": "Host",
                    "id": host_object_id_gw,
                    "name": host_object_name_gw
                }
            }
        else:
            gate_way = {
                "literal": {
                    "type": "Host",
                    "value": host_object_name_gw
                }
            }

        post_data = {
            "interfaceName": interface_name,
            "selectedNetworks": [
                {
                    "type": "Host",
                    "id": host_object_id,
                    "name": host_object_name
                }
            ],
            "gateway": gate_way,
            "metricValue": metric,
            "type": "IPv4StaticRoute",
            "isTunneled": False
        }
        r = self.rest_post(url, post_data)
        return r

    def register_device(self, name, mgmt_ip, policy_id, reg_id, nat_id, license_caps, device_grp_id):
        """
        Purpose:    Register the device to FMC
        Parameters: Name of device, Mgmt ip, Access Policy Id, Registration & NAT id, Licenses Caps, Group Id
        Returns:    REST post response
        Raises:
        """
        logger.info("Registering: "+name)
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords"
        url = self.server + api_path
        post_data = {
            "name": name,
            "hostName": mgmt_ip,
            "regKey": reg_id,
            "natID": nat_id,
            "type": "Device",
            "license_caps": license_caps,
            "accessPolicy": {
                "id": policy_id,
                "type": "AccessPolicy"
            },
            "deviceGroup": {
                "id": device_grp_id,
                "type": "DeviceGroup"
            }
        }

        r = self.rest_post(url, post_data)
        return r

    def deregister_device(self, name):
        """
        Purpose:    De-registers the device from FMC
        Parameters: Device Name
        Returns:    REST delete response
        Raises:
        """
        logger.info("De-registering: " + name)
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/"
        dev_id = self.get_device_id_by_name(name)
        url = self.server + api_path + dev_id
        r = self.rest_delete(url)
        return r

    def start_deployment(self, device_name):
        """
        Purpose:    Deploys policy changes on device
        Parameters: Device name
        Returns:    Task Id
        Raises:
        """
        logger.info("Deploy called for: " + device_name)
        device_list = self.get_deployable_devices()
        logging.debug("Device List = " + str(device_list))
        if device_name in device_list:
            logging.debug("deploying on device: " + device_name)
            api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/deployment/deploymentrequests"
            url = self.server + api_path
            post_data = {
                "type": "DeploymentRequest",
                "version": str(self.get_time_stamp()),
                "forceDeploy": True,
                "ignoreWarning": True,
                "deviceList": [self.get_device_id_by_name(device_name)]
            }
            r = self.rest_post(url, post_data)
            if 'type' in r.json():
                if r.json()['type'] == 'DeploymentRequest':
                    return r.json()['metadata']['task']['id']
        return ''

    def register_ftdv(self, vm_name, mgmtip, reg_id, nat_id, license_caps, device_grp_id):
        """
        Purpose:    Register the device to FMC
        Parameters: Device Name, Mgmgt Ip, Registration & NAT id, Licenses cap, grp id
        Returns:    Task id, None
        Raises:
        """
        try:
            vm_policy_id = self.get_access_policy_id_by_name(self.accessPolicyName)
        except Exception as e:
            logger.warn("%s policy doesn't exist in FMC!" % self.accessPolicyName)
            logger.debug(str(e))
            return None
        else:
            if vm_policy_id is not None:
                logger.info("Registering FTDv: " + vm_name + " to FMC with policy id: " + vm_policy_id)
                r = self.register_device(vm_name, mgmtip, vm_policy_id, reg_id, nat_id, license_caps, device_grp_id)
                logger.debug("Register response was: " + str(r.json()))
                if 'type' in r.json():
                    if r.json()['type'] == 'Device':
                        logger.info("NGWFv: " + vm_name + " registration started and task ID is: " +
                                    r.json()['metadata']['task']['id'])
                        return r.json()['metadata']['task']['id']
            else:
                logger.warn("%s policy doesn't exist in FMC" % self.accessPolicyName)
            return None

    def check_reg_status_from_fmc(self, vm_name):
        """
        Purpose:    Checks if device is registered to FMC
        Parameters: Device Name
        Returns:    SUCCESS, FAILED
        Raises:
        """
        try:
            device_id = self.get_device_id_by_name(vm_name)
        except Exception as e:
            logger.debug(str(e))
        else:
            if device_id != '':
                return "SUCCESS"
            else:
                return "FAILED"

    def check_deploy_status(self, vm_name):
        """
        Purpose:    Checks if any deployment pending for device
        Parameters: Device name
        Returns:    DEPLOYED, NOT-DEPLOYED
        Raises:
        """
        r = self.get_deployable_devices()
        for device in r:
            if device == vm_name:
                logger.debug("Policies not deployed on " + vm_name)
                return "NOT-DEPLOYED"
        logger.debug("Policies deployed on " + vm_name)
        return "DEPLOYED"

    def check_object_fmc(self, obj_name):
        """
        Purpose:    Checks for Object inn FMC
        Parameters: Object name
        Returns:    Object Id
        Raises:
        """
        obj_id = self.get_network_objectid_by_name(obj_name)
        if obj_id == '':
            obj_id = self.get_host_objectid_by_name(obj_name)
            if obj_id == '':
                obj_id = self.get_port_objectid_by_name(obj_name)
                if obj_id == '':
                    logger.error("Unable to find object %s" % obj_name)
                    return ''
        return obj_id
