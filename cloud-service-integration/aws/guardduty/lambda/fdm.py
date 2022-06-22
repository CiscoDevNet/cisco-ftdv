"""
Copyright (c) 2021 Cisco Systems Inc or its affiliates.

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

Name:       fdm.py
Purpose:    This is contains FDM related REST methods
"""

import os
import time
import requests
import json
import utils as util
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logger = util.setup_logging(os.environ['DEBUG_LOGS'])

class FirepowerDeviceManager:
    """
        FirepowerDeviceManager class has REST methods for FDM connections
    """
    def __init__(self, fdm_server, username, password, object_group=None):
        self.server = 'https://' + fdm_server
        self.api_base_path = self.server + '/api/fdm/latest'
        self.username = username
        self.password = password
        self.headers = []
        self.accessTokenTimestamp = 0
        self.accessTokenMaxAge = 15*60  # seconds - 30 minutes is the max without using refresh
        self.objectGroupName = object_group

    def rest_get(self, url):
        """
        Purpose:    Issue REST get to the specified URL
        Parameters: url
        Returns:    r.text is the text response (r.json() is a python dict version of the json response)
                    r.status_code = 2xx on success
        Raises:
        """
        # if the token is too old then get another
        if time.time() > self.accessTokenMaxAge + self.accessTokenTimestamp:
            logger.debug("Getting a new accessToken")
            self.get_access_token()
        r = None
        try:
            # REST call with SSL verification turned off:
            logger.debug("Request: " + url)
            r = requests.get(url, headers=self.headers, verify=False)

            status_code = r.status_code
            resp = r.text
            logger.debug("Response status_code: " + str(status_code))
            logger.debug("Response body: " + str(resp))

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
        if time.time() > self.accessTokenMaxAge + self.accessTokenTimestamp:
            logger.debug("Getting a new accessToken")
            self.get_access_token()
        r = None
        try:
            # REST call with SSL verification turned off:
            logger.debug("Request: " + url)
            logger.debug("Post_data " + str(post_data))
            r = requests.post(url, data=json.dumps(post_data), headers=self.headers, verify=False)

            status_code = r.status_code
            resp = r.text
            logger.debug("Response status_code: " + str(status_code))
            logger.debug("Response body: " + str(resp))
            if 200 <= status_code <= 202:
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
        if time.time() > self.accessTokenMaxAge + self.accessTokenTimestamp:
            logger.debug("Getting a new accessToken")
            self.get_access_token()
        r = None
        try:
            # REST call with SSL verification turned off:
            logger.debug("Request: " + url)
            logger.debug("Put_data: " + str(put_data))
            r = requests.put(url, data=json.dumps(put_data), headers=self.headers, verify=False)

            status_code = r.status_code
            resp = r.text
            logger.debug("Response status_code: " + str(status_code))
            logger.debug("Response body: " + str(resp))
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
        if time.time() > self.accessTokenMaxAge + self.accessTokenTimestamp:
            logger.debug("Getting a new accessToken")
            self.get_access_token()
        r = None
        try:
            # REST call with SSL verification turned off:
            logger.debug("Request: " + url)
            r = requests.delete(url, headers=self.headers, verify=False)

            status_code = r.status_code
            resp = r.text
            logger.debug("Response status_code: " + str(status_code))
            logger.debug("Response body: " + str(resp))
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

    def get_access_token(self):
        """
        Purpose:    get a new access token
                    update the 'headers' variable
                    set a timestamp for the header (tokens expire)
        Parameters:
        Returns:
        Raises:
        """
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        api_auth_path = "/fdm/token"
        auth_url = self.api_base_path + api_auth_path
        r = None
        try:
            post_data = {
                "grant_type": "password",
                "username": self.username,
                "password": self.password
            }
            logger.debug("Request url: " + auth_url)
            r = requests.post(auth_url, data=json.dumps(post_data), headers=self.headers, verify=False)
            logger.debug("Response status_code: " + str(r.status_code))
            logger.debug("Response body: " + str(r.text))
            if r.status_code == 200:
                resp_json = r.json()
                self.headers['Authorization'] = 'Bearer ' + resp_json['access_token']
                self.accessTokenTimestamp = int(time.time())
        except Exception as err:
            logger.error("Error in generating access token --> " + str(err))
        finally:
            if r: r.close()
        return

    def get_network_grp_by_name(self, name):
        """
        Purpose:    To get the network group id by passing name of the group
        Parameters: Name of network group
        Returns:    The network group or None
        Raises:
        """
        api_path =  self.api_base_path + '/object/networkgroups'
        url = api_path + '?filter=name%3A'+ name
        r = self.rest_get(url)
        if r.status_code == 200 and 'items' in r.json():
            for item in r.json()['items']:
                if item['name'] == name:
                    return item
        return None

    def create_network_grp(self, name, host_obj):
        """
        Purpose:    Creates a network group object with the host
        Parameters: Network group name and the host object to associate
        Returns:    REST post response
        Raises:
        """
        url =  self.api_base_path + '/object/networkgroups'
        post_data = {
            "name": name,
            "description": "Network group for guardduty",
            "objects": [
                {  "id": host_obj['id'],
                   "type": host_obj['type'],
                   "version": host_obj['version'],
                   "name": host_obj['name']
                }
            ],
            "type": "networkobjectgroup"
        }
        r = self.rest_post(url, post_data)
        if r.status_code == 200:
            return r.json()
        else:
            raise Exception("failed to create network group with name " + name)
        
    def get_host_object_by_name(self, name):
        """
        Purpose:    Gets a new host object
        Parameters: Name host object to be get
        Returns:    REST get response
        Raises:
        """
        api_path = self.api_base_path + '/object/networks'
        url = api_path + '?filter=name%3A'+ name
        r = self.rest_get(url)
        if r.status_code == 200 and 'items' in r.json():
            for item in r.json()['items']:
                if item['name'] == name:
                    return item
        return None

    def create_host_object(self, host_name, host_ip):
        """
        Purpose:    Creates a new host object
        Parameters: Name and IP for the host object to be created
        Returns:    REST post response
        Raises:
        """
        url =  self.api_base_path + '/object/networks'
        post_data = {
            "name": host_name,
            "subType": "HOST",
            "value": host_ip,
            "type": "networkobject",
            "description": "Object for host " + host_ip
        }
        r = self.rest_post(url, post_data)
        if r.status_code == 200:
            return r.json()
        else:
            raise Exception("failed to create network object with name " + host_name)

    def update_network_group(self, nw_group, host_obj):
        """
        Purpose:    Update network group object with the host
        Parameters: Network group object and the host to update
        Returns:    REST put response
        Raises:
        """
        api_path =  self.api_base_path + '/object/networkgroups/'
        url = api_path + nw_group['id']

        objects = []
        if 'objects' in nw_group:
            objects = nw_group['objects']
        objects.append({
            "id": host_obj['id'],
            "type": host_obj['type'],
            "version": host_obj['version'],
            "name": host_obj['name']
        })

        put_data = {
            "version": nw_group['version'],
            "name": nw_group['name'],
            "id": nw_group['id'],
            "objects": objects,
            "type": "networkobjectgroup"
        }
        r = self.rest_put(url, put_data)
        if r.status_code == 200:
            return r.json()
        else:
            raise Exception("failed to update network group with name " + nw_group['name'])