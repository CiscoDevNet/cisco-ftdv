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

Name:       fmcv.py
Purpose:    This is contains FMC related REST methods
"""

import os
import time
import requests
import json
import utils as util
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logger = util.setup_logging(os.environ['DEBUG_LOGS'])

class FirepowerManagementCenter:
    """
        FirepowerManagementCenter class has REST methods for FMC connections
    """
    def __init__(self, fmc_server, username, password, object_group=None):
        self.server = 'https://' + fmc_server
        self.api_base_path = '/api/fmc_config/v1/domain/'
        self.username = username
        self.password = password
        self.headers = []
        self.domain_uuid = ""
        self.authTokenTimestamp = 0
        self.authTokenMaxAge = 15*60  # seconds - 30 minutes is the max without using refresh
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
        if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
            logger.debug("Getting a new authToken")
            self.get_auth_token()
        r = None
        try:
            # REST call with SSL verification turned off:
            logger.debug("Request: " + url)
            r = requests.get(url, headers=self.headers, verify=False)
            # REST call with SSL verification turned on:
            # r = requests.get(url, headers=headers, verify='/path/to/ssl_certificate')
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
        if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
            logger.debug("Getting a new authToken")
            self.get_auth_token()
        r = None
        try:
            # REST call with SSL verification turned off:
            logger.debug("Request: " + url)
            logger.debug("Post_data " + str(post_data))
            r = requests.post(url, data=json.dumps(post_data), headers=self.headers, verify=False)
            # REST call with SSL verification turned on:
            # r = requests.post(url,data=json.dumps(post_data), headers=self.headers, verify='/path/to/ssl_certificate')
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
        if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
            logger.debug("Getting a new authToken")
            self.get_auth_token()
        r = None
        try:
            # REST call with SSL verification turned off:
            logger.debug("Request: " + url)
            logger.debug("Put_data: " + str(put_data))
            r = requests.put(url, data=json.dumps(put_data), headers=self.headers, verify=False)
            # REST call with SSL verification turned on:
            # r = requests.put(url, data=json.dumps(put_data), headers=headers, verify='/path/to/ssl_certificate')
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
        if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
            logger.debug("Getting a new authToken")
            self.get_auth_token()
        r = None
        try:
            # REST call with SSL verification turned off:
            logger.debug("Request: " + url)
            r = requests.delete(url, headers=self.headers, verify=False)
            # REST call with SSL verification turned on:
            # r = requests.delete(url, headers=headers, verify='/path/to/ssl_certificate')
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
            if auth_token is None:
                logger.debug("auth_token not found. Exiting...")
        except Exception as err:
            logger.error("Error in generating auth token --> " + str(err))
        return

    def get_network_grp_by_name(self, name):
        """
        Purpose:    To get the network group id by passing name of the group
        Parameters: Name of network group
        Returns:    The network group or None
        Raises:
        """
        api_path = self.server + self.api_base_path + self.domain_uuid + '/object/networkgroups'
        url = api_path + '?filter=%22nameOrValue%3A'+ name + '%22&expanded=true'
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
        url = self.server + self.api_base_path + self.domain_uuid + '/object/networkgroups'
        post_data = {
            "name": name,
            "type": "NetworkGroup",
            "objects": [{
                "type": "Host",
                "id": host_obj['id']
            }]
        }
        r = self.rest_post(url, post_data)
        if r.status_code == 201:
            return r.json()
        else:
            raise Exception("failed to create network group with name \"{}\"".format(name))
    
    def get_host_object_by_name(self, name):
        """
        Purpose:    Gets a new host object
        Parameters: Name host object to be get
        Returns:    REST get response
        Raises:
        """
        api_path = self.server + self.api_base_path + self.domain_uuid + '/object/hosts'
        url = api_path + '?filter=%22nameOrValue%3A'+ name + '%22&expanded=true'
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
        url = self.server + self.api_base_path + self.domain_uuid + '/object/hosts'
        post_data = {
            "name": host_name,
            "type": "Host",
            "value": host_ip,
            "description": "Object for host " + host_ip
        }
        r = self.rest_post(url, post_data)
        if r.status_code == 201:
            return r.json()
        else:
            raise Exception("failed to create network object with name \"{}\"".format(host_name))

    def update_network_group(self, nw_group, host_obj):
        """
        Purpose:    Update network group object with the host
        Parameters: Network group object and the host to update
        Returns:    REST put response
        Raises:
        """
        api_path = self.server + self.api_base_path + self.domain_uuid + '/object/networkgroups/'
        url = api_path + nw_group['id']

        objects = []
        if 'objects' in nw_group:
            objects = nw_group['objects']
        objects.append({
            "type": "Host",
            "id": host_obj['id']
        })

        literals = []
        if 'literals' in nw_group:
            literals = nw_group['literals']


        put_data = {
            "id": nw_group['id'],
            "name": nw_group['name'],
            "type": "NetworkGroup",
            "objects": objects,
            "literals": literals
        }
        r = self.rest_put(url, put_data)
        if r.status_code == 200:
            return r.json()
        else:
            raise Exception("failed to update network group with name \"{}\"" .format(nw_group['name']))