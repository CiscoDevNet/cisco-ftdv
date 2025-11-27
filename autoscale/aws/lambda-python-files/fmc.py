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

Name:       fmc.py
Purpose:    This is contains FMC related REST methods
"""

import time
import requests
import logging
import json
import ipaddress
import utility as utl
import ast
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logger = utl.setup_logging()


class FirepowerManagementCenter:
    """
        FirepowerManagementCenter class has REST methods for FMC connections
    """
    def __init__(self, fmc_server, username, password, accesspolicy=None):
        # Normalize FMC server to a proper URL, supporting IPv4, IPv6
        try:
            ip = ipaddress.ip_address(fmc_server)
            self.ip_version = ip.version
            if self.ip_version == 6:
                self.server = 'https://' + '[' + fmc_server + ']' 
            else:
                self.server = 'https://' + fmc_server
        except ValueError:
            # Not an IP literal; leave hostname as-is
            self.server = 'https://' + fmc_server
        
        self.username = username
        self.password = password
        self.headers = []
        self.domain_uuid = ""
        self.authTokenTimestamp = 0
        self.authTokenMaxAge = 15*60  # seconds - 30 minutes is the max without using refresh
        self.accessPolicyName = accesspolicy
        

    def rest_get(self, url):
        """
        Purpose:    Issue REST get to the specified URL with retry logic
        Parameters: url, max_retries (default 5), retry_delay (default 2 seconds), timeout (default 30 seconds)
        Returns:    r.text is the text response (r.json() is a python dict version of the json response)
                    r.status_code = 2xx on success
        Raises:
        """
        max_retries = 5
        retry_delay = 30
        timeout = 15
        # if the token is too old then get another
        if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
            logging.debug("Getting a new authToken")
            self.get_auth_token()
            
        last_exception = None
        
        for attempt in range(1, max_retries+1):
            try:
                r = None
                if attempt > 1:
                    logging.warning(f"Attempt number {attempt}/{max_retries} for URL: {url}")
                    time.sleep(retry_delay)
                # REST call with SSL verification turned off:
                logging.debug("Request: " + url)
                r = requests.get(url, headers=self.headers, verify=False, timeout=timeout)
                
                # Check if we got a valid response
                if r is None:
                    raise Exception("Received None response from requests.get")
                    
                status_code = r.status_code
                resp = r.text
                logging.debug("Response status_code: " + str(status_code))
                logging.debug("Response body: " + str(resp))
                
                if 200 <= status_code <= 300:
                    # Success - return the response
                    return r
                else:
                    # Non-success status code
                    if attempt < max_retries:
                        logging.warning(f"HTTP {status_code} error on attempt {attempt}, will retry")
                        if r:
                            r.close()
                        continue
                    else:
                        # Last attempt failed
                        r.raise_for_status()
                        raise Exception("Error occurred in GET -->"+resp)
                        
            except requests.exceptions.ConnectTimeout as e:
                last_exception = e
                logging.warning(f"Connection timeout on attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Connection timeout after {max_retries} attempts")
                    break
                    
            except requests.exceptions.ReadTimeout as e:
                last_exception = e
                logging.warning(f"Read timeout on attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Read timeout after {max_retries} attempts")
                    break
                    
            except requests.exceptions.ConnectionError as e:
                last_exception = e
                logging.warning(f"Connection error on attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Connection error after {max_retries} attempts")
                    break
                    
            except requests.exceptions.HTTPError as e:
                last_exception = e
                logging.warning(f"HTTP error on attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"HTTP error after {max_retries} attempts")
                    break
                    
            except requests.exceptions.RequestException as e:
                last_exception = e
                logging.warning(f"Request exception on attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Request exception after {max_retries} attempts")
                    break
                    
            except Exception as e:
                last_exception = e
                logging.warning(f"Unexpected error on attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Unexpected error after {max_retries} attempts")
                    break
        
        # All retries failed
        logging.error(f"REST GET failed after {max_retries} attempts. Last error: {str(last_exception)}")
        return r

    def rest_post(self, url, post_data):
        """
        Purpose:    Issue REST post to the specified url with the post_data provided with retry logic
        Parameters: url, post data
        Returns:    This function will return 'r' which is the response from the post:
                    r.text is the text response (r.json() is a python dict version of the json response)
                    r.status_code = 2xx on success
        Raises:     Error occurred in post
        """
        max_retries = 5
        retry_delay = 30
        timeout = 15
        
        if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
            logging.debug("Getting a new authToken")
            self.get_auth_token()
            
        last_exception = None
        
        for attempt in range(1, max_retries+1):
            try:
                r = None
                if attempt > 1:
                    logging.warning(f"Attempt number {attempt}/{max_retries} for POST URL: {url}")
                    time.sleep(retry_delay)
                    
                # REST call with SSL verification turned off:
                logging.debug("Request: " + url)
                logging.debug("Post_data " + str(post_data))
                r = requests.post(url, data=json.dumps(post_data), headers=self.headers, verify=False, timeout=timeout)
                
                # Check if we got a valid response
                if r is None:
                    raise Exception("Received None response from requests.post")
                    
                status_code = r.status_code
                resp = r.text
                logging.info("Response status_code: " + str(status_code))
                logging.info("Response body: " + str(resp))
                
                if 200 <= status_code <= 202:
                    # Success - return the response
                    return r
                else:
                    # Non-success status code
                    if attempt < max_retries:
                        logging.warning(f"HTTP {status_code} error on attempt {attempt}, will retry")
                        if r:
                            r.close()
                        continue
                    else:
                        # Last attempt failed
                        r.raise_for_status()
                        raise Exception("Error occurred in POST --> "+resp)
                        
            except requests.exceptions.ConnectTimeout as e:
                last_exception = e
                logging.warning(f"Connection timeout on POST attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Connection timeout after {max_retries} attempts")
                    break
                    
            except requests.exceptions.ReadTimeout as e:
                last_exception = e
                logging.warning(f"Read timeout on POST attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Read timeout after {max_retries} attempts")
                    break
                    
            except requests.exceptions.ConnectionError as e:
                last_exception = e
                logging.warning(f"Connection error on POST attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Connection error after {max_retries} attempts")
                    break
                    
            except requests.exceptions.HTTPError as e:
                last_exception = e
                logging.warning(f"HTTP error on POST attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"HTTP error after {max_retries} attempts")
                    break
                    
            except requests.exceptions.RequestException as e:
                last_exception = e
                logging.warning(f"Request exception on POST attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Request exception after {max_retries} attempts")
                    break
                    
            except Exception as e:
                last_exception = e
                logging.warning(f"Unexpected error on POST attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Unexpected error after {max_retries} attempts")
                    break
        
        # All retries failed
        logging.error(f"REST POST failed after {max_retries} attempts. Last error: {str(last_exception)}")
        return r

    def rest_put(self, url, put_data):
        """
        Purpose:    Issue REST put to specific url with the put_data provided with retry logic
        Parameters: url, put data
        Returns:    This function will return 'r' which is the response from the put:
                    r.text is the text response (r.json() is a python dict version of the json response)
                    r.status_code = 2xx on success
        Raises:
        """
        max_retries = 5
        retry_delay = 30
        timeout = 15
        
        if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
            logging.debug("Getting a new authToken")
            self.get_auth_token()
            
        last_exception = None
        
        for attempt in range(1, max_retries+1):
            try:
                r = None
                if attempt > 1:
                    logging.warning(f"Attempt number {attempt}/{max_retries} for PUT URL: {url}")
                    time.sleep(retry_delay)
                    
                # REST call with SSL verification turned off:
                logging.info("Request: " + url)
                logging.info("Put_data: " + str(put_data))
                r = requests.put(url, data=json.dumps(put_data), headers=self.headers, verify=False, timeout=timeout)
                
                # Check if we got a valid response
                if r is None:
                    raise Exception("Received None response from requests.put")
                    
                status_code = r.status_code
                resp = r.text
                logging.info("Response status_code: " + str(status_code))
                logging.info("Response body: " + str(resp))
                
                if 200 <= status_code <= 204:
                    # Success - return the response
                    return r
                else:
                    # Non-success status code
                    if attempt < max_retries:
                        logging.warning(f"HTTP {status_code} error on attempt {attempt}, will retry")
                        if r:
                            r.close()
                        continue
                    else:
                        # Last attempt failed
                        r.raise_for_status()
                        raise Exception("Error occurred in PUT --> "+resp)
                        
            except requests.exceptions.ConnectTimeout as e:
                last_exception = e
                logging.warning(f"Connection timeout on PUT attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Connection timeout after {max_retries} attempts")
                    break
                    
            except requests.exceptions.ReadTimeout as e:
                last_exception = e
                logging.warning(f"Read timeout on PUT attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Read timeout after {max_retries} attempts")
                    break
                    
            except requests.exceptions.ConnectionError as e:
                last_exception = e
                logging.warning(f"Connection error on PUT attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Connection error after {max_retries} attempts")
                    break
                    
            except requests.exceptions.HTTPError as e:
                last_exception = e
                logging.warning(f"HTTP error on PUT attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"HTTP error after {max_retries} attempts")
                    break
                    
            except requests.exceptions.RequestException as e:
                last_exception = e
                logging.warning(f"Request exception on PUT attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Request exception after {max_retries} attempts")
                    break
                    
            except Exception as e:
                last_exception = e
                logging.warning(f"Unexpected error on PUT attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Unexpected error after {max_retries} attempts")
                    break
        
        # All retries failed
        logging.error(f"REST PUT failed after {max_retries} attempts. Last error: {str(last_exception)}")
        return r

    def rest_delete(self, url):
        """
        Purpose:    Issue REST delete to the specified URL with retry logic
        Parameters: url
        Returns:    This function will return 'r' which is the response to the request:
                    r.text is the text response (r.json() is a python dict version of the json response)
                    r.status_code = 2xx on success
        Raises:
        """
        max_retries = 5
        retry_delay = 30
        timeout = 15
        
        if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
            logging.debug("Getting a new authToken")
            self.get_auth_token()
            
        last_exception = None
        
        for attempt in range(1, max_retries+1):
            try:
                r = None
                if attempt > 1:
                    logging.warning(f"Attempt number {attempt}/{max_retries} for DELETE URL: {url}")
                    time.sleep(retry_delay)
                    
                # REST call with SSL verification turned off:
                logging.debug("Request: " + url)
                r = requests.delete(url, headers=self.headers, verify=False, timeout=timeout)
                
                # Check if we got a valid response
                if r is None:
                    raise Exception("Received None response from requests.delete")
                    
                status_code = r.status_code
                resp = r.text
                logging.info("Response status_code: " + str(status_code))
                logging.info("Response body: " + str(resp))
                
                if 200 <= status_code <= 300:
                    # Success - return the response
                    return r
                else:
                    # Non-success status code
                    if attempt < max_retries:
                        logging.warning(f"HTTP {status_code} error on attempt {attempt}, will retry")
                        if r:
                            r.close()
                        continue
                    else:
                        # Last attempt failed
                        r.raise_for_status()
                        raise Exception("Error occurred in DELETE --> "+resp)
                        
            except requests.exceptions.ConnectTimeout as e:
                last_exception = e
                logging.warning(f"Connection timeout on DELETE attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Connection timeout after {max_retries} attempts")
                    break
                    
            except requests.exceptions.ReadTimeout as e:
                last_exception = e
                logging.warning(f"Read timeout on DELETE attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Read timeout after {max_retries} attempts")
                    break
                    
            except requests.exceptions.ConnectionError as e:
                last_exception = e
                logging.warning(f"Connection error on DELETE attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Connection error after {max_retries} attempts")
                    break
                    
            except requests.exceptions.HTTPError as e:
                last_exception = e
                logging.warning(f"HTTP error on DELETE attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"HTTP error after {max_retries} attempts")
                    break
                    
            except requests.exceptions.RequestException as e:
                last_exception = e
                logging.warning(f"Request exception on DELETE attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Request exception after {max_retries} attempts")
                    break
                    
            except Exception as e:
                last_exception = e
                logging.warning(f"Unexpected error on DELETE attempt {attempt}: {str(e)}")
                if r:
                    r.close()
                if attempt >= max_retries:
                    logging.error(f"Unexpected error after {max_retries} attempts")
                    break
        
        # All retries failed
        logging.error(f"REST DELETE failed after {max_retries} attempts. Last error: {str(last_exception)}")
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

    def get_member_list_in_device_grp(self, grp_id):
        """
        Purpose:    To get devices name list from grp id
        Parameters: Group Id
        Returns:    list or None
        Raises:
        """
        member_name_list = []
        member_id_list = []
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devicegroups/devicegrouprecords/"
        url = self.server + api_path + grp_id
        r = self.rest_get(url)
        if 'members' in r.json():
            for item in r.json()['members']:
                member_name_list.append(item['name'])
                member_id_list.append(item['id'])

        return member_name_list, member_id_list

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

    def get_network_host_objectids(self):
        """
        Purpose:    Get Network & Host objects present in the FMCv
        Parameters: None
        Returns:    Network & Host Object Name & Ids
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkaddresses"
        url = self.server + api_path + '?offset=0&limit=10000'
        network_obj = {}
        host_obj = {}
        r = self.rest_get(url)
        for item in r.json()['items']:
            if item['type'] == 'Network':
                network_obj[item['name']] = str(item['id'])
            elif item['type'] == 'Host':
                host_obj[item['name']] = str(item['id'])

        return network_obj, host_obj
    

    def get_group_objects(self):
        """
        Purpose: Get the Group objects in the FMCv
        Parameters: None
        Returns: Group Object Name & Ids
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups"
        url = self.server + api_path + '?offset=0&limit=10000'
        group_obj = {}
        r = self.rest_get(url)
        for item in r.json()['items']:
            group_obj[item['name']] = str(item['id'])
      
        return group_obj
    
    def get_group_objectid_by_name(self, name):
        """
        Purpose: Get the Group objects in the FMCv
        Parameters: None
        Returns: Group Object Name & Ids
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups"
        url = self.server + api_path + '?offset=0&limit=10000'
        group_obj = {}
        r = self.rest_get(url)
        for item in r.json()['items']:
            group_obj[item['name']] = str(item['id'])
            if item['name'] == name:
                return str(item['id'])
        return ''

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
        return ''

    def create_network_object(self, name, description, value):
        """
        Purpose: Create a Network Object
        Parameters: Object Name
        Returns: Object Id
        Raises:
        """
        try:
            api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networks?bulk=true"
            url = self.server + api_path
            post_data = [
                        {
                            "description": description,
                            "name": name,
                            "overridable": "false",
                            "type": "Network",
                            "value": value
                        }
                    ]
            r = self.rest_post(url, post_data)
            if 'items' in r.json():
                for item in r.json()['items']:
                    if item['name'] == name:
                        return str(item['id'])
        except Exception as e:
            logger.exception(e)
            return None    

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
    
    def get_platform_policy_id_by_name(self, name):
        """
        Purpose:    Get Platform Policy Id by its name
        Parameters: Platform policy name
        Returns:    Platform Policy Id, None
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/ftdplatformsettingspolicies"
        url = self.server + api_path + '?offset=0&limit=10000'
        r = self.rest_get(url)
        # Search for policy by name
        if 'items' in r.json():
            for item in r.json()['items']:
                if item['name'] == name:
                    return str(item['id'])
        return None
    
    def check_and_create_nat_rules(self, nat_policy_id, vni_seczone_name, vni_seczone_id, outside_seczone_name, outside_seczone_id, ipv6_support=False):
        '''
        Purpose:    [DUAL-ARM ONLY !!] 
                    Checks for NAT Rule(s) if present, if not then creates the NAT Rule(s).
        Parameters: NAT Policy Id, VNI Security Zone Name, VNI Security Zone Id, Outside Security Zone Name, Outside Security Zone Id, IPv6 Support
        Returns:    Success or Fail
        Raises:
        '''
        try:
            ret1, ret2 = '', ''
            r = self.check_nat_rule_within_nat_policy(nat_policy_id, vni_seczone_id, outside_seczone_id)
            if r == 'CONFIGURED':
                ret1 = 'SUCCESS'
            elif r == 'UN-CONFIGURED':
                r = self.create_nat_rule_within_nat_policy(nat_policy_id, vni_seczone_name, vni_seczone_id, outside_seczone_name, outside_seczone_id)
                logger.debug(r)
                if r.status_code != 200 and r.status_code != 201:
                    raise Exception("NAT Rule creation failed!!")
                ret1 = 'SUCCESS'
            else:
                raise Exception("Error checking / creating NAT Rule within NAT Policy")
        except Exception as e:
            logger.critical(e)
            return 'FAIL'

        ## Check if IPv6 NAT rule within NAT policy is configured as expected : else create and configure       
        if not ipv6_support:
            ret2 = 'SUCCESS'
        else:
            r = self.check_nat_rule_ipv6_within_nat_policy(nat_policy_id, vni_seczone_id, outside_seczone_id)
            if r == 'CONFIGURED':
                ret2 = 'SUCCESS'
            elif r == 'UN-CONFIGURED':
                r = self.create_nat_rule_ipv6_within_nat_policy(nat_policy_id, vni_seczone_name, vni_seczone_id, outside_seczone_name, outside_seczone_id)
                logger.debug(r)
                if r.status_code != 200 and r.status_code != 201:
                    raise Exception("IPv6 NAT Rule creation failed!!")
                ret2 = 'SUCCESS'
            else:
                raise Exception("Error checking / creating IPv6 NAT Rule within NAT Policy")    
        if ret1 == 'SUCCESS' and ret2 == 'SUCCESS':
            return 'SUCCESS'
        else:
            return 'FAIL'
    
    def check_nat_rule_within_nat_policy(self, nat_policy_id, vni_seczone_id, outside_seczone_id):
        """
        Purpose:    Checks if NAT Rule is configured correctly within NAT Policy
        Parameters: NAT policy Id, VNI Security Zone Id, Outside Security Zone Id
        Returns: "CONFIGURED" or "UN-CONFIGURED"
        Raises:
        """
        try:
            api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/ftdnatpolicies/" 
            url = self.server + api_path + nat_policy_id + '/manualnatrules?offset=0&limit=25&expanded=true'
            r = self.rest_get(url)
            any_obj_id = self.group_objects['any']
            if 'items' in r.json():
                for item in r.json()['items']:
                    if item['originalSource']['id'] == any_obj_id and item['sourceInterface']['id'] == vni_seczone_id:
                        if item['destinationInterface']['id'] == outside_seczone_id:
                            if item['natType'] == 'DYNAMIC' and item['enabled'] is True and item['metadata']['section'] == 'BEFORE_AUTO':
                                return "CONFIGURED"
            return "UN-CONFIGURED"
        except Exception as e:
            logger.exception(e)

    def check_nat_rule_ipv6_within_nat_policy(self, nat_policy_id, vni_seczone_id, outside_seczone_id):
        """
        Purpose:    Creates Dual-arm IPv6 Auto-NAT Rule within NAT Policy
        Parameters: NAT policy Id, VNI Security Zone Id, Outside Security Zone Id
        Returns:    "CONFIGURED" or "UN-CONFIGURED"
        Raises:
        """
        try:
            if 'anyipv6' not in self.network_objects:
                logger.info("Creating Network object 'anyipv6' for IPv6 Auto-NAT Rule")
                any_ipv6_obj_id = self.create_network_object('anyipv6', 'Anywhere-IPv6', '::/0')
                self.network_objects['anyipv6'] = any_ipv6_obj_id
            else:
                any_ipv6_obj_id = self.network_objects['anyipv6']
            api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/ftdnatpolicies/" + nat_policy_id + "/autonatrules?expanded=true"
            url = self.server + api_path
            r = self.rest_get(url)
            
            if 'items' in r.json():
                for item in r.json()['items']:
                    if item['originalNetwork']['id'] == any_ipv6_obj_id and item['sourceInterface']['id'] == vni_seczone_id:
                        if item['destinationInterface']['id'] == outside_seczone_id:
                            if item['natType'] == 'DYNAMIC' and item['interfaceIpv6'] is True and item['metadata']['section'] == 'AUTO':
                                return "CONFIGURED"
            return "UN-CONFIGURED"
        except Exception as e:
            logger.exception(e)

    def create_nat_rule_within_nat_policy(self, nat_policy_id, vni_seczone_name, vni_seczone_id, outside_seczone_name, outside_seczone_id):
        """
        Purpose:    Creates Dual-arm Manual NAT Rule within NAT Policy
        Parameters: NAT policy Id, VNI Security Zone Name, VNI Security Zone Id, Outside Security Zone Name, Outside Security Zone Id
        Returns:    Rest response
        Raises:
        """
        try:
            # any_obj_id = self.get_group_objectid_by_name('any')
            any_obj_id = self.group_objects['any']
            api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/ftdnatpolicies/" + nat_policy_id + "/manualnatrules"
            url = self.server + api_path
            post_data = {
                "originalSource": {
                    "type": "NetworkGroup",
                    "overridable": "false",
                    "id": any_obj_id,
                    "name": "any"
                },
                "interfaceInOriginalDestination": "false",
                "interfaceInTranslatedSource": "true",
                "unidirectional": "true",
                "enabled": "true",
                "type": "FTDManualNatRule",
                "dns": "false",
                "destinationInterface": {
                    "name": outside_seczone_name,
                    "id": outside_seczone_id,
                    "type": "SecurityZone"
                },
                "interfaceIpv6": "false",
                "fallThrough": "false",
                "routeLookup": "false",
                "noProxyArp": "false",
                "netToNet": "false",
                "sourceInterface": {
                    "name": vni_seczone_name,
                    "id": vni_seczone_id,
                    "type": "SecurityZone"
                },
                "natType": "DYNAMIC"
                }
            r = self.rest_post(url, post_data)
            return r  
        except Exception as e:
            logger.exception(e)
            return None
    
    def create_nat_rule_ipv6_within_nat_policy(self, nat_policy_id, vni_seczone_name, vni_seczone_id, outside_seczone_name, outside_seczone_id):
        """
        Purpose:    Creates Dual-arm Auto NAT Rule IPv6 within NAT Policy
        Parameters: NAT policy Id, VNI Security Zone Name, VNI Security Zone Id, Outside Security Zone Name, Outside Security Zone Id
        Returns:    Rest response
        Raises:
        """

        try:
            any_ipv6_obj_id = self.network_objects['anyipv6']
            api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/ftdnatpolicies/" + nat_policy_id + "/autonatrules"
            url = self.server + api_path
            post_data = {
                "originalNetwork": {
                    "type": "Network",
                    "overridable": "false",
                    "id": any_ipv6_obj_id,
                    "name": "anyipv6"
                },
                "interfaceInTranslatedNetwork": "true",
                "type": "FTDAutoNatRule",
                "dns": "false",
                "destinationInterface": {
                    "name": outside_seczone_name,
                    "id": outside_seczone_id,
                    "type": "SecurityZone"
                },
                "interfaceIpv6": "true",
                "fallThrough": "false",
                "routeLookup": "false",
                "noProxyArp": "false",
                "netToNet": "false",
                "sourceInterface": {
                    "name": vni_seczone_name,
                    "id": vni_seczone_id,
                    "type": "SecurityZone"
                },
                "natType": "DYNAMIC"
                }
            r = self.rest_post(url, post_data)
            return r  
        except Exception as e:
            logger.exception(e)
            return None    
        
    def check_and_create_platform_policy(self, policy_name):
        """
        Purpose:    To create platform policy in FMC if not already present
        Parameters: Platform policy name
        Returns:    Platform policy ID
        Raises:
        """
        try:
            pol_id = self.get_platform_policy_id_by_name(policy_name) 
            if pol_id:
                return pol_id
            else:
                logger.info('Platform policy does not exist,Creating platform policy in FMC ..')

                api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/ftdplatformsettingspolicies"
                url = self.server + api_path
                post_data = {
                    "type": "FTDPlatformSettingsPolicy",
                    "name": policy_name,
                    "description": "Platform Settings for FTD health check"
                    }
                r = self.rest_post(url, post_data)
                return r.json()['id']
        except Exception as e:
            logger.exception(e)
            return None
        
    def check_and_create_nat_policy(self,policy_name):
        """
        Purpose:    To create NAT policy in FMC if not already present
        Parameters: NAT policy name
        Returns:    NAT policy ID
        Raises:
        """
        try:
            pol_id = self.get_nat_policy_id_by_name(policy_name) 
            if pol_id:
                return pol_id
            else:
                logger.info('NAT policy does not exist, Creating NAT policy in FMC ..')

                api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/ftdnatpolicies"
                url = self.server + api_path
                post_data = {
                    "type": "FTDNatPolicy",
                    "name": policy_name,
                    "description": "NAT Policy for Dual-arm configuration"
                    }
                r = self.rest_post(url, post_data)
                return r.json()['id']
        except Exception as e:
            logger.exception(e)
            return None 
            
    def get_nic_id_by_name(self, device_id, nic_name):
        """
        Purpose:    Get Nic Id by device & nic name
        Parameters: Device Name, Nic name
        Returns:    Nic Id, None
        Raises:
        """
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

    def get_nic_status(self, device_id, nic, nic_id, ifname, zone_id, ip=None, ipv6 = None):
        """
        Purpose:    To check whether Nic is configured or not configured
        Description:  flag1 - ipv4 config, flag2 - Interface Name & SecurityZones, flag3 - ipv6 config (only checked if ipv6 address passed)
        Parameters: Device Id, Nic, Nic Id, Interface Name, Zone Id, Ip, Ipv6
        Returns:    CONFIGURED, MIS-CONFIGURED, UN-CONFIGURED
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + \
                   device_id + "/physicalinterfaces/" + nic_id
        url = self.server + api_path
        r = self.rest_get(url)
        flag1, flag2, flag3 = 0, 0, 0
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

        ## Check for IPv6 address if ipv6 is passed
        ## if it passes, flag3 = 1
        try:
            if ipv6:
                if 'ipv6' in r.json():
                    item = dict.copy(r.json()['ipv6'])
                    for addr in item["addresses"]:
                        if addr['address'] == ipv6:
                            flag3 = 1
        except:
            flag3 = 0

        if flag1 == 1 and flag2 == 1:
            if ipv6:
                if flag3 == 0:
                    logger.critical("IPv6 Mis-Configured! ")
            return "CONFIGURED"
        elif (flag1 == 1 and flag2 == 0) or (flag1 == 0 and flag2 == 1):
            logger.critical("Interface Mis-Configured! ")

        return "UN-CONFIGURED"

    def check_static_route(self, device_id, interface_name, _object_name, gate_way): 
        """
        Purpose:    Check if a static route exists on a device
        Parameters: Device, Interface name, Network, Gateway
        Returns:    CONFIGURED, UN-CONFIGURED
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + \
                   device_id + "/routing/ipv4staticroutes"
        url = self.server + api_path + '?offset=0&limit=10000'
        r = self.rest_get(url)

        if 'items' in r.json():
            for key1 in r.json()['items']:
                id = key1['id']
                url = self.server + api_path + '/' + id
                r = self.rest_get(url)
                if r.json()['interfaceName'] == interface_name:
                    for key2 in r.json()['selectedNetworks']:
                        if key2['name'] == _object_name:
                            try:
                                element = dict.copy(r.json()['gateway']['object'])
                                if element['name'] == gate_way:
                                    return "CONFIGURED"
                            except:
                                pass
                            try:
                                element = dict.copy(r.json()['gateway']['literal'])
                                if element['value'] == gate_way:
                                    return "CONFIGURED"
                            except:
                                pass
        return "UN-CONFIGURED"

    def check_static_route_ipv6(self, device_id, interface_name, _object_name, gate_way): 
        """
        Purpose:    Check if an IPv6 static route exists on a device
        Parameters: Device, Interface name, Network, Gateway
        Returns:    CONFIGURED, UN-CONFIGURED
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + \
                   device_id + "/routing/ipv6staticroutes"
        url = self.server + api_path + '?offset=0&limit=10000'
        r = self.rest_get(url)

        if 'items' in r.json():
            for key1 in r.json()['items']:
                id = key1['id']
                url = self.server + api_path + '/' + id
                r = self.rest_get(url)
                if r.json()['interfaceName'] == interface_name:
                    for key2 in r.json()['selectedNetworks']:
                        if key2['name'] == _object_name:
                            try:
                                element = dict.copy(r.json()['gateway']['object'])
                                if element['name'] == gate_way:
                                    return "CONFIGURED"
                            except:
                                pass
                            try:
                                element = dict.copy(r.json()['gateway']['literal'])
                                if element['value'] == gate_way:
                                    return "CONFIGURED"
                            except:
                                pass
        return "UN-CONFIGURED"    

    def configure_nic(self, device_id, nic_id, nic, nic_name, mgmt_only, mode, zone_id, mtu, ip=None, netmask=None, ipv6=None, netmask_ipv6=None, config_method_ipv4='DHCP', config_method_ipv6='STATIC'):
        """
        Purpose:    Configure a Nic interface with IPv4 and IPv6 (if specified)
        Parameters: Device Name, Nic, Nic name, Zone, IP, Netmask, IPv6, Netmask IPv6, method of config (static or dhcp)
        Returns:    REST put response
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + \
                   device_id + "/physicalinterfaces/" + nic_id
        url = self.server + api_path
        put_data = {
                "type": "PhysicalInterface",
                "managementOnly": mgmt_only,
                "MTU": int(mtu),
                "securityZone": {
                    "id": zone_id,
                    "type": "SecurityZone"
                },
                "mode": mode,
                "ifname": nic_name,
                "enabled": "true",
                "name": nic,
                "id": nic_id
                }
        if config_method_ipv4.lower() == 'dhcp':
            put_data.update({
                "ipv4": {
                    "dhcp": {
                        "enableDefaultRouteDHCP": "false",
                        "dhcpRouteMetric": 1
                    }
                }
            })
        elif config_method_ipv4.lower() == 'static':
            put_data.update({
                "ipv4": {
                    "static": {
                        "address": ip,
                        "netmask": netmask
                    }
                }
            })
        if ipv6 and netmask_ipv6:
            put_data.update({
                    "ipv6": {
                    "enableIPV6": "true",
                    "addresses": [
                        {
                            "address": ipv6,
                            "prefix": netmask_ipv6, ##64
                            "enforceEUI64": "false"
                        }
                    ]
                }
            })   
        
        r = self.rest_put(url, put_data)
        return r   

    def check_vtep_enabled(self, device_id, nic_id):
        """
        Purpose:    Check if VTEP is enabled
        Parameters: Device ID, Nic ID
        Returns:    "CONFIGURED" or "UN-CONFIGURED"
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + \
                   device_id + "/vteppolicies?offset=0&limit=25&expanded=true"
        url = self.server + api_path
        r = self.rest_get(url)
        if 'items' in r.json():
            for item in r.json()['items']:
                if item['nveEnable'] is True:
                    if item['vtepEntries'][0]['sourceInterface']['id'] == nic_id:
                        return "CONFIGURED"
        return "UN-CONFIGURED"

    def enable_vtep(self, device_id, nic_name, nic_id):
        """
        Purpose:    Enable VTEP
        Parameters: Device ID, Nic name, Nic ID
        Returns:    REST put response
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + \
		           device_id + "/vteppolicies"	    
        url = self.server + api_path
		
        put_data = {
			"nveEnable": "true",
			"vtepEntries": [
			{
				"sourceInterface": {
					"name": nic_name,
					"type": "PhysicalInterface",
					"id": nic_id
				},
				"nveVtepId": 1,
				"nveDestinationPort": 6081,
				"nveEncapsulationType": "GENEVE"
			}
			],
			"type": "VTEPPolicy"
			}
		
        r = self.rest_put(url, put_data)
        return r	
		
    def check_vni_added(self, device_id, vni_nic_name, sec_zone_id, ipv6_support='disable'):
        """
        Purpose:    Check if VNI is added
        Parameters: Device ID, VNI interface name, Security Zone ID, ipv6_support
        Returns:    "CONFIGURED" or "UN-CONFIGURED"
        Raises:
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + \
                   device_id + "/vniinterfaces?offset=0&limit=25&expanded=true"
        url = self.server + api_path
        r = self.rest_get(url)
        if 'items' in r.json():
            for item in r.json()['items']:
                if item['ifname'] == vni_nic_name and item['securityZone']['id'] == sec_zone_id:
                    if ipv6_support == 'enable':
                        if item['ipv6']['enableIPV6'] is True and item['ipv6']['enableAutoConfig'] is True:
                            return "CONFIGURED"
                    else:
                        return "CONFIGURED"
        return "UN-CONFIGURED"

    def add_vni(self, device_id, proxy_type, vni_nic_name, sec_zone_id, ipv6_support='disable'): 
        """
        Purpose:    Add VNI
        Parameters: Device ID, proxy type (single-arm / dual-arm),  VNI interface name, Security Zone ID for VNI interface, ipv6_support
        Returns:    REST put response
        Raises:
        """

        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + \
		           device_id + "/vniinterfaces"	    
        url = self.server + api_path
		
        put_data = {
            "type": "VNIInterface",
            "vniId": 1,
            "enabled": "true",
            "vtepID": 1,
            "enableProxy": "true",
            "ifname": vni_nic_name,
            "securityZone": {
                "id": sec_zone_id,
                "type": "SecurityZone"
           }
        }
        if ipv6_support == 'enable':
            put_data.update({
                "ipv6": { 
                "enableIPV6": "true",
                "enableAutoConfig": "true"
            }}) 
        ## Fix backward-compatibility for <= 7.6.0
        ## Default proxyType = SINGLE_ARM if not specified in put_data
        if proxy_type == 'DUAL_ARM':
            put_data.update({"proxyType": "DUAL_ARM"})
        r = self.rest_put(url, put_data)
        return r

    def create_static_route(self, device_id, interface_name, _type, _object_name, _object_id, gate_way, metric): 
        """
        Purpose:    To create static route on device
        Parameters: Device, Interface Name, Host, Gateway, Metric
        Returns:    REST response
        Raises:
        """

        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + \
                   device_id + "/routing/ipv4staticroutes"  
        url = self.server + api_path

        post_data = {
            "interfaceName": interface_name,
            "selectedNetworks": [
                {
                    "type": _type,
                    "id": _object_id,
                    "name": _object_name
                }
            ],
            "gateway": gate_way,
            "metricValue": metric,
            "type": "IPv4StaticRoute",
            "isTunneled": False
        }
        r = self.rest_post(url, post_data)
        return r

    def create_static_route_ipv6(self, device_id, interface_name, _type, _object_name, _object_id, gate_way, metric):
        """
        Purpose:    To create IPv6 static route on device
        Parameters: Device, Interface Name, Host, Gateway, Metric
        Returns:    REST response
        Raises:
        """

        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/" + \
                   device_id + "/routing/ipv6staticroutes"  
        url = self.server + api_path

        post_data = {
            "interfaceName": interface_name,
            "selectedNetworks": [
                {
                    "type": _type,
                    "id": _object_id,
                    "name": _object_name
                }
            ],
            "gateway": gate_way,
            "metricValue": metric,
            "type": "IPv6StaticRoute",
            "isTunneled": False
        }
        r = self.rest_post(url, post_data)
        return r

    def register_device(self, name, ftd_ip, policy_id, reg_id, nat_id, license_caps, performance_tier, device_grp_id):
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
            "hostName": ftd_ip,
            "regKey": reg_id,
            "natID": nat_id,
            "type": "Device",
            "license_caps": license_caps,
            "performanceTier": performance_tier,
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
                return "PENDING...."

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
        Purpose:    Checks for Object in FMC
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
    def get_memory_metrics_from_fmc(self, device_id):
        """
        Purpose:    Fetch Memory Metric
        Parameters: device id
        Returns:
        Raises:
        """
        try:
            #Health Monitoring API
            api_path = f'/api/fmc_config/v1/domain/{self.domain_uuid}/health/metrics'
            # Values are fetched from last one minute at interval of 10 sec (step).
            end_time = int(time.time())
            start_time = end_time - 60
            step_size = 10
            regex_filter = "used_percentage_system_and_swap"
            api_suffix = \
                f'?offset=0&limit=100&filter=deviceUUIDs%3A{device_id}%3Bmetric%3Amem%3B' + \
                f"startTime%3A{start_time}%3BendTime%3A{end_time}%3Bstep%3A{step_size}%3B" + \
                f"regexFilter%3A{regex_filter}&expanded=true"
            url = self.server + api_path + api_suffix

            r = self.rest_get(url)
            resp = r.text
            return json.loads(resp)
        except Exception as e:
            logger.error("Error {}".format(e))
            return None

    def get_policy_assign_targets(self, pol_id):
        """
        Purpose:    Get targets by its policy id
        Parameters: Device Name
        Returns:    Device Id
          "targets": [
                    {
                      "id": "87b98de4-919c-11ea-bedf-d2d17d1b9702",
                      "type": "DeviceGroup",
                      "name": "AWS-Cisco-NGFW-VMs-2"
                    },
                    {
                      "id": "d263cee0-919c-11ea-ad04-b08a2fa13b2d",
                      "type": "DeviceGroup",
                      "name": "AWS-Cisco-NGFW-VMs-1"
                    },
                    {
                      "id": "4d71e0d4-91e0-11ea-b727-a060bdd6dece",
                      "type": "DeviceGroup",
                      "name": "AWS-Cisco-NGFW-VMs-3"
                    }
                  ]
        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/assignment/policyassignments/"
        url = self.server + api_path + pol_id
        r = self.rest_get(url)
        if 'targets' in r.json():
            return r.json()["targets"]
        else:
            return []
  
    def get_nat_policy_id_by_name(self, pol_name):
        """
        Purpose:    Gets policy id
        Parameters: Policy Name
        Returns:    Policy Id

        """
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/ftdnatpolicies"
        url = self.server + api_path + '?offset=0&limit=10000'
        r = self.rest_get(url)
        # Search for policy by name
        if 'items' in r.json():
            for item in r.json()['items']:
                if item['name'] == pol_name:
                    return str(item['id'])    
        return None

    def associate_policy_to_device_group(self, policy_type, policy_name, policy_id, device_grp_name, device_grp_id):
        """
        Purpose:  Associates  Policy to FTD Device Group
        Parameters: Policy type,  Policy name , Policy ID , Device Group name , Device Group ID 
        Returns: Response 
        Raises:
        """
        try:
            api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/assignment/policyassignments"
            url = self.server + api_path
            post_data = {
                        "type": "PolicyAssignment",
                        "policy": {
                                "type": policy_type,
                                "name": policy_name,
                                "id": policy_id
                            },
                        "targets": [
                                {
                                "type": "DeviceGroup",
                                "name": device_grp_name,
                                "id": device_grp_id
                            }
                            ]
                            }
                            
            r = self.rest_post(url, post_data)  
            return r  
        except Exception as e:
            logger.exception(e)
            return None 
        
    def check_http_access_settings(self, platform_policy_id,health_check_port,inside_seczone_name,inside_seczone_id): 
        """
        Purpose: Checks if required HTTP access setting is configured in platform policy
        Parameters: Platform policy ID
        Returns: 'CONFIGURED' or 'UN-CONFIGURED'
        Raises:
        """
        try:
            api_path ='/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/ftdplatformsettingspolicies/' 
            url = self.server + api_path + platform_policy_id  + '/httpaccesssettings?offset=0&limit=25&expanded=true'
            r = self.rest_get(url)
            any_obj_id = self.group_objects['any']
            if 'items' in r.json():
                for item in r.json()['items']:
                    if 'enableHttpServer' in item and 'port' in item:
                        if str(item['port']) == str(health_check_port) and item['enableHttpServer'] is True:
                            if 'httpConfiguration' in item:
                                http_configs = item['httpConfiguration']
                                for config in http_configs:
                                    if config['ipAddress']['name']=='any' and config['ipAddress']['id']==any_obj_id:
                                        int_objects = config['interfaces']['objects']
                                        for int_object in int_objects:
                                            if int_object['name'] == inside_seczone_name and int_object['id']==inside_seczone_id:
                                                return "CONFIGURED"    
            return "UN-CONFIGURED"
        except Exception as e:
            logger.exception(e)
            return "MIS-CONFIGURED"
            
    def create_http_access_settings(self,platform_pol_id,health_check_port,inside_seczone_name,inside_seczone_id):
        """
        Purpose:  Creates HTTP access settings in  platform policy for enabling health check on inside interface
        Parameters: Health check port , security zone
        Returns: Response 
        Raises:
        """

        api_path ='/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/ftdplatformsettingspolicies/' + platform_pol_id + '/httpaccesssettings/' + platform_pol_id
        url = self.server + api_path 
        any_obj_id = self.group_objects['any']
        put_data = {
                    "type": "HttpAccessSetting",
                    "id": platform_pol_id,
                    "enableHttpServer": "true",
                    "port": health_check_port,
                    "httpConfiguration": [
                        {
                        "ipAddress": {
                            "name": "any",
                            "id": any_obj_id,
                            "type": "Network"
                        },
                        "interfaces": {
                            "objects": [
                            {
                                "name": inside_seczone_name,
                                "id": inside_seczone_id,
                                "type": "SecurityZone"
                            }
                            ]
                        }
                        }
                    ]
                    }
        r = self.rest_put(url,put_data)
        return r    
           

class DerivedFMC(FirepowerManagementCenter):
    """
        DerivedFMC is a child class of FirepowerManagementCenter, updates parameters & methods
    """
    def __init__(self, fmc_server, username, password, accesspolicy):
        super().__init__(fmc_server, username, password, accesspolicy)

        self.d_grp_name = ''
        self.a_policy_name = ''
        self.nat_policy_name = '' ##NLB
        self.seczone_name = []
        self.vni_seczone_name = ''
        self.network_obj_name = []
        self.host_obj_name = [] ##NLB

        self.d_grp_id = ''
        self.a_policy_id = ''
        self.nat_policy_id = '' ## NLB
        self.seczone_obj_pair = {}
        self.network_obj_pair = {}
        self.host_obj_pair = {} ##NLB
        self.vni_seczone_id = '' ##GWLB

        self.reachable = False
        self.configuration = {}
        self.configuration_status = ""

        self.network_objects = {}
        self.host_objects = {}
        self.group_objects = {}

    def reach_fmc_(self):
        """
        Purpose:    To get Auth token & update self.reachable value
        Parameters:
        Returns:    self.reachable
        Raises:
        """
        try:
            self.get_auth_token()
            if self.headers['X-auth-access-token']:
                self.reachable = 'AVAILABLE'
        except Exception as e:
            logger.exception(e)
            self.reachable = 'UN-AVAILABLE'
        self.configuration.update({'fmc_reachable': self.reachable})
        return self.reachable

    def set_fmc_configuration(self, is_geneve_support, proxy_type):
        """
        Purpose:    To update DerivedFMC class parameters : fetching required policies' and objects' IDs from FMC
        Parameters:
        Returns:    Object
        Raises:
        """
        if self.d_grp_name:
            self.d_grp_id = self.get_device_grp_id_by_name(self.d_grp_name)
            self.configuration.update({"device_grp": {self.d_grp_name: self.d_grp_id}})
        if self.a_policy_name:
            self.a_policy_id = self.get_access_policy_id_by_name(self.a_policy_name)
            self.configuration.update({"access_policy": {self.a_policy_name: self.a_policy_id}})        
        if is_geneve_support == 'disable' and self.nat_policy_name:
            self.nat_policy_id = self.get_nat_policy_id_by_name(self.nat_policy_name)
            self.configuration.update({"nat_policy": {self.nat_policy_name: self.nat_policy_id}})
        if self.seczone_name:
            for i in self.seczone_name:
                self.seczone_obj_pair.update({i: self.get_security_objectid_by_name(i)})
            self.configuration.update({"inside_outside_security_zones": self.seczone_obj_pair})
        if proxy_type == 'DUAL_ARM' and self.vni_seczone_name:
            self.vni_seczone_id = self.get_security_objectid_by_name(self.vni_seczone_name) 
            self.configuration.update({"vni_security_zone": {self.vni_seczone_name: self.vni_seczone_id}})   
        if self.network_obj_name:
            for i in self.network_obj_name:
                self.network_obj_pair.update({i: self.get_network_objectid_by_name(i)})
            self.configuration.update({"net_objects": self.network_obj_pair})
        if is_geneve_support == 'disable' and self.host_obj_name:
            for i in self.host_obj_name:
                self.host_obj_pair.update({i: self.get_host_objectid_by_name(i)})
            self.configuration.update({"host_objects": self.host_obj_pair})

        self.network_objects, self.host_objects = self.get_network_host_objectids()
        self.group_objects = self.get_group_objects()
        logger.info('fmc_configuration: {}'.format(self.configuration))
        logger.info(json.dumps(self.configuration, separators=(',', ':')))
        return

    def update_fmc_config_user_input(self, d_grp_name, a_policy_name, l_seczone_name,
                                     l_network_obj_name, l_host_obj_name = None, nat_policy_name = None, vni_seczone_name = None):
        """
        Purpose:    To take parameters to DerivedFMC class
        Parameters:
        Returns:
        Raises:
        """
        self.d_grp_name = d_grp_name
        self.a_policy_name = a_policy_name
        self.nat_policy_name = nat_policy_name
        self.seczone_name = l_seczone_name
        self.network_obj_name = l_network_obj_name
        self.host_obj_name = l_host_obj_name
        self.vni_seczone_name = vni_seczone_name
        return

    def check_fmc_configuration(self, is_geneve_support, proxy_type):
        """
        Purpose:    To check if deployed FMC has all required policies / objects created 
        Parameters:
        Returns:    self.configuration_status
        Raises:
        """
        self.configuration_status = 'UN-CONFIGURED'

        if self.reachable == 'AVAILABLE':
            if self.d_grp_id == '':
                return self.configuration_status
            if self.a_policy_id == '':
                return self.configuration_status
            else:
                r = self.get_policy_assign_targets(self.a_policy_id)
                if not utl.find_value_in_list(r, self.d_grp_id):
                    return self.configuration_status
            for (k, v) in self.seczone_obj_pair.items():
                if v is None:
                    return self.configuration_status
            if is_geneve_support == "enable":
                pass
            else:
                for (k, v) in self.host_obj_pair.items():
                    if v is None:
                        return self.configuration_status
            if is_geneve_support == "enable": 
                pass
            elif self.nat_policy_id == '':
                return self.configuration_status
            else:
                r = self.get_policy_assign_targets(self.nat_policy_id)
                if not utl.find_value_in_list(r, self.d_grp_id):
                    return self.configuration_status 
            #Check vni security zone is created for DualArm deployments    
            if proxy_type == 'DUAL_ARM':
                if self.vni_seczone_id == '':
                    return self.configuration_status           
               
        self.configuration_status = 'CONFIGURED'
        self.configuration.update({'fmc_configuration_status': self.configuration_status})
        return self.configuration_status

    def register_ftdv(self, vm_name, ftd_ip, reg_id, nat_id, license_caps, performance_tier):
        """
        Purpose:    Register the device to FMC
        Parameters: Device Name, Mgmgt Ip, Registration & NAT id, Licenses cap
        Returns:    Task id, None
        Raises:
        """
        try:
            logger.info("Registering FTDv: " + vm_name + " to FMC with policy id: " + self.a_policy_name)
            r = self.register_device(vm_name, ftd_ip, self.a_policy_id, reg_id, nat_id, license_caps, performance_tier, self.d_grp_id)
            logger.debug("Register response was: " + str(r.json()))
            if 'type' in r.json():
                if r.json()['type'] == 'Device':
                    logger.info("NGWFv: " + vm_name + " registration started and task ID is: " +
                                r.json()['metadata']['task']['id'])
                    return r.json()['metadata']['task']['id']
        except Exception as e:
            logger.exception(e)
            return None

    def conf_static_rt(self, device_id, int_name, net_name, gateway, metric, is_ipv6=False):
        """
        Purpose:    To configure gateway if required for static_route
        Parameters: Device ID, Interface name, Network type, Network name, Gateway, Metric, is_ipv6:If route is IPv4 or IPv6
        Returns:    response
        Raises:
        """
        # Get the type of the net_name
        if net_name in self.host_objects:
            logger.info(net_name + " is present in host object")
            net_id = self.host_objects[net_name]
            rt_type = 'Host'
        elif net_name in self.network_objects:
            logger.info(net_name + " is present in network object")
            net_id = self.network_objects[net_name]
            rt_type = 'Network'
        elif net_name in self.group_objects:
            logger.info(net_name + " is present in Group Object")
            net_id = self.group_objects[net_name]
            rt_type = 'Group'
        else:
            raise Exception(f"Object {net_name} specified in Configuration json is not found in FMC Host, Network or Group Objects!!!")
        
        # Gateway can be an object or IP literal
        if gateway in self.host_objects:
            gate_way = {
                "object": {
                    "type": "Host",
                    "id": self.host_objects[gateway],
                    "name": gateway
                }
            }
        else:
            gate_way = {
                "literal": {
                    "type": "Host",
                    "value": gateway
                }
            }
        try:
            if is_ipv6:
                r = self.create_static_route_ipv6(device_id, int_name, rt_type, net_name, net_id, gate_way, metric)
            else:
                r = self.create_static_route(device_id, int_name, rt_type, net_name, net_id, gate_way, metric)
            return r
        except Exception as e:
            logger.exception(e)
            return None
        
    def check_and_associate_policy_to_device_group(self, policy_type, policy_name, policy_id):
        """
        Purpose:    Associate policy to FTD device group (if not already associated)
        Parameters: Policy type , Policy name, policy ID
        Returns: 'SUCCESS' or 'FAIL'
        Raises:
        """
        try: 
            #If policy already assigned to device group return success
            r = self.get_policy_assign_targets(policy_id)
            if utl.find_value_in_list(r, self.d_grp_id):
                return 'SUCCESS'
            #Else assign to device group and return success
            else:
                logger.info('Associating Policy %s to FTD device group..' % policy_name)
                r = self.associate_policy_to_device_group(policy_type, policy_name, policy_id, self.d_grp_name, self.d_grp_id)
                if r is None:
                    raise Exception('Error associating policy %s to FTD device group' % policy_name)
                if r.status_code != 200 and r.status_code != 201:
                    logger.error("response: " + str(r.json()))
                    return 'FAIL'
                return 'SUCCESS'
        except Exception as e:
            logger.exception(e)
            return 'FAIL'
        
