from .ssh_and_cluster_utils import send_cmd_and_wait_for_execution
import requests
import time
import json
import os

class FirepowerManagementCenter:
    def __init__(self):
        self.server = 'https://' + os.getenv('FMC_IP')
        self.username = os.getenv('FMC_USERNAME')
        self.password = os.getenv('FMC_PASSWORD')
        self.headers = []
        self.domain_uuid = ""
        self.authTokenTimestamp = 0
        self.authTokenMaxAge = 15*60  # seconds - 30 minutes is the max without using refresh

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
          print("Authentication URL: "+ auth_url)
          try:
               # 2 ways of making a REST call are provided:
               # One with "SSL verification turned off" and the other with "SSL verification turned on".
               # The one with "SSL verification turned off" is commented out. If you like to use that then
               # uncomment the line where verify=False and comment the line with =verify='/path/to/ssl_certificate'
               # REST call with SSL verification turned off:
               r = requests.post(auth_url, headers=self.headers, auth=requests.auth.HTTPBasicAuth(self.username, self.password), verify=False)
               print("R in get_auth_token:", r)
               # REST call with SSL verification turned on: Download SSL certificates
               # from your FMC first and provide its path for verification.
               # r = requests.post(auth_url, headers=self.headers,
               #                   auth=requests.auth.HTTPBasicAuth(username,password), verify='/path/to/ssl_certificate')
               auth_headers = r.headers
               auth_token = auth_headers.get('X-auth-access-token', default=None)
               self.domain_uuid = auth_headers.get('domain_uuid', default=None)
               self.headers['X-auth-access-token'] = auth_token
               self.authTokenTimestamp = int(time.time())
               # print("Acquired AuthToken: " + auth_token)
               # print("domain_uuid: " + domain_uuid)
               if auth_token is None:
                    print("auth_token not found")
          except Exception as err:
               print("Error in generating Auth Token")
          return

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
               print("Getting a new authToken")
               self.get_auth_token()
          try:
               print("Requesting(rest_get):" + url)
               r = requests.get(url, headers=self.headers, verify=False)
               status_code = r.status_code
               resp = r.text
               print("Response Status Code(rest_get): " + status_code)
               print("Response body(rest_get): " + str(resp))
               if 200 <= status_code <= 300:
                    pass
               else:
                    print("Exception occurred in rest_get")
                    raise Exception("Error occurred in Get -->"+resp)
          except requests.exceptions.HTTPError as err:
               print("Exception occurred in Connection")
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
        # if the token is too old then get another
        if time.time() > self.authTokenMaxAge + self.authTokenTimestamp:
            print("Getting a new authToken")
            self.get_auth_token()
        try:
            print("Requesting(rest_post): " + url)
            r = requests.post(url, data=json.dumps(post_data), headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            print("Response Status Code(rest_post): ", status_code)
            print("Response body(rest_post): " + str(resp))
            if 201 <= status_code <= 202:
                pass
            else:
                r.raise_for_status()
                print("Exception occurred in rest_post")
                raise Exception("Error occurred in POST --> "+resp)
        except requests.exceptions.HTTPError as err:
            raise Exception("Error in connection --> "+str(err))
        finally:
            if r: r.close()
            return r

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

    def register_device(self, name, mgmt_ip, policy_id, reg_id, nat_id, performanceTier):
          """
          Purpose:    Register the device to FMC
          Parameters: Name of device, Mgmt ip, Access Policy Id, Registration & NAT id, Licenses Caps, Group Id
          Returns:    REST post response
          Raises:
          """
          lic_caps = os.getenv('LICENSE_CAPABILITY')
          lic_caps = lic_caps.split(",")
          print("Registering: "+ name)
          api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords"
          url = self.server + api_path
          post_data = {
               "name": name,
               "hostName": mgmt_ip,
               "regKey": reg_id,
               "natID": nat_id,
               "type": "Device",
               "license_caps": lic_caps,
               "performanceTier": performanceTier,
               "accessPolicy": {
                    "id": policy_id,
                    "type": "AccessPolicy"
               }
          }

          r = self.rest_post(url, post_data)
          return r

    def register_ftdv(self, vm_name, mgmtip, reg_id, nat_id, policy_id, performanceTier='FTDv50'):
        """
        Purpose:    Register the device to FMC
        Parameters: Device Name, Mgmgt Ip, Registration & NAT id, Licenses cap, grp id
        Returns:    Task id, None
        Raises:
        """
        try:
            vm_policy_id = self.get_access_policy_id_by_name(policy_id)
        except Exception as e:
            print("Access Policy doesnot exist")
            return None
        else:
            if vm_policy_id is not None:
                print("Registering FTDv: " + vm_name + " to FMCv with policy id: " + vm_policy_id)
                #grp_id = self.get_device_grp_id_by_name(grp_id)
                r = self.register_device(vm_name, mgmtip, vm_policy_id, reg_id, nat_id,  performanceTier)
                if 'type' in r.json():
                     if r.json()['type'] == 'Device':
                          return r.json()['metadata']['task']['id']
            else:
                print("No policy found")
            return None

    def check_task_status_from_fmc(self, task_id):
          """
          Purpose:    Checks task status from fmc
          Parameters: task id
          Returns:    SUCCESS, FAILED, PENDING, RUNNING
          Raises:
          """
          api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/job/taskstatuses/"
          url = self.server + api_path + task_id
          r = self.rest_get(url)
          status = r.json()['message']
          return status



def configureManager(channel, fmc_ip, reg_id, nat_id):
     cmd = 'configure manager add ' + fmc_ip + ' ' + reg_id + ' ' + nat_id

     status, msg = send_cmd_and_wait_for_execution(channel, cmd)

     print("MESSAGE: "+ msg)

     if "Manager successfully configured." in msg:
          print("MANAGER CONFIGURED")
          return "SUCCESS"
     if "already exists" in msg:
          print("MANAGER ALREADY EXISTS")
          return "EXISTS"
     return "OTHER"

def check_ftdv_reg_status(channel):
     cmd = "show managers"
     status, msg = send_cmd_and_wait_for_execution(channel, cmd)

     if "Completed" in msg:
          return "COMPLETED"
     elif "Pending" in msg:
          return "PENDING"
     elif "No managers" in msg:
          return "NO MANAGERS"
     else:
          return "FAILED"

def ftdv_reg_polling(fmc, task_id, minutes=1):
     """
     Purpose:    To poll both NGFW & FMCv for registration status
     Parameters: FirepowerManagementCenter class object, Minutes
     Returns:    SUCCESS, PARTIAL, FAILED
     Raises:
     """
     # Polling registration completion for specified 'minutes'
     status_in_fmc = ''
     for i in range(9*minutes):
           status_in_fmc = fmc.check_task_status_from_fmc(task_id)
           if status_in_fmc == 'DEVICE_SUCCESSFULLY_REGISTERED':
                return "SUCCESS"
           else:
                print("Sleeping for 10 seconds")
                time.sleep(6)
     if status_in_fmc == "SUCCESS":
          return "PARTIAL"
     return "FAILED"
