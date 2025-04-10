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

Name:       __init__.py
Purpose:    This python file is used for deploying the changes made in the FTDv instance.
"""

import os
import time
import azure.functions as func
from SharedCode.Utils import FMC
import logging as log
from SharedCode.cluster_utils import ClusterUtils

fmc_ip = os.environ.get("FMC_IP")
fmc_domain_uuid = os.environ.get("FMC_DOMAIN_UUID")

def main(req: func.HttpRequest):
        fmc = FMC()

        url = "https://" + fmc_ip + "/api/fmc_config/v1/domain/" + fmc_domain_uuid + "/deployment/deploymentrequests"

        req_body = req.get_json()
        ftdv_name = req_body.get('ftdDevName')
        ftdv_public_ip = req_body.get('ftdPublicIp')
        ftdv_port_number = 22
        ftdv_username = os.environ.get("FTD_USERNAME")
        ftdv_password = os.environ.get("FTD_PASSWORD")
        
        log.warning("DeployConfiguration:::: Deployment Started")
 
        # --------- Checking if the ftdv device is a data node ------------------------------------
        ftdv = ClusterUtils(ftdv_public_ip, ftdv_port_number, ftdv_username, ftdv_password)
        cluster_info_status, cluster_info = ftdv.get_cluster_info()
        if cluster_info_status == "SUCCESS":
            cluster_node = ftdv.get_node_state(cluster_info)
            log.info("DeployConfiguration:::: FTDv {} is a {}".format(ftdv_public_ip, cluster_node))

        # Checking if the data node is discovered in the FMCv
        device_id = fmc.getDevIdByName(ftdv_public_ip, "FTD")
        if cluster_node == "DATA_NODE":
            log.info("DeployConfiguration::: FTDv {} is a data node. Checking if the data node is discovered to the FMCv".format(ftdv_public_ip))
            if device_id == "ERROR":
                 log.error("DeployConfiguration:: FTDv {} is not registered to FMCv.".format(ftdv_public_ip))
            else:
                 log.info("DeployConfiguration:: Data Node {} is discovered in the FMCv".format(ftdv_public_ip))
            return func.HttpResponse("SUCCESS", status_code=200)
        
        elif cluster_node == "CONTROL_NODE":
            post_data = { 
                "type": "DeploymentRequest", 
                "version": "0000000000", 
                "forceDeploy": True, 
                "ignoreWarning": True, 
                "deviceList": [device_id]
            }

            for i in range(5):
                r = fmc.rest_post(url, post_data)
                log.info("deployConfiguration:: FMCv post output {}".format(r))
                if r.status_code == 400:
                    log.info("DeployConfiguration:: Another deployment is in progress. Waiting for the current deployment to get completed")
                    time.sleep(60)
                else:
                    break

            if not (200 <= r.status_code <= 300):
                log.error("DeployConfiguration:::: Deployment failed with status code {}".format(r.status_code))
                log.error("DeployConfiguration::::  Deployment falied status - {}".format(r.content))
                return func.HttpResponse("Deployment failed",status_code=400) 
            
        return func.HttpResponse("SUCCESS", status_code=200)