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

Name:       __init__.py
Purpose:    This python file is used for deploying FMC configuration changes.
"""

import os
import azure.functions as func
from SharedCode.Utils import FMC, getFtdDeviceId
import logging as log

fmc_ip = os.environ.get("FMC_IP")
fmc_domain_uuid = os.environ.get("FMC_DOMAIN_UUID")


def _get_deployable_device(fmc, device_id):
        url = "https://" + fmc_ip + "/api/fmc_config/v1/domain/" + fmc_domain_uuid + "/deployment/deployabledevices?expanded=true&limit=1000"
        r = fmc.rest_get(url)
        for item in r.json().get("items", []):
                if item.get("id") == device_id:
                        return item
        return None


def _get_deployable_devices(fmc):
        url = "https://" + fmc_ip + "/api/fmc_config/v1/domain/" + fmc_domain_uuid + "/deployment/deployabledevices?expanded=true&limit=1000"
        r = fmc.rest_get(url)
        return r.json().get("items", [])


def _is_deployment_in_progress(deployable_device):
        if not deployable_device:
                return False

        message = (deployable_device.get("message") or "").lower()
        return bool(deployable_device.get("isDeploying")) or "another deployment is in progress" in message


def _get_request_devices(req_body):
        if isinstance(req_body, list):
                return req_body
        if isinstance(req_body, dict) and isinstance(req_body.get("devices"), list):
                return req_body.get("devices")
        return [req_body]


def main(req: func.HttpRequest):
        fmc = FMC()

        url = "https://" + fmc_ip + "/api/fmc_config/v1/domain/" + fmc_domain_uuid + "/deployment/deploymentrequests"

        req_body = req.get_json()
        req_devices = _get_request_devices(req_body)

        log.warning("DeployConfiguration:::: Deployment Started")
        device_ids = []
        for req_device in req_devices:
            ftdv_name = req_device.get('ftdDevName')
            device_id = getFtdDeviceId(fmc, req_device)
            if device_id == "ERROR":
                log.error("DeployConfiguration:::: Failed to get Device ID for {}".format(ftdv_name))
                return func.HttpResponse("Unable to get Device ID", status_code=400)
            device_ids.append(device_id)

        deployable_devices = _get_deployable_devices(fmc)
        deployable_by_id = {item.get("id"): item for item in deployable_devices}
        pending_deployable_devices = [
            deployable_by_id[device_id] for device_id in device_ids if device_id in deployable_by_id
        ]

        if not pending_deployable_devices:
            log.info("DeployConfiguration:::: No pending deployment for requested devices")
            return func.HttpResponse("SUCCESS", status_code=200)

        if any(_is_deployment_in_progress(item) for item in pending_deployable_devices):
            log.info("DeployConfiguration:::: Deployment already in progress")
            return func.HttpResponse("Deployment already in progress", status_code=202)

        post_data = { 
            "type": "DeploymentRequest", 
            "version": pending_deployable_devices[0]["version"],
            "forceDeploy": True, 
            "ignoreWarning": True, 
            "deviceList": [item["id"] for item in pending_deployable_devices]
        }

        # //----------for some reason generic rest api fails            
        # var client = new RestClient(uri);
        # var request = new RestRequest(Method.POST);
        # client.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
        # request.AddHeader("cache-control", "no-cache");
        # request.AddHeader("Connection", "keep-alive");
        # request.AddHeader("content-length", "163");
        # request.AddHeader("accept-encoding", "gzip, deflate");
        # request.AddHeader("Cache-Control", "no-cache");
        # request.AddHeader("Accept", "*/*");
        # request.AddHeader("Content-Type", "application/json");
        # request.AddHeader("X-auth-access-token", authToken);
        # request.AddParameter("undefined", body, ParameterType.RequestBody);
        # IRestResponse response = client.Execute(request);

        try:
            r = fmc.rest_post(url, post_data)
        except Exception as err:
            deployable_devices = _get_deployable_devices(fmc)
            if any(_is_deployment_in_progress(item) for item in deployable_devices) or "another deployment is in progress" in str(err).lower():
                log.info("DeployConfiguration:::: Deployment already in progress")
                return func.HttpResponse("Deployment already in progress", status_code=202)

            log.error("DeployConfiguration:::: Deployment request failed: {}".format(repr(err)))
            return func.HttpResponse("Deployment failed", status_code=400)

        if not (200 <= r.status_code <= 300):
            log.error("DeployConfiguration:::: Deployment failed with status code {}".format(r.status_code))
            log.error("DeployConfiguration::::  Deployment falied status - {}".format(r.content))
            return func.HttpResponse("Deployment failed",status_code=400) 
            
        log.info("DeployConfiguration:::: Deployment request accepted for {} devices".format(len(pending_deployable_devices)))
        return func.HttpResponse("DEPLOYMENT_STARTED", status_code=202)
