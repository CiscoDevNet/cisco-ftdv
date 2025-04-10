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
Purpose:    This python file is used for managing autoscaling decisions.
"""

import os
import json
import traceback
import azure.functions as func
import logging as log
from SharedCode.Utils import FMC
from SharedCode import azure_utils as azutils
from datetime import timedelta

def main(req: func.HttpRequest):
    
    try:
        log.warning("AutoScaleManager:: Checking to see if scaling is required")
        subscriptionId = os.environ.get("SUBSCRIPTION_ID")
        resourceGroupName = os.environ.get("RESOURCE_GROUP_NAME")
        vmScalesetName = os.environ.get("VMSS_NAME")
        minFTDCount = int(os.environ.get("MIN_FTD_COUNT"))
        maxFTDCount = int(os.environ.get("MAX_FTD_COUNT"))
        sampleTimeMin = int(os.environ.get("SAMPLING_TIME_MIN"))
        scaleOutThresholdCpu = float(os.environ.get("SCALE_OUT_THRESHLD_CPU"))
        scaleInThresholdCpu = float(os.environ.get("SCALE_IN_THRESHLD_CPU"))
        scaleOutThresholdMem = float(os.environ.get("SCALE_OUT_THRESHLD_MEM"))
        scaleInThresholdMem = float(os.environ.get("SCALE_IN_THRESHLD_MEM"))
        initialDeployMethod = os.environ.get("INITIAL_DEPLOYMENT_MODE")
        scalingPolicy = os.environ.get("SCALING_POLICY")
        metrics = os.environ.get("SCALING_METRICS_LIST")
        
        currentVmCapacity = 0
        scaleStr = ""
        
        # Getting vmss details and vmss vm list
        vmss = azutils.get_vmss_obj()
        vmss_vms = azutils.get_vmss_vm_list()
        vmss_resourceId = vmss.id

        if vmss_resourceId == None: 
            log.error("AutoScaleManager:: Unable to get VM Scale Set ID")
            return func.HttpResponse("ERROR: Unable to get VM Scale Set ID", status_code=400)
        
        currentVmCapacity = vmss.sku.capacity
        log.warning("AutoScaleManager:: Current VM Scale Set capacity: {}".format(currentVmCapacity))

        # If the VMSS capacity is '0' consider this as first deployment and spawn 'minimum FTD count' at a time
        if currentVmCapacity == 0 and minFTDCount != 0:
            log.warning("AutoScaleManager:: Current VM Scale Set capacity is 0, considering it as initial deployment (Minimum FTDv count needed : {})".format(minFTDCount))
            if initialDeployMethod == "BULK":
                log.warning("AutoScaleManager:: Selected Initial deployment mode is Bulk")
                log.warning("AutoScaleManager:: Deploying {} FTDv instances in scale set.".format(minFTDCount))
                cmdStr = "{ \"COMMAND\": \"SCALEOUT\", \"COUNT\": \"" + str(minFTDCount) + "\", \"TYPE\": \"INIT\" }"
                return func.HttpResponse(cmdStr, status_code=200)
            
            else:
                log.warning("AutoScaleManager:: Selected Initial deployment mode is Individual, bringing up FTDv instances one after another")
                cmdStr = "{ \"COMMAND\": \"SCALEOUT\", \"COUNT\": \"1\", \"TYPE\": \"REGULAR\"}"
                return func.HttpResponse(cmdStr, status_code=200)
            
        # If VM Scale set currect capacity is less than minimum FTDv count, we need to scale out
        if currentVmCapacity < minFTDCount:
            log.warning("AutoScaleManager:: Current VM Scale Set capacity({}) is less than minimum FTDv count({}), Scaling out".format(currentVmCapacity, minFTDCount))
            cmdStr = "{ \"COMMAND\": \"SCALEOUT\", \"COUNT\": \"1\", \"TYPE\": \"REGULAR\"}"
            return func.HttpResponse(cmdStr, status_code=200)

        log.info("CPU Scale Out threshold: {}, Scale In threshold: {}".format(scaleOutThresholdCpu, scaleInThresholdCpu))
        # Checking if scale in threshold is less than scale out threshold
        if scaleOutThresholdCpu == 0 and scaleInThresholdCpu == 0:
            log.info("AutoScaleManager:: Autoscaling is disabled as both Scaleout and Scalein threshold is 0")
        elif scaleOutThresholdCpu == scaleInThresholdCpu:
            log.info("AutoScaleManager:: Scale-out and Scale-in thresholds are same. Autoscale is disabled")
            return func.HttpResponse("NOACTION", status_code=200)
        elif scaleOutThresholdCpu < scaleInThresholdCpu:
            log.error("AutoScaleManager:: CPU Metric Scale Out threshold ({}) is less than or equal to Scale In threshold ({}), please specify correct values".format(scaleOutThresholdCpu, scaleInThresholdCpu))
            return func.HttpResponse("ERROR: CPU Metrics ScaleOut threshold is less than or equal to ScaleIn threshold", status_code=400)
        
        # Validating Metrics
        if "CPU" not in metrics and "MEMORY" not in metrics: #check MEMORY
            log.error("AutoScaleManager:: Invalid metrics specified, please choose atleast one of the metrics for scaling.")
            return func.HttpResponse("ERROR: Invalid metrics specified. Can not proceed further", status_code=400)
        
        # Check if we are able to connect to FMCv
        log.info("AutoScaleManager:: Checking FMCv connection")
        fmc = FMC()
        authToken = fmc.getFmcAuthToken()
        if authToken == "ERROR":
            log.error("AutoScaleManager:: Failed to connect to FMCv, can not continue.")
            return func.HttpResponse("ERROR: Failed to connect to FMCv.", status_code=400)
        
        log.info("AutoScaleManager:: Sampling resource utilization at {}min average".format(sampleTimeMin))

        
        ##################################################### Scaling decisions based on metrics #####################################################
        
        log.warning("AutoScaleManager:: Scaling policy selected during deployment : {}".format(scalingPolicy))
        sampleIntervalMin = timedelta(minutes=sampleTimeMin) # Need to validate : supported values - PT1M,PT5M,PT15M,PT30M,PT1H,PT6H,PT12H,P1D
        metric_client = azutils.get_monitor_metric_client() 
        ftdCpuUsage = 0
        groupCpuUsage = 0
        consolidatedCpuUsage = 0
        scaleInRejectFlag = False
        minFtdCpuUsage = 9999
        leastCpuLoadedFtd = ""
        leastCpuLoadedFtdIndex = ""
        memoryMetricsEnabled = False
        
        ftdMemUsage = 0
        groupMemUsage = 0
        consolidatedMemUsage = 0
         
        # Get FTDv's memory usage if 'Memory' metrics is enabled
        if "MEMORY" in metrics:
            memoryMetricsEnabled = True
            log.info("AutoScaleManager:: Memory metrics enabled")
            log.info("AutoScaleManager:: Memory Scale Out threshold : {}, Scale In threshold : {}".format(scaleOutThresholdMem, scaleInThresholdMem))
            
            # Checking if memory scale in threshold is less than scale out threshold
            if scaleOutThresholdMem == scaleInThresholdMem:
                log.info("AutoScaleManager:: Scale-out and Scale-in thresholds are same. Autoscale is disabled")
                return func.HttpResponse("NOACTION", status_code=200)
            elif scaleOutThresholdMem <= scaleInThresholdMem:
                log.error("AutoScaleManager:: Memory Metric ScaleOut threshold ({}) is less than or equal to ScaleIn threshold ({}), please specify correct values".format(scaleOutThresholdMem, scaleInThresholdMem))
                return func.HttpResponse("ERROR: Memory Metrics ScaleOut threshold is less than or equal to ScaleIn threshold", status_code=400)
            
            devIds = fmc.getAllDevID()
            if devIds == {}:
                log.error("AutoScaleManager:: Unable to get device IDs.")
                return func.HttpResponse("ERROR: Unable to get device IDs", status_code=400)

            for vm in azutils.get_vmss_vm_list():
                vmName = vm.name 
                try:
                    for device_name in devIds.keys():
                        if vmName == device_name:
                            devId = str(devIds[device_name])
                            break
                    if len(devId) == 0:
                        log.error("AutoScaleManager:: Unable to get device ID for VM {}".format(vmName))
                        return func.HttpResponse("ERROR: Unable to get device ID for VM", status_code=500)
                except Exception as e:
                    log.error("AutoScaleManager:: Exception occured while parsing device ID response : {}".format(e))
                    return func.HttpResponse("ERROR: Exception occured while parsing device ID response", status_code=500)
                       
                ftdMemResponse = fmc.getFtdMetricsFromFmc(devId)
                if ftdMemResponse is None:
                    log.error("AutoScaleManager:: Unable to get memory metrics for FTDv {}".format(vmName))
                    return func.HttpResponse("ERROR: Unable to get memory metrics for FTDv", status_code=500)
                ftdMemUsage = float(json.loads(ftdMemResponse["items"][0]["response"])["data"]["result"][0]["values"][-1][1])
                if ftdMemUsage == -1:
                    log.error("AutoScaleManager:: Failed to get memory usage of {}".format(vmName))
                    return func.HttpResponse("ERROR: Failed to get memory usage of FTDv", status_code=500)
                
                if ftdMemUsage > scaleInThresholdMem:
                    # No need to scale in
                    scaleInRejectFlag = True
                log.info("AutoScaleManager:: Memory usage of  {} is {}".format(vmName, ftdMemUsage))
                if scalingPolicy == "POLICY-1":
                    if ftdMemUsage > scaleOutThresholdMem:
                        log.warning("AutoScaleManager:: SCALING OUT, Memory usage of {} is {}, which greater than scale out threshold".format(vmName, ftdMemUsage))
                        ftdNameWithHighMemUtilization = vmName
                        break
                elif scalingPolicy == "POLICY-2":
                    groupMemUsage += ftdMemUsage
                
            groupMemUsage = groupMemUsage / vmss.sku.capacity
            if scalingPolicy == "POLICY-2":
                log.info("AutoScaleManager:: Group Memory average usage : {}".format(groupMemUsage))
        
        else:
            scaleOutThresholdMem = 0
            
        if scalingPolicy == "POLICY-2":
            log.info("AutoScaleManager:: Scaling Policy-2 is selected. Getting average CPU Utilization of Scale set.")
            vmss_metrics = metric_client.metrics.list(resource_uri = vmss.id, interval = sampleIntervalMin, metricnames = "Percentage CPU", aggregation = "Average")
            for item in vmss_metrics.value:
                for series in item.timeseries:
                    for data in series.data:
                        if data.average != None:
                            groupCpuUsage = data.average
                            log.debug("AutoScaleManager:: Group CPU average usage : {}".format(groupCpuUsage))
            
            log.info("AutoScaleManager:: Group CPU average usage : {}".format(groupCpuUsage))
        
        for vm in vmss_vms:
            ftdCpuUsage = 0
            vm_metrics = metric_client.metrics.list(resource_uri = vm.id, interval = sampleIntervalMin, metricnames = "Percentage CPU", aggregation = "Average")
            for item in vm_metrics.value:
                for series in item.timeseries:
                    for data in series.data:
                        if data.average != None:
                            ftdCpuUsage = data.average
                            log.debug("AutoScaleManager:: FTDv CPU average usage : {}".format(ftdCpuUsage))
            
            log.info("AutoScaleManager:: Average CPU Utilization of VM {} in last {} minutes is {}".format(vm.name, sampleTimeMin, ftdCpuUsage))
            
            # Store the name of FTDv with minimum utilization to scale-in if needed
            if ftdCpuUsage < minFtdCpuUsage:
                minFtdCpuUsage = ftdCpuUsage
                leastCpuLoadedFtd = vm.name
                leastCpuLoadedFtdIndex = vm.id
            
            if scalingPolicy == "POLICY-1":
                # Average Usage of Individual instance
                consolidatedCpuUsage = ftdCpuUsage
                consolidatedMemUsage = ftdMemUsage
            
            elif scalingPolicy == "POLICY-2":
                consolidatedCpuUsage = groupCpuUsage
                consolidatedMemUsage = groupMemUsage
            
            else:
                log.error("AutoScaleManager:: Invalid Scaling Policy {}".format(scalingPolicy))
                return func.HttpResponse("ERROR: Invalid Scaling Policy", status_code=400)
            
            # If CPU utilization is greater than scale-out threshold then scale-out
            # If memory metrics is not enabled then consolidated memory utilization is set to 0
            if scaleOutThresholdCpu == 0:
                log.info("AutoScaleManager:: Autoscaling is disabled hence no scaling is required")
                return func.HttpResponse("NOACTION", status_code=200)
            elif consolidatedCpuUsage > scaleOutThresholdCpu or consolidatedMemUsage > scaleOutThresholdMem:
                # If current scale set capacity us equal to max FTD count, do nothing
                # If current scale set capacity is more than max FTD count (Ideally, should never happen), do nothing
                if currentVmCapacity >= maxFTDCount:
                    log.warning("AutoScaleManager:: NO ACTION, Current scale set capacity is {}, which is greater than or equal to max FTD count ({}). No action required.".format(currentVmCapacity, maxFTDCount))
                    return func.HttpResponse("NOACTION", status_code=200)
                
                if scalingPolicy == "POLICY-1":
                    log.warning("AutoScaleManager:: Avg CPU Utilization of VM({}) in last {}min is {}".format(vm.name, sampleTimeMin, consolidatedCpuUsage))
                    if memoryMetricsEnabled and (consolidatedMemUsage > scaleOutThresholdMem):
                        log.warning("AutoScaleManager:: Avg Memory Utilization of VM({}) is {}".format(ftdNameWithHighMemUtilization, consolidatedMemUsage))
                    log.warning("AutoScaleManager:: Scaling Out")
                    
                if scalingPolicy == "POLICY-2":
                    log.warning("AutoScaleManager:: Average CPU Utilization of Scale Set in last {}min is {}".format(sampleTimeMin, consolidatedCpuUsage))
                    if memoryMetricsEnabled:
                        log.warning("AutoScaleManager:: Average Memory utilization of Scale set is {}".format(consolidatedMemUsage))
                    log.warning("AutoScaleManager:: SCALING OUT, Average resource utilization of scale set is more than scale out threshold")
                
                scaleStr = "{ \"COMMAND\": \"SCALEOUT\", \"COUNT\": \"1\", \"TYPE\": \"REGULAR\" }"
                return func.HttpResponse(scaleStr, status_code=200)

            # If any VM's CPU utilization is greater than scale-in threshold then scale-in is not required
            elif ftdCpuUsage > scaleInThresholdCpu:
                scaleInRejectFlag = True
                log.warning("AutoScaleManager:: NO ACTION, CPU utilization of {} is {}, which greater than scale in threshold, scaling in is not required".format(vm.name, ftdCpuUsage))
        
        # If scaleInRejectFlag is not set, it means all the VMs' CPU and Memory Utilization is less than or equal to Scale-In threshold
        # We will consider only the least CPU consuming FTDv for Scale-In operation
        if scaleInRejectFlag == False:
            # If current capacity is less than or equal to minimum FTD count required then scale-in should not be done
            if currentVmCapacity <= minFTDCount:
                log.warning("AutoScaleManager:: Scale-In needed but currect VMSS capacity ({}) is less than or equal to minimum FTD count ({}) needed. No action taken.".format(currentVmCapacity, minFTDCount))
                return func.HttpResponse("NOACTION", status_code=200)
            
            networkInterfaceName = os.environ.get("MNGT_NET_INTERFACE_NAME")
            ipConfigurationName = os.environ.get("MNGT_IP_CONFIG_NAME")
            publicIpAddressName = os.environ.get("MNGT_PUBLIC_IP_NAME")
            
            idx = leastCpuLoadedFtdIndex.split("/")[-1]
            
            publicIp = azutils.get_vmss_public_ip(idx, networkInterfaceName, ipConfigurationName, publicIpAddressName)
            log.warning("AutoScaleManager:: SCALING IN, CPU Utilization of all the FTDs is less than or equal to CPU Scale-In threshold ({}).".format(scaleInThresholdCpu))
            if memoryMetricsEnabled:
                log.warning("AutoScaleManager:: SCALING IN, Memory Utilization of all the FTDs is less than or equal to Memory Scale-In threshold ({}).".format(scaleInThresholdMem))
            
            log.warning("AutoScaleManager:: Least loded FTD is {} with utilization {}".format(leastCpuLoadedFtd, minFtdCpuUsage))
            scaleStr = "{ \"COMMAND\": \"SCALEIN\", \"ftdDevName\": \"" + leastCpuLoadedFtd + "\", \"ftdPublicIp\": \"" + publicIp + "\", \"instanceid\" : \"" + idx + "\"  }"
            return func.HttpResponse(scaleStr, status_code=200)
        
        log.warning("AutoScaleManager:: FTD VMSS utilization is within threshold. No action needed")
        return func.HttpResponse("NOACTION", status_code=200)
    except Exception as e:
        log.error("AutoScaleManager:: Exception occurred : {}".format(e))
        log.error("AutoScaleManager:: Exception occurred : {}".format(traceback.format_exc()))
        return func.HttpResponse("ERROR: Exception occurred", status_code=500)
