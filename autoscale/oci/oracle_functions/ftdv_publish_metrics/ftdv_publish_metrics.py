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

Name:       publish_metrics.py
Purpose:    This python file is used for publishing the ftdv CPU usage and unhealthy vms count
            These classes will be initialized in the oracle function
"""

# Import System Libraries
import io
import logging
import oci
import os
import paramiko
import re
import socket
import sys
import time
import json
import base64

from fdk import response

from fmc import FirepowerManagementCenter
import utility as utl

# Logger Initialization
logging.basicConfig(force=True, level="INFO")
logging.getLogger("paramiko").setLevel(logging.WARNING)
logger = logging.getLogger()

endpoints_for_region = {"eu-frankfurt-1": "https://telemetry-ingestion.eu-frankfurt-1.oraclecloud.com",
                        "us-phoenix-1": "https://telemetry-ingestion.us-phoenix-1.oraclecloud.com",
                        "us-ashburn-1": "https://telemetry-ingestion.us-ashburn-1.oraclecloud.com",
                        "uk-london-1": "https://telemetry-ingestion.uk-london-1.oraclecloud.com",
                        "ca-toronto-1": "https://telemetry-ingestion.ca-toronto-1.oraclecloud.com",
                        "ap-sydney-1": "https://telemetry-ingestion.ap-sydney-1.oraclecloud.com",
                        "ap-melbourne-1": "https://telemetry-ingestion.ap-melbourne-1.oraclecloud.com",
                        "sa-saopaulo-1": "https://telemetry-ingestion.sa-saopaulo-1.oraclecloud.com",
                        "ca-montreal-1": "https://telemetry-ingestion.ca-montreal-1.oraclecloud.com",
                        "sa-santiago-1": "https://telemetry-ingestion.sa-santiago-1.oraclecloud.com",
                        "ap-hyderabad-1": "https://telemetry-ingestion.ap-hyderabad-1.oraclecloud.com",
                        "ap-mumbai-1": "https://telemetry-ingestion.ap-mumbai-1.oraclecloud.com",
                        "ap-osaka-1": "https://telemetry-ingestion.ap-osaka-1.oraclecloud.com",
                        "ap-tokyo-1": "https://telemetry-ingestion.ap-tokyo-1.oraclecloud.com",
                        "eu-amsterdam-1": "https://telemetry-ingestion.eu-amsterdam-1.oraclecloud.com",
                        "me-jeddah-1": "https://telemetry-ingestion.me-jeddah-1.oraclecloud.com",
                        "ap-seoul-1": "https://telemetry-ingestion.ap-seoul-1.oraclecloud.com",
                        "ap-chuncheon-1": "https://telemetry-ingestion.ap-chuncheon-1.oraclecloud.com",
                        "eu-zurich-1": "https://telemetry-ingestion.eu-zurich-1.oraclecloud.com",
                        "me-dubai-1": "https://telemetry-ingestion.me-dubai-1.oraclecloud.com",
                        "uk-cardiff-1": "https://telemetry-ingestion.uk-cardiff-1.oraclecloud.com",
                        "us-sanjose-1": "https://telemetry-ingestion.us-sanjose-1.oraclecloud.com"
                        }
FTDv_SSH_PORT = 22
FTDv_USERNAME = "admin"
SCALE_BASED_ON = "Average"

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
        self.timeout = 60
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
            logger.error("Exception occurred: {}".format(repr(e)))
            return self.FAIL
        except Exception as e:
            logger.error("Exception occurred: {}".format(repr(e)))
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
            self.ssh.connect(self.server, self.port, username, password, timeout=10, allow_agent= False, look_for_keys= False)
            logger.debug("Connection to %s on port %s is successful!" % (self.server, self.port))
            return self.SUCCESS
        except paramiko.AuthenticationException as exc:
            logger.error("Exception occurred: {}".format(repr(exc)))
            return self.AUTH_EXCEPTION
        except paramiko.BadHostKeyException as exc:
            logger.debug("Exception occurred: {}".format(repr(exc)))
            return self.BAD_HOST_KEY_EXCEPTION
        except paramiko.SSHException as exc:
            logger.debug("Exception occurred: {}".format(repr(exc)))
            return self.SSH_EXCEPTION
        except BaseException as exc:
            logger.debug("Exception occurred: {}".format(repr(exc)))
            return self.FAIL


    def invoke_interactive_shell(self):
        """
        Purpose:    Performs an interactive shell action
        Parameters:
        Returns:    a new Channel connected to the remote shell
        """
        try:
            shell = self.ssh.invoke_shell()
        except paramiko.SSHException as exc:
            logger.error("Exception occurred: {}".format(repr(exc)))
            self.ssh.close()
            return self.FAIL, None
        else:
            return self.SUCCESS, shell

    def handle_interactive_session(self, command_set, username, password):

        if self.connect(username, password) != self.SUCCESS:
            logger.error("Unable to connect to server")
            return self.FAIL
        status, shell = self.invoke_interactive_shell()
        if status != self.SUCCESS:
            logger.error("Unable to invoke shell")
            return self.FAIL
        if self.send_cmd_and_wait_for_execution(shell, '\n') is not None:
            for key in command_set:
                set = command_set[key]
                for i in range(0, len(set)):
                    command = set[i]['command'] + '\n'
                    expect = set[i]['expect']
                    output = self.send_cmd_and_wait_for_execution(shell, command, expect)
                    logger.info("Output : {}".format(output))
                    if output is not None:
                        if "CPU utilization" in output:
                            self.ssh.close()
                            return output
                        pass
                    else:
                        self.ssh.close()
                        logger.error("Unable to execute command!")
                        return self.FAIL
        self.ssh.close()
        return self.FAIL

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
                # logger.info("send_cmd_and_wait_for_execution Output : {}".format(str(rcv_buffer)))
                if "The maximum number of management sessions for protocol ssh already exist" in rcv_buffer:
                    return None
            logger.debug("Interactive SSH Output: " + str(rcv_buffer))
            return rcv_buffer
        except Exception as e:
            logger.error("Error occurred: {}".format(repr(e)))
            return None


class publishMetrics:

    def __init__(self, signer, compartment_id, region, instance_pool_id, metric_namespace, metric_resource_grp,
                 cpu_metric_name, ftdv_password, healthcheck_metric_name, elb_id, elb_bs_name, ilb_id, ilb_bs_name):
        self.compartment_id = compartment_id
        self.instance_pool_id = instance_pool_id
        self.service_endpoint = endpoints_for_region[region]
        self.oci_compute_obj = oci.core.ComputeManagementClient(config={}, signer=signer)
        self.instance_obj = oci.core.ComputeClient(config={}, signer=signer)
        self.lb_client_obj = oci.load_balancer.LoadBalancerClient(config={}, signer=signer)
        self.virtual_network_client = oci.core.VirtualNetworkClient(config={}, retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY, signer=signer)
        self.monitoring_client = oci.monitoring.MonitoringClient(config={},service_endpoint=self.service_endpoint, signer=signer)
        self.namespace = metric_namespace
        self.resourceGroup = metric_resource_grp
        self.cpu_metric_name = cpu_metric_name
        self.ftdv_password = ftdv_password
        self.healthcheck_metric_name = healthcheck_metric_name
        self.elb_id = elb_id
        self.elb_bs_name = elb_bs_name
        self.ilb_id = ilb_id
        self.ilb_bs_name = ilb_bs_name

    def calculate_cpu_usage_value(self, ftdv_cpu_usage_list):
        try:
            if not ftdv_cpu_usage_list:
                logger.debug("FTDv CPU usage list is empty.")
                return 0

            scaling_based_on = SCALE_BASED_ON.lower()
            logger.info("PUBLISH METRICS : CPU Usage List : {}".format(ftdv_cpu_usage_list))
            # logger.info("PUBLISH METRICS : Scaling action is done based on the \"{}\" value.".format(scaling_based_on))
            if scaling_based_on == "average":
                val = int(sum(ftdv_cpu_usage_list) / len(ftdv_cpu_usage_list))
                logger.info("PUBLISH METRICS : The average value of CPU utilization is : {}".format(val))
                return val
            elif scaling_based_on == "maximum":
                val = int(max(ftdv_cpu_usage_list))
                logger.info("PUBLISH METRICS : The maximum value of CPU utilization is : {}".format(val))
                return val
        except Exception as err:
            raise Exception("PUBLISH METRICS : Unable to calculate the CPU usage for the FTDv instances. \n Error : {}".format(err))

    def fetch_ftdv_ips(self):
        try:
            ftdv_ips = []
            # Fetching instances in the instance pool
            instances_list = self.oci_compute_obj.list_instance_pool_instances(self.compartment_id,
                                                                               self.instance_pool_id).data
            logger.info("PUBLISH METRICS : FTDv instance count : {}".format(len(instances_list)))
            if len(instances_list) > 0:
                for instance in instances_list:
                    if instance.state.lower() == "running":
                        # instance_details = self.instance_obj.get_instance(instance.id)
                        vnic_attachments = oci.pagination.list_call_get_all_results(
                            self.instance_obj.list_vnic_attachments,
                            compartment_id=instance.compartment_id,
                            instance_id=instance.id).data
                        vnics = [self.virtual_network_client.get_vnic(va.vnic_id).data for va in vnic_attachments]
                        for vnic in vnics:
                            if vnic.public_ip:
                                ftdv_ips.append(vnic.public_ip)
            else:
                logger.info("PUBLISH METRICS : No instances in the instance pool")

            return ftdv_ips

        except Exception as err:
            raise Exception("PUBLISH METRICS : Unable to fetch the ip addresses of the FTDv instances. \n Error : {}".format(err))

    def fetch_cpu_usage_from_ftdv(self):
        cpu_usage_list = []
        command_set_to_show_cpu_usage = {
            "cmd": [
                {
                    "command": "show cpu usage",
                    "expect": "CPU utilization"
                }
            ]
        }
        FAIL = 'FAILURE'
        AUTH_EXCEPTION = 'Authentication Exception Occurred'
        BAD_HOST_KEY_EXCEPTION = 'Bad Key Exception occurred'
        SSH_EXCEPTION = 'SSH Exception Occurred'
        try:
            ftdv_ip_list = self.fetch_ftdv_ips()
            logger.info("PUBLISH METRICS : FTDv Instances list : {}".format(ftdv_ip_list))
            # Check if the list is not empty
            if not ftdv_ip_list:
                logger.error("PUBLISH METRICS : FTDv Instance List is empty. So the CPU value is published as 0")
                cpu_value = 0
            else:
                for ip in ftdv_ip_list:
                    logger.debug("PUBLISH METRICS : Fetching CPU Utilization for the FTDv : {}".format(ip))
                    cnt_ftd = ParamikoSSH(ip, FTDv_SSH_PORT, FTDv_USERNAME, self.ftdv_password)
                    cmd_output = cnt_ftd.handle_interactive_session(command_set_to_show_cpu_usage, FTDv_USERNAME, self.ftdv_password)
                    if cmd_output not in [FAIL, AUTH_EXCEPTION, BAD_HOST_KEY_EXCEPTION, SSH_EXCEPTION]:
                        # pattern = "CPU utilization for 5 seconds\ =\ (.*?)\%;"
                        cpu_usage = int(re.search("CPU utilization for 5 seconds\ =\ (.*?)\%;", cmd_output).group(1))
                        logger.debug("PUBLISH METRICS : CPU Utilization value : {}".format(cpu_usage))
                        cpu_usage_list.append(cpu_usage)
                    else:
                        logger.error("Unable to fetch CPU info for the FTDv {}. Error : {}".format(ip, cmd_output))

                # Calculating CPU value
                cpu_value = self.calculate_cpu_usage_value(cpu_usage_list)

            logger.info("PUBLISH METRICS : CPU Utilization : {}".format(cpu_value))
            return cpu_value
        except Exception as err:
            raise Exception("PUBLISH METRICS : Unable to fetch CPU usage from the FTDv instances. \n Error : {}".format(err))

    def construct_metric_data(self, metric_name, metric_value, metric_unit):
        try:
            post_metric_data = oci.monitoring.models.PostMetricDataDetails(
                metric_data=[
                    oci.monitoring.models.MetricDataDetails(
                        namespace=self.namespace,
                        compartment_id=self.compartment_id,
                        name=metric_name,
                        dimensions={
                            'instancePoolId': self.instance_pool_id},
                        datapoints=[
                            oci.monitoring.models.Datapoint(
                                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time())),
                                value=metric_value)
                        ],
                        resource_group=self.resourceGroup,
                        metadata={'unit': metric_unit})]
            )
            return post_metric_data
        except Exception as err:
            logger.error("Unable to construct post metric data. Error Message : {}".format(err))

    def publish_cpu_metrics(self):
        try:
            cpu_value = self.fetch_cpu_usage_from_ftdv()
            if cpu_value is None:
                cpu_value = 0

            post_metric_data_details = self.construct_metric_data(self.cpu_metric_name, cpu_value, 'Percentage')
            post_metric_data_response = self.monitoring_client.post_metric_data(post_metric_data_details)
            if post_metric_data_response.data.failed_metrics_count == 0:
                logger.info("PUBLISH CPU METRICS : Successfully posted the cpu metrics.")
            else:
                logger.error("PUBLISH CPU METRICS : Unable to post cpu metrics. Reason : {}".format(post_metric_data_response.data))

        except Exception as err:
            post_metric_data_details = self.construct_metric_data(self.cpu_metric_name, 0, 'Percentage')
            post_metric_data_response = self.monitoring_client.post_metric_data(post_metric_data_details)
            if post_metric_data_response.data.failed_metrics_count == 0:
                logger.info("PUBLISH CPU METRICS : Successfully posted the cpu metrics.")
            else:
                logger.error("PUBLISH CPU METRICS : Unable to post cpu metrics. Reason : {}".format(post_metric_data_response.data))

    def get_memory_metric_pair(self, fmc, intersection_list, query_device_dict):

        ftdv_memory_metric_dict = pair_of_metric_name_value = {}
        count = 0
        sum_memory, max_memory, min_memory = (0 for i in range(3))
        for i in range(0, len(intersection_list)):
            device_name = intersection_list[i]
            device_id = query_device_dict[device_name]
            response = fmc.get_memory_metrics_from_fmc(device_id)
            if response is None:
                logger.error("Unable to get metrics for instance: " + device_name)
            try:
                metric_value = response["items"][0]["healthMonitorMetric"]["value"]
                ftdv_memory_metric_dict.update({device_name: metric_value})
                if i == 0:
                    max_memory = metric_value
                    min_memory = metric_value
                else:
                    if metric_value > max_memory:
                        max_memory = metric_value
                    if metric_value < min_memory:
                        min_memory = metric_value
                sum_memory += metric_value
            except Exception as e:
                logger.error("{}".format(e))
            count += 1

        if len(ftdv_memory_metric_dict) > 0:
            pair_of_metric_name_value['Average'] = sum_memory / count
            pair_of_metric_name_value['Maximum'] = max_memory
            pair_of_metric_name_value['Minimum'] = min_memory

        return pair_of_metric_name_value, ftdv_memory_metric_dict

    def get_oci_instances(self):
        try:
            # logger.debug("Fetching instances from the instance pool")
            all_instances_in_instance_pool = self.oci_compute_obj.list_instance_pool_instances(
                compartment_id=self.compartment_id, instance_pool_id=self.instance_pool_id).data
            all_instances_id = [instance.id[-12:] for instance in all_instances_in_instance_pool]
            return all_instances_id
        except Exception as err:
            logger.error("Unable to fetch instances from the instance pool. Reason : {}".format(err))

    def publish_memory_metrics(self, memory_metric_name, fmc_ip, fmc_username, fmc_password, device_grp_name, autoscale_prefix):

        try:
            fmc = FirepowerManagementCenter(fmc_ip, fmc_username, fmc_password)
            fmc.get_auth_token()
            device_grp_id = fmc.get_device_grp_id_by_name(device_grp_name)
            if device_grp_id is None:
                raise ValueError("Unable to find Device Group in FMC: %s " % device_grp_name)
            else:
                logger.debug("FMC Device group ID: %s " % device_grp_id)

            instances_list = self.get_oci_instances()
            append_str = autoscale_prefix + '_'
            oci_instance_name_list = [append_str + suf for suf in instances_list]

            fmc_devices_list, device_id_list = fmc.get_member_list_in_device_grp(device_grp_id)
            query_device_dict = dict(zip(fmc_devices_list, device_id_list))
            intersection_list = utl.intersection(oci_instance_name_list, fmc_devices_list)

            # Update list with memory metrics
            pair_of_metric_name_value, ftdv_memory_metric_dict = self.get_memory_metric_pair(fmc, intersection_list, query_device_dict)
            logger.debug("Memory Utilization of the FTDv instance(s) : {}".format(pair_of_metric_name_value))
            logger.info("Memory Utilization per FTDv devices : {}".format(ftdv_memory_metric_dict))

            post_metric_data_details = self.construct_metric_data(memory_metric_name, pair_of_metric_name_value['Average'], 'Percentage')
            post_metric_data_response = self.monitoring_client.post_metric_data(post_metric_data_details)
            if post_metric_data_response.data.failed_metrics_count == 0:
                logger.info("PUBLISH MEMORY METRICS : Successfully posted the memory metrics.")
            else:
                logger.error("PUBLISH MEMORY METRICS : Unable to post memory metrics. Reason : {}".format(post_metric_data_response.data))

            return True
        except Exception as err:
            logger.error("PUBLISH METRICS : Unable to publish memory usage. Error : {}".format(err))

    def get_backends_health(self, loadbalancer_id, backendset_name):
        try:
            bs_health_status = self.lb_client_obj.get_backend_set_health(load_balancer_id=loadbalancer_id, backend_set_name=backendset_name).data
            return bs_health_status
        except Exception as err:
            raise Exception("PUBLISH METRICS : Unable to get health status of the loadbalancer backends. Error : {}".format(err))

    def publish_health_check_data(self):
        try:
            elb_backends_health = self.get_backends_health(self.elb_id, self.elb_bs_name)
            if elb_backends_health is not None:
                elb_critical_backends = elb_backends_health.critical_state_backend_names
                elb_critical_ips_list = set([elb_backend.split(":")[0] for elb_backend in elb_critical_backends])
                elb_unhealthy_vm_count = len(elb_critical_ips_list)
            else:
                elb_unhealthy_vm_count = 0

            ilb_backend_health = self.get_backends_health(self.ilb_id, self.ilb_bs_name)
            if ilb_backend_health is not None:
                ilb_critical_backends = ilb_backend_health.critical_state_backend_names
                ilb_critical_ips_list = set([ilb_backend.split(":")[0] for ilb_backend in ilb_critical_backends])
                ilb_unhealthy_vm_count = len(ilb_critical_ips_list)
            else:
                ilb_unhealthy_vm_count = 0

            unhealthy_vm_count = max(elb_unhealthy_vm_count, ilb_unhealthy_vm_count)
            logger.info("PUBLISH UNHEALTHY VM COUNT : Unhealthy instance(s) Count : {}".format(unhealthy_vm_count))
            post_metric_data_details = self.construct_metric_data(self.healthcheck_metric_name, unhealthy_vm_count, 'count')
            post_metric_data_response = self.monitoring_client.post_metric_data(post_metric_data_details)
            if post_metric_data_response.data.failed_metrics_count == 0:
                logger.info("PUBLISH UNHEALTHY VM COUNT : Successfully posted the unhealthy vm count to the health_check metrics.")
            else:
                logger.error("PUBLISH UNHEALTHY VM COUNT : Unable to post unhealthy vm count to the health_check metric."
                             " Reason : {}".format(post_metric_data_response.data))

        except Exception as err:
            raise Exception("PUBLISH UNHEALTHY VM COUNT : Unable to update health check data. Error : {}".format(err))

def decrypt_password(signer, crypto_endpoint, cipher, master_key_id):
    try:
        kms_client = oci.key_management.KmsCryptoClient(config={}, signer=signer, service_endpoint=crypto_endpoint)
        decrypt_response = kms_client.decrypt(
            decrypt_data_details=oci.key_management.models.DecryptDataDetails(ciphertext=cipher,
                                                                              key_id=master_key_id)).data
        decrypted_passwd = base64.b64decode(decrypt_response.plaintext).decode('utf-8')
        return decrypted_passwd

    except Exception as e:
        logger.error("PUBLISH METRICS: ERROR IN DECRYPTING FTDv PASSWORD ERROR: {}".format(e))
        return None

def handler(ctx, data: io.BytesIO = None):

    try:
        environmentVariables = ctx.Config()
        # Parameter used to PUBLISH metrics
        compartmentId = environmentVariables["compartment_id"]
        region = environmentVariables["region"]
        instancePoolId = environmentVariables["instance_pool_id"]
        metricNamespaceName = environmentVariables["metric_namespace_name"]
        resourceGroupName = environmentVariables["resource_group_name"]
        cpuMetricName = environmentVariables["cpu_metric_name"]
        # Parameters used to post unhealthy VMs
        healthcheckMetricName = environmentVariables["healthcheck_metric_name"]
        elbId = environmentVariables["elb_id"]
        elbBackendSetName = environmentVariables["elb_backend_set_name"]
        ilbId = environmentVariables["ilb_id"]
        ilbBackendSetName = environmentVariables["ilb_backend_set_name"]
        # ftdv Password decryption related info
        ftdvEncryptedPassword = environmentVariables["ftdv_encrypted_password"]
        cryptEndpoint = environmentVariables["cryptographic_endpoint"]
        master_key_id = environmentVariables["master_key_id"]
        # Memory Metrics
        publish_memory_metric = environmentVariables["publish_memory_metrics"].lower()

    except Exception as e:
        logger.error("PUBLISH METRICS : Error while retrieving environment variables. Error : {0}".format(e))
        return None

    try:
        signer = oci.auth.signers.get_resource_principals_signer()
    except Exception as e:
        logger.error("PUBLISH METRICS : ERROR IN OBTAINING SIGNER. Error : {}".format(e))
        return None

    try:
        # Decrypting the FTDv password
        ftdv_password = decrypt_password(signer, cryptEndpoint, ftdvEncryptedPassword, master_key_id)
        obj = publishMetrics(signer, compartmentId, region, instancePoolId, metricNamespaceName,
                                resourceGroupName, cpuMetricName, ftdv_password, healthcheckMetricName,
                                elbId, elbBackendSetName, ilbId, ilbBackendSetName)
        obj.publish_cpu_metrics()
        obj.publish_health_check_data()
        if publish_memory_metric == "true":
            fmc_ip = environmentVariables["fmc_ip"]
            fmc_username = environmentVariables["fmc_metrics_username"]
            fmcEncryptedPassword = environmentVariables["fmc_metrics_password"]
            fmc_device_grp = environmentVariables["fmc_device_group_name"]
            memory_metric_name = environmentVariables["memory_metric_name"]
            autoscale_prefix = environmentVariables["autoscale_group_prefix"]
            fmc_password = decrypt_password(signer, cryptEndpoint, fmcEncryptedPassword, master_key_id)
            obj.publish_memory_metrics(memory_metric_name, fmc_ip, fmc_username, fmc_password, fmc_device_grp, autoscale_prefix)

    except Exception as e:
        logger.error("PUBLISH METRICS : Unable to run publish-custom-metrics method.Error: {}".format(e))
        return None

    return response.Response(ctx, response_data=json.dumps({"Message": "Publish Alarm Metrics is completed Successfully"}), headers={"Content-Type": "application/json"})
