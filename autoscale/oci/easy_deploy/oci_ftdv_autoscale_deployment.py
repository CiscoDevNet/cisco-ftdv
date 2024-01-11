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

Name:       oci_ftdv_autoscale_deployment.py
Purpose:    This python file has terraform deployment and oracle function
            deployment steps to deploy the end-to-end solution.
"""

import json
import base64
import sys
import time
import re
import oci

import os
import shutil
import subprocess
from zipfile import ZipFile

from oci_ftdv_autoscale_teardown import Cleanup

class Function_Deploy:
    def __init__(self):
        self.region_dict = {'ap-sydney-1':'SYD',
        'ap-melbourne-1':'MEL',
        'sa-saopaulo-1':'GRU',
        'ca-montreal-1':'YUL',
        'ca-toronto-1':'YYZ',
        'sa-santiago-1':'SCL',
        'eu-frankfurt-1':'FRA',
        'ap-hyderabad-1':'HYD',
        'ap-mumbai-1':'BOM',
        'ap-osaka-1':'KIX',
        'ap-tokyo-1':'NRT',
        'eu-amsterdam-1':'AMS',
        'me-jeddah-1':'JED',
        'ap-seoul-1':'ICN',
        'ap-chuncheon-1':'YNY',
        'eu-zurich-1':'ZRH',
        'me-dubai-1':'DXB',
        'uk-london-1':'LHR',
        'uk-cardiff-1':'CWL',
        'us-ashburn-1':'IAD',
        'us-phoenix-1':'PHX',
        'us-sanjose-1':'SJC'}

    def execute(self, cmd):
        subprocess.call(cmd, shell=True)

    def deploy(self, region_key, compartment_id, app_name, autoscale_prefix, context_registry_path, directory):
        try:
            repo_name = autoscale_prefix + "_" + directory
            container_repo_path = context_registry_path + repo_name
            cmd1 = "fn use context " + region_key
            cmd2 = "fn update context oracle.compartment-id " + compartment_id
            cmd3 = "fn update context registry " + container_repo_path
            cmd4 = "fn deploy --app " + app_name
            self.execute(cmd1)
            self.execute(cmd2)
            self.execute(cmd3)
            self.execute(cmd4)
            return True
        except Exception as e:
            print("EXCEPTION OCCURRED: "+ repr(e))
            return False

    def deploy_oracle_functions(self, application_name, region_key, compartment_name, compartment_id, profile_name, object_storage_namespace, authorization_token):
        print("Application Name: ",application_name, end='\n')
        print("Region: ",region_key, end='\n')
        print("Profile Name: ",profile_name, end="\n")
        print("Compartment Name: ",compartment_name, end="\n")
        print("Compartment OCID: ",compartment_id, end="\n")
        print("Object Storage Namespace: ",object_storage_namespace, end="\n")

        if region_key in self.region_dict.keys():
            region_value = self.region_dict[region_key]
        else:
            print("REGION IS NOT CORRECT, PLEASE VERIFY AGAIN")
            return

        region_link = region_value.lower()+ ".ocir.io"
        function_api_url = "https://functions."+region_key+".oraclecloud.com"
        context_registry_path = region_link +"/"+ object_storage_namespace +"/"

        context_set_cmd = "fn create context " + compartment_name + " --provider oracle" + " --api-url " + function_api_url + " --registry " + context_registry_path
        self.execute(context_set_cmd)

        root_path = os.getcwd()
        os.chdir(root_path)
        try:
            os.mkdir('oracle-functions')
        except Exception as e:
            shutil.rmtree("oracle-functions")
            os.mkdir('oracle-functions')

        # specifying the zip file name
        file_name = "Oracle-Functions.zip"

        # opening the zip file in READ mode
        with ZipFile(file_name, 'r') as zip:
            # printing all the contents of the zip file
            zip.printdir()

            # extracting all the files
            print('Extracting all the files now...')
            zip.extractall(path='oracle-functions')
            print('Done!')

        os.chdir("oracle-functions")
        oracle_functions_path = os.getcwd()
        all_directories = os.listdir()

        cmd4 = "docker login -u " + "'" + object_storage_namespace +"/"+ profile_name +"' " + region_link +" -p "+"'"+authorization_token+"'"
        self.execute(cmd4)

        autoscale_prefix = application_name.split("_application")[0]
        for directory in all_directories:
            os.chdir(directory)
            deploy_response = self.deploy(region_key, compartment_id, application_name, autoscale_prefix, context_registry_path, directory)
            if deploy_response == False:
                print("ONE OF THE COMMAND EXECUTION FAILED, CHECK STDERR")
                os.chdir(root_path)
                shutil.rmtree("oracle-functions")
                return False
            os.chdir(oracle_functions_path)

        os.chdir(root_path)
        shutil.rmtree("oracle-functions")
        return True

class Stack_Deploy:
    def __init__(self):
        self.signer = self.get_signer()
        self.resourceManagerClient = oci.resource_manager.ResourceManagerClient(config={}, signer=self.signer)
        self.resourceManagerClientCompositeOperation = oci.resource_manager.ResourceManagerClientCompositeOperations(client = self.resourceManagerClient)
        self.functions_client = oci.functions.FunctionsManagementClient(config={}, signer=self.signer)
        self.retry = 3

    def get_signer(self):
        try:
            # get the cloud shell delegated authentication token
            delegation_token = open('/etc/oci/delegation_token', 'r').read()
            # create the api request signer
            signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(delegation_token = delegation_token)
            return signer
        except Exception as e:
            print("ERROR IN OBTAINING SIGNER "+ repr(e),end="\n")

    def get_application_id(self, compartmentId, appName):
        try:

            list_applications_response = self.functions_client.list_applications(
                compartment_id = compartmentId,
                lifecycle_state = "ACTIVE",
                display_name = appName).data

            return list_applications_response[0].id
        except Exception as e:
            return None

    def parameter_validation(self):
        try:
            parameters = self.load_parameters("deployment_parameters.json")

            tenancy_ocid = str(parameters["tenancy_ocid"])
            if tenancy_ocid[0:14] != "ocid1.tenancy." or not(re.match("[a-z0-9\.]*$",tenancy_ocid)):
                raise Exception("tenancy_ocid is incorrect in deployment_parameters.json, Please verify again")

            compartmentId = str(parameters["compartment_id"])
            if compartmentId[0:18] != "ocid1.compartment." or not(re.match("[a-z0-9\.]*$",compartmentId)):
                raise Exception("compartment_id is incorrect in deployment_parameters.json, Please verify again")

            regionKey = str(parameters["region"])
            if not(re.match(r"^[A-Za-z]*(.-)(.[A-Za-z]*)(.-)([0-9]$)",regionKey)):
                raise Exception("region is incorrect in deployment_parameters.json, Please verify again")

            lb_size = str(parameters["lb_size"])
            if lb_size not in ["100Mbps", "10Mbps", "10Mbps-Micro", "400Mbps", "8000Mbps"]:
                raise Exception("lb_size is incorrect, Please verify again")

            availability_domain = str(parameters["availability_domain"]).split(",")
            for ad in availability_domain:
                if not(re.match("^[A-Z](.[a-z])*(.:)(.[A-Z])+(.-)(.[A-Z])+(.[0-9]$)",ad)):
                    raise Exception("availability_domain is incorrect, Please verify again")

            min_and_max_instance_count = str(parameters["min_and_max_instance_count"])
            min_count, max_count = min_and_max_instance_count.split(',')
            if not min_count.isdigit() or not max_count.isdigit():
                raise Exception("min_and_max_instance_count is not a number, Please verify again")
            if int(min_count) > int(max_count):
                raise Exception("min_and_max_instance_count is incorrect, min cant be greater than or equals to max, Please verify again")
            if int(max_count) > 25:
                raise Exception("min_and_max_instance_count is incorrect, maximum instance count can not be more than 25 (FMCv Limit).")

            autoscale_group_prefix = str(parameters["autoscale_group_prefix"])
            if not (re.match("^[a-z][a-z0-9_]*[a-z0-9]$",autoscale_group_prefix)):
                raise Exception("autoscale_group_prefix is incorrect in deployment_parameters.json, Please verify again")
            if len(autoscale_group_prefix) > 25:
                raise Exception("autoscale_group_prefix in deployment_parameters.json, length must be less than 25 characters, Please verify again")
            if autoscale_group_prefix[:3] == "oci" or autoscale_group_prefix[:4] == "orcl":
                raise Exception("autoscale_group_prefix in deployment_parameters.json, please don't use reserved characters like oci or orcl, Please verify again")

            mgmt_subnet_ocid = str(parameters["mgmt_subnet_ocid"])
            if not mgmt_subnet_ocid.startswith("ocid1.subnet."):
                raise Exception("mgmt_subnet_ocid is incorrect, Please verify again")

            mgmt_nsg_ocid = str(parameters["mgmt_nsg_ocid"])
            if not mgmt_nsg_ocid.startswith("ocid1.networksecuritygroup."):
                raise Exception("mgmt_nsg_ocid is incorrect, Please verify again")

            diag_subnet_ocid = str(parameters["diag_subnet_ocid"])
            if not diag_subnet_ocid.startswith("ocid1.subnet."):
                raise Exception("diag_subnet_ocid is incorrect, Please verify again")

            diag_nsg_ocid = str(parameters["diag_nsg_ocid"])
            if not diag_nsg_ocid.startswith("ocid1.networksecuritygroup."):
                raise Exception("diag_nsg_ocid is incorrect, Please verify again")

            inside_subnet_ocid = str(parameters["inside_subnet_ocid"])
            if not inside_subnet_ocid.startswith("ocid1.subnet."):
                raise Exception("inside_subnet_ocid is incorrect, Please verify again")

            inside_nsg_ocid = str(parameters["inside_nsg_ocid"])
            if not inside_nsg_ocid.startswith("ocid1.networksecuritygroup."):
                raise Exception("inside_nsg_ocid is incorrect, Please verify again")

            outside_subnet_ocid = str(parameters["outside_subnet_ocid"])
            if not outside_subnet_ocid.startswith("ocid1.subnet."):
                raise Exception("outside_subnet_ocid is incorrect, Please verify again")

            outside_nsg_ocid = str(parameters["outside_nsg_ocid"])
            if not outside_nsg_ocid.startswith("ocid1.networksecuritygroup."):
                raise Exception("outside_nsg_ocid is incorrect, Please verify again")

            function_subnet_ocid = str(parameters["function_subnet_ocid"])
            if not function_subnet_ocid.startswith("ocid1.subnet."):
                raise Exception("function_subnet_ocid is incorrect, Please verify again")
            
            elb_listener_port = str(parameters["elb_listener_port"])
            port_list = elb_listener_port.split(',')
            if len(port_list) != len(set(port_list)):
                raise Exception("elb_listener_port, duplicate ports entered, please verify again")
            for port in port_list:
                if not port.isdigit():
                    raise Exception("elb_listener_port, one of the ports is not a number, Please verify again")
                if int(port) > 65535 or int(port) < 1:
                    raise Exception("elb_listener_port, one of the ports is not in the allowed range, Please verify again")

            ilb_listener_port = str(parameters["ilb_listener_port"])
            port_list = ilb_listener_port.split(',')
            if len(port_list) != len(set(port_list)):
                raise Exception("ilb_listener_port, duplicate ports entered, please verify again")
            for port in port_list:
                if not port.isdigit():
                    raise Exception("ilb_listener_port, one of the ports is not a number, Please verify again")
                if int(port) > 65535 or int(port) < 1:
                    raise Exception("ilb_listener_port, one of the ports is not in the allowed range, Please verify again")

            health_check_port = str(parameters["health_check_port"])
            if not health_check_port.isdigit():
                raise Exception("health_check_port is not a number, Please verify again")
            if int(health_check_port) > 65535 or int(health_check_port) < 1:
                raise Exception("health_check_port is incorrect, port is not in the allowed range, Please verify again")

            instance_shape = str(parameters["instance_shape"])
            if instance_shape not in ["VM.Standard2.4", "VM.Standard2.8"]:
                raise Exception("instance_shape is incorrect, Please verify again")

            lb_bs_policy = str(parameters["lb_bs_policy"])
            if lb_bs_policy not in ["ROUND_ROBIN", "LEAST_CONNECTIONS", "IP_HASH"]:
                raise Exception("lb_bs_policy is incorrect, Please verify again")

            cpu_scaling_thresholds = str(parameters["cpu_scaling_thresholds"])
            cpu_min_threshold, cpu_max_threshold = cpu_scaling_thresholds.split(',')
            if not cpu_min_threshold.isdigit() or not cpu_max_threshold.isdigit():
                raise Exception("cpu_scaling_thresholds is not a number, Please verify again")
            if int(cpu_min_threshold) > int(cpu_max_threshold):
                raise Exception("cpu_scaling_thresholds is incorrect, min cant be greater than or equals to max, Please verify again")
            if int(cpu_min_threshold) > 100 or int(cpu_min_threshold) <0:
                raise Exception("cpu_scaling_thresholds min value should be between 0 and 100, Please verify again")
            if int(cpu_max_threshold) > 100 or int(cpu_max_threshold) <0:
                raise Exception("cpu_scaling_thresholds max value should be between 0 and 100, Please verify again")

            memory_scaling_thresholds = str(parameters["memory_scaling_thresholds"])
            memory_min_threshold, memory_max_threshold = memory_scaling_thresholds.split(',')
            if not memory_min_threshold.isdigit() or not memory_max_threshold.isdigit():
                raise Exception("memory_scaling_thresholds is not a number, Please verify again")
            if int(memory_min_threshold) > int(memory_max_threshold):
                raise Exception("memory_scaling_thresholds is incorrect, min cant be greater than or equals to max, Please verify again")
            if int(memory_min_threshold) > 100 or int(memory_min_threshold) <0:
                raise Exception("memory_scaling_thresholds min value should be between 0 and 100, Please verify again")
            if int(memory_max_threshold) > 100 or int(memory_max_threshold) <0:
                raise Exception("memory_scaling_thresholds max value should be between 0 and 100, Please verify again")

            fmc_ip = str(parameters["fmc_ip"])
            if not (re.match("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",fmc_ip)):
                raise Exception("fmc_ip is incorrect, Please verify again")

            key_id = str(parameters["master_encryption_key_id"])
            if not key_id.startswith("ocid1.key."):
                raise Exception("master_encryption_key_id is incorrect, Please verify again")

            endpoint_url = str(parameters["cryptographic_endpoint"])
            if not (re.match("^((https?:[/][/])?(\w+[.-])+com)",endpoint_url)):
                raise Exception("cryptographic_endpoint is incorrect, Please verify again")            
            
            return True
        except Exception as e:
            print(e)
            return False

    def load_parameters(self, file_name):
        try:
            # reading the data from the file
            with open(file_name) as f:
                data = f.read()

            # reconstructing the data as a dictionary
            all_parameters = json.loads(data)
            f.close()
            return all_parameters

        except Exception as e:
            print(e)
            return None

    def zip_to_base64(self, file_name):
        with open(file_name, "rb") as f:
            bytes = f.read()
            encode_string = base64.b64encode(bytes)

        return encode_string.decode('utf-8')

    def create_stack(self, compartmentId, stackName, zipFileName, variableFileName, stackDescription=None):
        try:
            create_stack_response = self.resourceManagerClient.create_stack(
            create_stack_details = oci.resource_manager.models.CreateStackDetails(
                compartment_id = compartmentId,
                config_source=oci.resource_manager.models.CreateZipUploadConfigSourceDetails(
                    config_source_type = "ZIP_UPLOAD",
                    zip_file_base64_encoded = self.zip_to_base64(zipFileName)),
                display_name = stackName,
                description = stackDescription,
                variables = self.load_parameters(variableFileName),
                terraform_version="0.14.x")).data
            return create_stack_response

        except Exception as e:
            print(repr(e))
            return None

    def create_resources(self, stackId):
        try:
            create_job_details = oci.resource_manager.models.CreateJobDetails(
            stack_id = stackId,
            job_operation_details = oci.resource_manager.models.CreateApplyJobOperationDetails(
                operation = "APPLY",
                execution_plan_strategy = "AUTO_APPROVED"))

            create_resource_response = self.resourceManagerClientCompositeOperation.create_job_and_wait_for_state(create_job_details, wait_for_states=["SUCCEEDED","FAILED","CANCELED","UNKNOWN_ENUM_VALUE"], waiter_kwargs={"max_wait_seconds":1800}).data
            return create_resource_response
        
        except Exception as e:
            print(e)
            return None

    def create_logs(self, jobId, stackName):
        try:
            get_job_logs_content_response = self.resourceManagerClient.get_job_logs_content(job_id=jobId).data
            log_file_name = stackName + "_Error_log.log"
            log_file = open(log_file_name, "w")
            log_file.write(get_job_logs_content_response)
            log_file.close()
            return True
        except Exception as e:
            print(e)
            return None

if __name__ == "__main__":
    try:
        deployer = Stack_Deploy()
        if deployer.parameter_validation():
            print("Parameters verfied successfully")
        else:
            exit(1)

        all_parameters = deployer.load_parameters("deployment_parameters.json")
        compartmentId = all_parameters["compartment_id"]
        autoscale_prefix = all_parameters["autoscale_group_prefix"]
        stack1_Name = autoscale_prefix + "_stack_1"        
        stack2_Name = autoscale_prefix + "_stack_2"

        print("\nSTACK-1 NAME : {}".format(stack1_Name))
        print("STACK-2 NAME : {}".format(stack2_Name))

        cleaner = Cleanup()
    ###############################################################################################
        try:
            print("\n{} Creation started ...".format(stack1_Name))
            stack1_response = deployer.create_stack(compartmentId, stack1_Name, "template1.zip", "deployment_parameters.json")
            if stack1_response == None:
                print("ERROR IN CREATING STACK {0}".format(stack1_Name))
                exit(1)
            else:
                print("{0} Created Successfully with OCID: {1}".format(stack1_Name, stack1_response.id))

            print("\nResources Creation for {} started... it will take some time be patient".format(stack1_Name))
            resource1_create_response = deployer.create_resources(stack1_response.id)
            if resource1_create_response == None:
                print("EXCEPTION IN CREATING RESOURCES OF {}".format(stack1_Name))
                print("FOR FURTHER DETAILS SEE THE LOG OF RECENT APPLY JOB IN {}".format(stack1_Name))
                print("PLEASE MANUALLY DESTROY AND DELETE")
                exit(1)

            if resource1_create_response.lifecycle_state != "SUCCEEDED":
                log_response = deployer.create_logs(resource1_create_response.id, stack1_Name)
                if log_response == True:
                    print(f"\nAN ERROR HAS BEEN OCCURED WHILE CREATNG RESOURCES FOR {stack1_Name}")
                    print(f"PLEASE GO THROUGH FILE {stack1_Name}_Error.log IN CURRENT DIRECTORY, FOR DETAILED LOGS")
                    print(f"STACK {stack1_Name} WILL BE ROLLEDBACK")
                else:
                    print("ERROR IN CREATING RESOURCES OF {}".format(stack1_Name))
                    print("FOR FURTHER DETAILS SEE THE LOG OF RECENT APPLY JOB IN {}".format(stack1_Name))
                    print("ROLLING BACK UNFINISHED STACK, PLEASE MANUALLY VERIFY TOO")
                
                destroy_stack1_response = cleaner.destroy_stack(1, stack1_response.id)
                if destroy_stack1_response.lifecycle_state != "SUCCEEDED":
                    print("ERROR OCCURRED WHILE DESTROYING RESOURCES OF STACK-1, PLEASE SEE THE LOGS IN OCI AND MANUALLY DESTROY AND DELETE")
                    exit(1) 
                cleaner.delete_stack(1, stack1_response.id)
                exit(1)
            else:
                print("Resources Created Successfully for {}".format(stack1_Name))
                print("For full details of resource creation, look for Job Name: {0} with OCID: {1} in the stack {2}".format(resource1_create_response.display_name, resource1_create_response.id, stack1_Name))
        except Exception as e:
            print(e)
            exit(1)
    ###############################################################################################
        try:
            print("\nStarting Oracle-Function deployment...")
            OFDeployer = Function_Deploy()
            application_name = autoscale_prefix + "_application"
            region_key = all_parameters["region"]
            compartment_name = all_parameters["compartment_name"]
            compartment_id = compartmentId
            profile_name = all_parameters["profile_name"]
            object_storage_namespace = all_parameters["object_storage_namespace"]
            authorization_token = all_parameters["authorization_token"]

            appId = deployer.get_application_id(compartmentId, application_name)
        except Exception as e:
            print("ERROR : "+repr(e))
        try:
            deploy_oracle_functions_response = OFDeployer.deploy_oracle_functions(application_name, region_key, compartment_name, compartment_id, profile_name, object_storage_namespace, authorization_token)
            if deploy_oracle_functions_response == False:
                print("ERROR IN ORACLE-FUNCTION DEPLOYMENT, WHOLE DEPLOYMENT WILL BE ROLLED BACK INCLUDING STACK-1")
                function_delete_response = cleaner.delete_functions(appId)
                if function_delete_response == False:
                    print(f"ERROR OCCURED IN DELETING FUNCTIONS, PLEASE MANUALLY DELETE ALL FUNCTION INSIDE APPLICATION {application_name}, THEN USE TEARDOWN SCRIPT TO DESTROY {stack1_Name}")
                    exit(1)
                destroy_stack1_response = cleaner.destroy_stack(1, stack1_response.id)
                if destroy_stack1_response.lifecycle_state != "SUCCEEDED":
                    print(f"ERROR OCCURRED WHILE DESTROYING RESOURCES OF STACK {stack1_Name}, PLEASE SEE THE LOGS IN OCI AND MANUALLY DESTROY AND DELETE THE STACK")
                    exit(1)
                cleaner.delete_stack(1, stack1_response.id)
                exit(1)
            else:
                print("Oracle Function deployed successfully")
        except Exception as e:
            print(e)
            print("Exception occurred while deploying Oracle-Functions")
            exit(1)

    ###############################################################################################

        try:
            print("\n{} Creation started ...".format(stack2_Name))
            stack2_response = deployer.create_stack(compartmentId, stack2_Name, "template2.zip", "deployment_parameters.json")
            if stack2_response == None:
                print("ERROR IN CREATING STACK {0}".format(stack2_Name))
                exit(1)
            else:
                print("{0} Created Successfully with OCID: {1}".format(stack2_Name, stack2_response.id))

            print("\nResources Creation for {} started... it will take some time be patient".format(stack2_Name))
            resource2_create_response = deployer.create_resources(stack2_response.id)
            if resource2_create_response == None:
                print("EXCEPTION IN CREATING RESOURCES OF {}".format(stack2_Name))
                print("FOR FURTHER DETAILS SEE THE LOG OF RECENT APPLY JOB IN {}".format(stack2_Name))
                print("PLEASE MANUALLY DESTROY AND DELETE")
                exit(1)
                
            if resource2_create_response.lifecycle_state != "SUCCEEDED":
                log_response = deployer.create_logs(resource2_create_response.id, stack2_Name)
                if log_response == True:
                    print(f"\nAN ERROR HAS BEEN OCCURED WHILE CREATNG RESOURCES FOR {stack2_Name}")
                    print(f"PLEASE GO THROUGH FILE {stack2_Name}_Error.log IN CURRENT DIRECTORY,FOR DETAILED LOGS")
                    print(f"STACK {stack2_Name} WILL BE ROLLEDBACK")
                else:
                    print("ERROR IN CREATING RESOURCES OF {}".format(stack2_Name))
                    print("FOR FURTHER DETAILS SEE THE LOG OF RECENT APPLY JOB IN {}".format(stack2_Name.upper()))
                    print("ROLLING BACK WHOLE STACK DEPLOYMENT INCLUDING STACK-1, ORACLE-FUNCTION AND STACK-2, PLEASE MANUALLY VERIFY TOO")
            
                destory_stack2_response = cleaner.destroy_stack(2, stack2_response.id)
                if destory_stack2_response.lifecycle_state != "SUCCEEDED":
                    print("ERROR IN DESTROYING RESOURCES OF STACK-2, PLEASE SEE THE LOGS IN OCI AND MANUALLY DESTROY AND DELETE")
                    exit(1)
                cleaner.delete_stack(2, stack2_response.id)
                function_delete_response = cleaner.delete_functions(appId)
                if function_delete_response == False:
                    print(f"ERROR OCCURED IN DELETING FUNCTIONS, PLEASE MANUALLY DELETE ALL FUNCTION INSIDE APPLICATION {application_name}, THEN USE TEARDOWN SCRIPT TO DESTROY {stack1_Name}")
                    exit(1)
                destroy_stack1_response = cleaner.destroy_stack(1, stack1_response.id)
                if destroy_stack1_response.lifecycle_state != "SUCCEEDED":
                    print(f"ERROR OCCURRED WHILE DESTROYING RESOURCES OF STACK {stack1_Name}, PLEASE SEE THE LOGS IN OCI AND MANUALLY DESTROY AND DELETE THE STACK")
                    exit(1) 
                cleaner.delete_stack(1, stack1_response.id)
                exit(1)
            else:
                print("Resources Created Successfully for {}".format(stack2_Name))
                print("\nFor full details of resource creation, look for Job Name: {0} with OCID: {1} in the stack {2}".format(resource2_create_response.display_name, resource2_create_response.id, stack2_Name))
        except Exception as e:
            print(e)
            exit(1)
    
    ###############################################################################################

        if appId == None:
            appId = ''
        try:
            conclusion = {}
            conclusion["stack1Id"] = stack1_response.id
            conclusion["stack2Id"] = stack2_response.id
            conclusion["applicationId"] = appId

            delete_parameters = open("teardown_parameters.json",'w')
            delete_parameters.write(json.dumps(conclusion))
            delete_parameters.close()
            print("destroy_solution_parameters.json has been updated, can be used when destroying the solution")
        except Exception as e:
            print("\ndestroy_solution_parameters.json has not been updated, please update, before destroying the solution")

        print("\nCOMPLETE END TO END OCI FTDv AUTOSCALE SOLUTION HAS BEEN DEPLOYED\nVERIFY MANUALLY TOO BEFORE ACTUAL USAGE\nTHANK YOU !!!")
        exit(0)
    except Exception as e:
        print(e)
        print("UNEXPECTED ERROR OCCURRED, PLEASE RESOLVE AND RETRY")
        exit(1)