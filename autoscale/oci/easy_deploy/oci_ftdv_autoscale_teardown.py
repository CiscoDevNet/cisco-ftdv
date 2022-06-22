#!/usr/bin/env python3
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

Name:       oci_ftdv_autoscale_teardown.py
Purpose:    This python file has terraform and Oracle Functions related methods
            which are being used for performing Cleanup of Stack
            in OCI FTDv Autoscale.
"""

import oci
import argparse
from argparse import RawTextHelpFormatter
import json
import time
import requests

class Cleanup:
    def __init__(self):
        self.signer = self.get_signer()
        self.resourceManagerClient = oci.resource_manager.ResourceManagerClient(config={}, signer=self.signer)
        self.resourceManagerClientCompositeOperation = oci.resource_manager.ResourceManagerClientCompositeOperations(client = self.resourceManagerClient)
        self.functionClient = oci.functions.FunctionsManagementClient(config={}, signer=self.signer)
        self.functionClientCompositeOperation = oci.functions.FunctionsManagementClientCompositeOperations(client = self.functionClient)
        self.retry = 3

    def get_signer(self):
        try:
            # get the cloud shell delegated authentication token
            delegation_token = open('/etc/oci/delegation_token', 'r').read()
            # create the api request signer
            signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(delegation_token = delegation_token)
            return signer
        except Exception as e:
            print("ERROR IN OBTAINING SIGNER",end="\n")

    def destroy_stack(self, stackNo, stackId):
        print("\nStarting Stack-{0} destroy, may take up to 25 Minutes or more in some cases, Please be patient".format(stackNo),end="\n")
        try:
            create_job_details = oci.resource_manager.models.CreateJobDetails(
                stack_id = stackId,
                job_operation_details = oci.resource_manager.models.CreateDestroyJobOperationDetails(
                    operation = "DESTROY",
                    execution_plan_strategy = "AUTO_APPROVED"))
            destroy_stack_response = self.resourceManagerClientCompositeOperation.create_job_and_wait_for_state(create_job_details, wait_for_states=["SUCCEEDED","FAILED","CANCELED"], waiter_kwargs={"max_wait_seconds":1800}).data
            return destroy_stack_response

        except Exception as e:
            print(e)
            return None

    def delete_stack(self, stackNo, stackId):
        print("\nDeleting Stack-{0}".format(stackNo),end="\n")
        for i in range(0,self.retry):
            try:
                delete_stack_response = self.resourceManagerClientCompositeOperation.delete_stack_and_wait_for_state(stack_id = stackId, wait_for_states=["DELETED"])
                print("Stack has been deleted successfully",end="\n")

                return True
            except Exception as e:
                print(e,end="\n")
                continue
        return False

    def delete_functions(self, appId):
        print("\nStarting to delete functions",end="\n")
        for i in range(0, self.retry):
            try:
                list_of_functions = self.functionClient.list_functions(application_id = appId).data

                if len(list_of_functions) == 0:
                    print("\nThere are no functions to delete, either they were not deployed or they got deleted in previous try already",end="\n")
                    print("Process will move to next step",end="\n")
                    return True

                for function in list_of_functions:
                    if function.display_name == "ftdv_teardown_operations":
                        try:
                            print("\nPerforming Teardown Operations, will take 2 minutes ...")
                            endpoint = str(function.invoke_endpoint)+"/20181201/functions/"+str(function.id)+"/actions/invoke"
                            requests.post(endpoint, auth=self.signer)
                        except Exception as e:
                            print("ERROR IN INVOKING TEARDOWN OPERATION FUNCTION, WILL SKIP IT "+repr(e))
                        time.sleep(120)
                    delete_function_response = self.functionClientCompositeOperation.delete_function_and_wait_for_state(function_id = function.id, wait_for_states=["DELETED"])
                    print("\nFunction {} has been deleted successfully".format(function.display_name),end="\n")
                return True

            except Exception as e:
                print("\nRetry Count:{} Error:{}".format(str(i), e),end="\n")
                continue
        return False

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="*** Script to destroy full end-to-end OCI-FTDv Autoscale Solution (Stack-1, Oracle-Function and Stack-2) ***\nPlease provide the required input in destroy_solution_parameters.txt", formatter_class=RawTextHelpFormatter)
    args = parser.parse_args()

    with open("teardown_parameters.json",'r') as f:
        data = f.read()
    f.close()

    parameters = json.loads(data)
    stack1_Id = parameters["stack1Id"]
    stack2_Id = parameters["stack2Id"]
    application_Id = parameters["applicationId"]

    print("\nStack-1 OCID : {0}".format(stack1_Id))
    print("Stack-2 OCID : {0}".format(stack2_Id))
    print("Application OCID : {0}".format(application_Id),end="\n")

    cleaner = Cleanup()

    try:
        # Destroying all resources of stack-2 and deleting it.
        stack2_destroy_response = cleaner.destroy_stack(2, stack2_Id)
        if stack2_destroy_response.lifecycle_state != "SUCCEEDED":
            print("\nERROR IN DESTROYING RESOURCES OF STACK-2, PLEASE SEE THE LOGS AND DESTORY IT MANUALLY")
            exit(1)
        else:
            print("Stack-2 resources destroyed successfully",end="\n")

        stack2_delete_response = cleaner.delete_stack(2, stack2_Id)
        if stack2_delete_response == False:
            print("\nERROR IN DELETING STACK-2")
            exit(1)
        else:
            print("Stack-2 deleted successfully",end="\n")

        # Deleting Functions
        function_delete_response = cleaner.delete_functions(application_Id)
        if function_delete_response == False:
            print("\nERROR IN DELETING ORACLE FUNCTIONS")
            exit(1)
        else:
            print("All the function deleted successfully",end="\n")

        # Destroying all resources of stack-1 and deleting it.
        stack1_destroy_response = cleaner.destroy_stack(1, stack1_Id)
        if stack1_destroy_response.lifecycle_state != "SUCCEEDED":
            print("\nERROR IN DESTROYING RESOURCES OF STACK-1. PLEASE SEE THE LOGS AND DESTORY IT MANUALLY")
            exit(1)
        else:
            print("Stack-1 resources destroyed successfully",end="\n")

        stack1_delete_response = cleaner.delete_stack(1, stack1_Id)
        if stack1_delete_response == False:
            print("\nERROR IN DELETING STACK-1")
            exit(1)
        else:
            print("Stack-1 deleted successfully",end="\n")

        print("\nSTAKE DELETION COMPLETED SUCCESSFULLY, PLEASE VERIFY MANUALLY TOO",end="\n")

    except Exception as e:
        print("\nUNEXPECTED ERROR OCCURRED, PLEASE MANUALLY DESTROY OR DELETE ANY RESOURCE IF LEFT", end="\n")
        print(e)
        exit(1)
