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

Name:       deploy_oracle_functions_cloudshell.py
Purpose:    This python file is used to deploy the oracle functions
            via application cloudshell
"""

import os
import sys
import shutil
import subprocess

import argparse
from argparse import RawTextHelpFormatter
from zipfile import ZipFile
from platform import system

def deploy(app_name,directory):
    try:

        autoscale_prefix = app_name.split("_application")[0]
        repo_name = autoscale_prefix + "_" + directory
        container_repo_path = context_registry_path + repo_name
        print("Container Repo Path : {}".format(container_repo_path))
        cmd2 = "fn use context " + region_key
        cmd3 = "fn update context oracle.compartment-id " + compartment_id
        cmd4 = "fn update context registry " + container_repo_path
        cmd5 = "fn deploy --app " + app_name

        output = subprocess.Popen(cmd2, shell=True, stderr=subprocess.PIPE)
        out, err = output.communicate()
        if err != None:
            print(err.decode('utf-8'))

        output = subprocess.Popen(cmd3, shell=True, stderr=subprocess.PIPE)
        out, err = output.communicate()
        if err != None:
            print(err.decode('utf-8'))

        output = subprocess.Popen(cmd4, shell=True, stderr=subprocess.PIPE)
        out, err = output.communicate()
        if err != None:
            print(err.decode('utf-8'))

        output = subprocess.Popen(cmd5, shell=True, stderr=subprocess.PIPE)
        out, err = output.communicate()
        if err != None:
            print(err.decode('utf-8'))

        return True

    except Exception as e:
        print("EXCEPTION OCCURRED: "+ repr(e))
        return False

if __name__ == "__main__":
    region_dict = {'ap-sydney-1':'SYD',
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

    parser = argparse.ArgumentParser(description='*** Script to deploy Oracle Function for OCI ASAv Autoscale Solution ***\n\nInstruction to find values of required arguments:\nApplication Name: Name of Application created by first Terraform Template\nRegion Identifier: OCI -> Administration -> Region Management\nProfile Name: OCI -> Profile\nCompartment OCID: OCI -> Identity -> Compartment -> Compartment Details\nObject Storage Namespace: OCI -> Administration -> Tenancy Details\nAuthorization Token: OCI -> Identity -> Users -> User Details -> Auth Tokens -> Generate Token', formatter_class=RawTextHelpFormatter)

    parser.add_argument('-a', dest="application_name", type=str, metavar='', required=True, help="Name of Application in OCI to which functions will be deployed")
    parser.add_argument('-r', dest="region_key", type=str, metavar='', required=True, help="Region Identifier")
    parser.add_argument('-p', dest="profile_name", type=str, metavar='', required=True, help="Profile Name of User")
    parser.add_argument('-c', dest="compartment_id", type=str, metavar='', required=True, help="Compartment OCID")
    parser.add_argument('-o', dest="object_storage_namespace", type=str, required=True, metavar='', help="Object Storage Namespace")
    parser.add_argument('-t', dest="authorization_token", type=str, required=True, metavar='', help="Authorization Token for Docker Login (*Please Put in Quotes)")
    args = parser.parse_args()

    application_name = args.application_name
    region_key = args.region_key
    profile_name = args.profile_name
    compartment_id = args.compartment_id
    object_storage_namespace = args.object_storage_namespace
    authorization_token = args.authorization_token

    print("Application Name: ",application_name, end='\n')
    print("Region: ",region_key, end='\n')
    print("Profile Name: ",profile_name, end="\n")
    print("Compartment OCID: ",compartment_id, end="\n")
    print("Object Storage Namespace: ",object_storage_namespace, end="\n")

    if region_key in region_dict.keys():
        region_value = region_dict[region_key]
    else:
        print("REGION IS NOT CORRECT, PLEASE VERIFY AGAIN")
        sys.exit(1)


    region_link = region_value.lower()+ ".ocir.io"
    function_api_url = "https://functions."+region_key+".oraclecloud.com"
    context_registry_path = region_link +"/"+ object_storage_namespace +"/"

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
    os.system(cmd4)

    for directory in all_directories:
        os.chdir(directory)
        deploy_response = deploy(application_name, directory)
        if deploy_response == False:
            print("ONE OF THE COMMAND EXECUTION FAILED, CHECK STDERR")
            os.chdir(root_path)
            shutil.rmtree("oracle-functions")
            sys.exit(1)
        os.chdir(oracle_functions_path)

    os.chdir(root_path)
    shutil.rmtree("oracle-functions")
    sys.exit(0)
