"""
Copyright (c) 2020 Cisco Systems Inc or its affiliates.

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

Name:       make.py
Purpose:    To build zip files from python files for lambda functions.
            In "target" directory, zip files & template files will be copied.

"""

from __future__ import print_function
import platform
import os
import subprocess
import sys
import shutil
# import logging

oracle_functions_zip = 'Oracle-Functions.zip'
template1_zip = 'template1.zip'
template2_zip = 'template2.zip'
easy_deploy_zip = 'ftdv_autoscale_deploy.zip'
full_dir_path = os.path.dirname(os.path.realpath(__file__)) + '/'
target_path = full_dir_path + "target/"

cisco_oci_lib_file = full_dir_path + 'lib/cisco_oci.py'
fmc_lib_file = full_dir_path + 'lib/fmc.py'
manager_lib_file = full_dir_path + 'lib/manager.py'
ngfw_lib_file = full_dir_path + 'lib/ngfw.py'
utility_lib_file = full_dir_path + 'lib/utility.py'
# ftdv_scale_out_path = full_dir_path + 'oracle_functions/ftdv_scale_out/'

ftdv_configure_path = full_dir_path + 'oracle_functions/ftdv_configure/'
ftdv_post_launch_actions_path = full_dir_path + 'oracle_functions/ftdv_post_launch_actions/'
ftdv_publish_metrics_path = full_dir_path + 'oracle_functions/ftdv_publish_metrics/'
ftdv_remove_unhealthy_vm_path = full_dir_path + 'oracle_functions/ftdv_remove_unhealthy_vm/'
ftdv_scale_in_path = full_dir_path + 'oracle_functions/ftdv_scale_in/'
ftdv_token_manager_path = full_dir_path + 'oracle_functions/ftdv_token_manager/'
ftdv_teardown_operations_path = full_dir_path + 'oracle_functions/ftdv_teardown_operations/'

def print_function_name(function):
    def echo_func(*func_args, **func_kwargs):
        print('Running function: {}'.format(function.__name__))
        return function(*func_args, **func_kwargs)
    return echo_func


def main():
    try:
        print("Argument passed to make.py: {}".format(sys.argv[1]))
    except IndexError as e:
        print(e)
        print("Please use 'clean' or 'build' as argument to make.py")
        print("example: 'python make.py clean'")
    try:
        if sys.argv[1] == 'clean':
            # Cleans the target directory
            clean()

        elif sys.argv[1] == 'build':
            # Cleans the target directory
            clean()
            # Checks if all requirements for build
            setup()
            # Builds in target directory
            build()
            # Create target zip
            easy_deploy_zip_creation()
            remove_lib_files()
        else:
            print("No valid argument passed to make! "
                  "Please use clean/build argument.")
    except Exception as e:
        print(e)

    return


@print_function_name
def build():
    # copying library files to oracle functions
    copy_lib_files()
    # Zips python files for lambda function
    zip_()
    # Copies the files to target directory
    copy()
    return


@print_function_name
def setup():
    print("setup creates target and its sub-directories")
    folder_path = [target_path]
    for path in folder_path:
        try:
            isdir = os.path.isdir(path)
            if isdir:
                pass
            else:
                os.mkdir(path)
        except Exception as e:
            logger.error(e)
    return


@print_function_name
def clean():
    print("clean deletes target directory and contents if exists, further creates empty target directory")
    dir_path = target_path
    print("Cleaning the directory")
    try:
        shutil.rmtree(dir_path)
    except Exception as e:
        pass

    try:
        isdir = os.path.isdir(dir_path)
        if isdir:
            pass
        else:
            os.mkdir(dir_path)
    except Exception as e:
        logger.error(e)

    return


@print_function_name
def zip_():
    print("Create oracle functions zip file")
    oracle_function_path = full_dir_path + 'oracle_functions/'
    os.chdir(oracle_function_path)
    cmd = 'zip -r ' + target_path + oracle_functions_zip + ' ' + '*'
    print(cmd)
    execute_cmd(cmd)

    template_1_path = full_dir_path + 'templates/tf_template_1/'
    os.chdir(template_1_path)
    cmd = 'zip -r ' + target_path + template1_zip + ' ' + '*'
    print(cmd)
    execute_cmd(cmd)

    template_2_path = full_dir_path + 'templates/tf_template_2/'
    os.chdir(template_2_path)
    cmd = 'zip -r ' + target_path + template2_zip + ' ' + '*'
    print(cmd)
    execute_cmd(cmd)

    return


@print_function_name
def easy_deploy_zip_creation():
    print("Creating easy deploy scripts zip file")
    os.chdir(target_path)
    files_to_be_zipped = "template1.zip template2.zip Oracle-Functions.zip oci_ftdv_autoscale_deployment.py oci_ftdv_autoscale_teardown.py deployment_parameters.json teardown_parameters.json"
    cmd = 'zip -r ' + target_path + easy_deploy_zip + ' ' + files_to_be_zipped
    print(cmd)
    execute_cmd(cmd)

    os.remove("oci_ftdv_autoscale_deployment.py")
    os.remove("oci_ftdv_autoscale_teardown.py")
    os.remove("deployment_parameters.json")
    os.remove("teardown_parameters.json")
    os.chdir(full_dir_path)
    return

def copy_lib_files():

    print("Copying library files to the oracle functions")
    ftdv_configure_copy_cmd = "cp " + cisco_oci_lib_file + " " + fmc_lib_file + " " + manager_lib_file + " " + \
                              ngfw_lib_file + " " + utility_lib_file + " " + ftdv_configure_path
    execute_cmd(ftdv_configure_copy_cmd)

    ftdv_post_launch_actions_copy_cmd = "cp " +  utility_lib_file + " " + ftdv_post_launch_actions_path
    execute_cmd(ftdv_post_launch_actions_copy_cmd)

    ftdv_publish_metrics_copy_cmd = "cp " +  utility_lib_file + " " + fmc_lib_file+ " " + ftdv_publish_metrics_path
    execute_cmd(ftdv_publish_metrics_copy_cmd)

    ftdv_remove_unhealthy_copy_cmd = "cp " + cisco_oci_lib_file + " " + fmc_lib_file + " " + manager_lib_file + " " + \
                              ngfw_lib_file + " " + utility_lib_file + " " + ftdv_remove_unhealthy_vm_path
    execute_cmd(ftdv_remove_unhealthy_copy_cmd)

    ftdv_scale_in_copy_cmd = "cp " + cisco_oci_lib_file + " " + fmc_lib_file+ " " + manager_lib_file + " " + ngfw_lib_file + " " + \
                             utility_lib_file + " " + ftdv_scale_in_path
    execute_cmd(ftdv_scale_in_copy_cmd)

    ftdv_token_manager_copy_cmd = "cp " + fmc_lib_file + " " + utility_lib_file + " " + ftdv_token_manager_path
    execute_cmd(ftdv_token_manager_copy_cmd)

    ftdv_teardown_operations_copy_cmd = "cp " + fmc_lib_file + " " + utility_lib_file + " " + ftdv_teardown_operations_path
    execute_cmd(ftdv_teardown_operations_copy_cmd)
    
    return True

@print_function_name
def remove_lib_files():
    print("Removing library files from the oracle functions")
    ftdv_configure_rm_cmd = "rm " + ftdv_configure_path + "cisco_oci.py" + " " + ftdv_configure_path + "fmc.py" + " " + \
                                  ftdv_configure_path + "manager.py" + " " + ftdv_configure_path + "ngfw.py" + " " + \
                                  ftdv_configure_path + "utility.py"
    execute_cmd(ftdv_configure_rm_cmd)

    ftdv_remove_unhealthy_rm_cmd = "rm " + ftdv_remove_unhealthy_vm_path + "cisco_oci.py" + " " + ftdv_remove_unhealthy_vm_path \
                                  + "fmc.py" + " " + ftdv_remove_unhealthy_vm_path + "manager.py" + " " + \
                                  ftdv_remove_unhealthy_vm_path + "ngfw.py" + " " + ftdv_remove_unhealthy_vm_path + \
                                  "utility.py"
    execute_cmd(ftdv_remove_unhealthy_rm_cmd)

    ftdv_post_launch_actions_rm_cmd = "rm " + ftdv_post_launch_actions_path + "utility.py"
    execute_cmd(ftdv_post_launch_actions_rm_cmd)

    ftdv_publish_metrics_rm_cmd = "rm " +  ftdv_publish_metrics_path + "utility.py" + " " + \
                                  ftdv_publish_metrics_path +  "fmc.py"
    execute_cmd(ftdv_publish_metrics_rm_cmd)

    ftdv_scale_in_rm_cmd = "rm " + ftdv_scale_in_path + "cisco_oci.py" + " " + ftdv_scale_in_path + "fmc.py" + " " + \
                           ftdv_scale_in_path + "ngfw.py" + " " + ftdv_scale_in_path + "utility.py" + " " + \
                           ftdv_scale_in_path + "manager.py"
    execute_cmd(ftdv_scale_in_rm_cmd)

    ftdv_token_manager_rm_cmd = "rm " +  ftdv_token_manager_path + "utility.py" + " " + \
                                  ftdv_token_manager_path +  "fmc.py"
    execute_cmd(ftdv_token_manager_rm_cmd)

    ftdv_teardown_operations_rm_cmd = "rm " +  ftdv_teardown_operations_path + "utility.py" + " " + \
                                  ftdv_teardown_operations_path +  "fmc.py"
    execute_cmd(ftdv_teardown_operations_rm_cmd)
    return True

@print_function_name
def copy():
    print("copies contents to target directory")

    print ("Copying cloud shell oracle functions deploy script to target")
    cmd = "cp " + full_dir_path + "deploy_oracle_functions_cloudshell.py" + " " + target_path
    execute_cmd(cmd)

    print("Copying configuration file to target")
    cmd = "cp " + full_dir_path + "Configuration.json" + " " + target_path
    execute_cmd(cmd)

    print("Copying deployment scripts to target")
    cmd = "cp " + full_dir_path + "easy_deploy/oci_ftdv_autoscale_deployment.py" + " " + target_path
    execute_cmd(cmd)

    cmd = "cp " + full_dir_path + "easy_deploy/deployment_parameters.json" + " " + target_path
    execute_cmd(cmd)

    cmd = "cp " + full_dir_path + "easy_deploy/oci_ftdv_autoscale_teardown.py" + " " + target_path
    execute_cmd(cmd)

    cmd = "cp " + full_dir_path + "easy_deploy/teardown_parameters.json" + " " + target_path
    execute_cmd(cmd)

    return


def execute_cmd(cmd):
    # print(cmd)
    subprocess.call(cmd, shell=True)


if __name__ == '__main__':
    if platform.system() == 'Darwin' or platform.system() == 'Linux':
        main()
    else:
        print("Un-supported platform: %s" % platform.system())
        print("Supported platforms: Darwin, Linux")
