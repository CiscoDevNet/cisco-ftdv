"""
Copyright (c) 2022 Cisco Systems Inc or its affiliates.

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

cluster_manager_zip = 'cluster_manager.zip'
cluster_lifecycle_zip = 'cluster_lifecycle.zip'
lambda_layer_zip = 'cluster_layer.zip'
custom_metric_publisher_zip = 'custom_metrics_publisher.zip'
full_dir_path = os.path.dirname(os.path.realpath(__file__)) + '/'
target_path = full_dir_path + "target/"


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
        else:
            print("No valid argument passed to make! "
                  "Please use clean/build argument.")
    except Exception as e:
        print(e)

    return


@print_function_name
def build():
    # Zips python files for lambda function
    zip_()
    # Copies the files to target directory
    copy()
    return


@print_function_name
def setup():
    print("setup creates target and its sub-directories")
    # folder_path = ['./target', './target/templates', './target/lambda_functions', './target/config_files']
    folder_path = [target_path]
    for path in folder_path:
        try:
            isdir = os.path.isdir(path)
            if isdir:
                pass
            else:
                os.mkdir(path)
        except Exception as e:
            print(e)
    return


@print_function_name
def clean():
    print("clean deletes target directory and contents if exists, further creates empty target directory")
    dir_path = target_path
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
        print(e)
    return


@print_function_name
def zip_():
    print("zip_ creates lambda zip files with only required python files")

    list_of_files = ['aws.py', 'manager.py', 'constant.py', 'ngfw.py', 'fmc.py', 'utility.py', 'Configuration.json']
    cmd = 'zip -jr ' + target_path + cluster_manager_zip + ' '
    for file in list_of_files:
        file = full_dir_path + 'lambda-python-files/' + file
        cmd = cmd + file + ' '
    execute_cmd(cmd)

    list_of_files = ['aws.py', 'custom_metrics_publisher.py', 'constant.py', 'ngfw.py', 'fmc.py', 'utility.py']
    cmd = 'zip -jr ' + target_path + custom_metric_publisher_zip + ' '
    for file in list_of_files:
        file = full_dir_path + 'lambda-python-files/' + file
        cmd = cmd + file + ' '
    execute_cmd(cmd)

    list_of_files = ['aws.py', 'lifecycle_ftdv.py', 'constant.py', 'utility.py']
    cmd = 'zip -jr ' + target_path + cluster_lifecycle_zip + ' '
    for file in list_of_files:
        file = full_dir_path + 'lambda-python-files/' + file
        cmd = cmd + file + ' '
    execute_cmd(cmd)

    return


@print_function_name
def copy():
    print("copies contents to target directory")

    cmd = "cp " + full_dir_path + 'lambda-python-files/' + lambda_layer_zip + " " + target_path
    execute_cmd(cmd)

    list_template_files = [
        'deploy_ngfw_cluster.yaml',
        'infrastructure.yaml'
    ]
    for file in list_template_files:
        cmd = "cp " + full_dir_path + 'templates/' + file + " " + target_path
        execute_cmd(cmd)
    return


@print_function_name
def execute_cmd(cmd):
    # print(cmd)
    subprocess.call(cmd, shell=True)


if __name__ == '__main__':
    if platform.system() == 'Darwin' or platform.system() == 'Linux':
        main()
    else:
        print("Un-supported platform: %s" % platform.system())
        print("Supported platforms: Darwin, Linux")
