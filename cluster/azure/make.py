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

Name:       make.py
Purpose:    This python file is build the cluster zip file.
"""

from __future__ import print_function
import platform
import os
import subprocess
import sys
import shutil
import logging

clustering_autoscal_zip = "cluster_function.zip"
full_dir_path = os.path.dirname(os.path.realpath(__file__)) + '/'
target_path = full_dir_path + "target/"
function_app_path = full_dir_path + 'function-app/'
logic_app_file_path = full_dir_path + 'logic-app/logic_app.txt'

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
    folder_path = [target_path]
    for path in folder_path:
        try:
            isdir = os.path.isdir(path)
            if isdir:
                pass
            else:
                os.mkdir(path)
        except Exception as e:
            logging.error(e)
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
        logging.error(e)

    return


@print_function_name
def zip_():
    print("Creating azure functions zip file")
    # oracle_function_path = full_dir_path + 'oracle_functions/'
    os.chdir(function_app_path)
    #zip -r azure_functions_with_latest_lib.zip *
    cmd = 'zip -r ' + target_path + clustering_autoscal_zip + '  ' + '*'
    print(cmd)
    execute_cmd(cmd)

    return

@print_function_name
def copy():
    print("copies contents to target directory")

    # cmd = "cp " + function_app_path + clustering_autoscal_zip + " " + target_path
    # execute_cmd(cmd)

    cmd = "cp " + logic_app_file_path + " " + target_path
    execute_cmd(cmd)
    return


@print_function_name
def execute_cmd(cmd):
    subprocess.call(cmd, shell=True)


if __name__ == '__main__':
    if platform.system() == 'Darwin' or platform.system() == 'Linux':
        main()
    else:
        print("Un-supported platform: %s" % platform.system())
        print("Supported platforms: Darwin, Linux")
