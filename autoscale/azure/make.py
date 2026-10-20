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

Name:       make.py
Purpose:    This python file is used for building the Azure autoscale function package and target folder.
"""

from __future__ import print_function

import logging
import os
import platform
import shutil
import subprocess
import sys
import tempfile


function_app_zip = "autoscale_function.zip"
full_dir_path = os.path.dirname(os.path.realpath(__file__)) + "/"
target_path = full_dir_path + "target/"
function_app_path = full_dir_path + "function-app/"
logic_app_file_path = full_dir_path + "logic-app/logic_app.txt"
arm_templates_path = full_dir_path + "arm-templates/"


def print_function_name(function):
    def echo_func(*func_args, **func_kwargs):
        print("Running function: {}".format(function.__name__))
        return function(*func_args, **func_kwargs)

    return echo_func


def main():
    try:
        command = sys.argv[1]
    except IndexError:
        print("Please use 'clean' or 'build' as argument to make.py")
        print("example: 'python make.py build'")
        return

    if command == "clean":
        clean()
    elif command == "build":
        clean()
        setup()
        build()
    else:
        print("No valid argument passed to make.py. Please use clean/build.")


@print_function_name
def build():
    with tempfile.TemporaryDirectory(prefix="autoscale_function_") as package_path:
        package(package_path)
        zip_(package_path)
    copy()


@print_function_name
def setup():
    print("setup creates target and its sub-directories")
    try:
        os.makedirs(target_path, exist_ok=True)
    except Exception as err:
        logging.error(err)


@print_function_name
def clean():
    print("clean deletes target directory and contents if it exists")
    try:
        shutil.rmtree(target_path)
    except Exception:
        pass

    try:
        os.makedirs(target_path, exist_ok=True)
    except Exception as err:
        logging.error(err)


@print_function_name
def zip_(package_path):
    print("Creating azure functions zip file")
    execute_cmd([
        "zip",
        "-r",
        target_path + function_app_zip,
        ".",
        "-x",
        "*/__pycache__/*",
        "*.pyc",
    ], cwd=package_path)


@print_function_name
def package(package_path):
    print("packages Azure Functions app with Linux Python dependencies")
    shutil.copytree(function_app_path, package_path, dirs_exist_ok=True)
    deployment_file = os.path.join(package_path, ".deployment")
    if os.path.exists(deployment_file):
        os.remove(deployment_file)

    dependency_path = os.path.join(package_path, ".python_packages/lib/site-packages")
    os.makedirs(dependency_path, exist_ok=True)

    execute_cmd([
        sys.executable,
        "-m",
        "pip",
        "install",
        "--upgrade",
        "--no-compile",
        "--target",
        dependency_path,
        "--platform",
        os.environ.get("AZURE_FUNCTIONS_PIP_PLATFORM", "manylinux2014_x86_64"),
        "--implementation",
        "cp",
        "--python-version",
        os.environ.get("AZURE_FUNCTIONS_PYTHON_VERSION", "3.11"),
        "--only-binary=:all:",
        "-r",
        os.path.join(package_path, "requirements.txt"),
    ])

    for root, dirs, _ in os.walk(package_path):
        if "__pycache__" in dirs:
            shutil.rmtree(os.path.join(root, "__pycache__"))


@print_function_name
def copy():
    print("copies templates and logic app file to target directory")
    shutil.copy(logic_app_file_path, target_path)
    shutil.copytree(arm_templates_path, target_path + "arm-templates", dirs_exist_ok=True)


@print_function_name
def execute_cmd(cmd, cwd=None):
    subprocess.check_call(cmd, cwd=cwd)


if __name__ == "__main__":
    if platform.system() in ("Darwin", "Linux"):
        main()
    else:
        print("Un-supported platform: %s" % platform.system())
        print("Supported platforms: Darwin, Linux")
