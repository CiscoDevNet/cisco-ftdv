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

Name:       utility.py
Purpose:    To create zip files for lambda functions & upload to S3 bucket.
"""

import platform
import re
import argparse
import subprocess

UPLOAD_TO_S3 = False

try:
    import boto3
    from boto3.s3.transfer import S3Transfer
    client = boto3.client('s3')
    s3 = boto3.resource('s3')
    transfer = S3Transfer(client)
    cft = boto3.client('cloudformation')
    UPLOAD_TO_S3 = True
except Exception as e:
    print("{}".format(e))
    print("Uploading to S3 will not work!")
    print("Please upload files manually!")
    pass

autoscale_manager_zip = 'autoscale_manager.zip'
autoscale_grp_zip = 'autoscale_grp.zip'
scale_functions_zip = 'scale_functions.zip'

asm_yaml = 'asm.yaml'
asg_yaml = 'asg.yaml'
deploy_yaml = 'deploy.yaml'

configuration_json = 'Configuration.json'

filepath1 = './autoscale_manager/'
filepath2 = './autoscale_grp/'
filepath3 = './scale_functions/'


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--create-zip-file', type=bool, default=False, help='If True, will create zip file')
    parser.add_argument('--upload-file', type=bool, default=False, help='If True, will upload files to S3')
    parser.add_argument('--s3-bucket', type=str, default=None, help='S3 Bucket Name')

    args = parser.parse_args()

    if args.create_zip_file:
        if platform.system() == 'Darwin' or platform.system() == 'Linux':
            print("\n")
            print("---------------------- Removing .zip File if exists locally ----------------------")

            cmd = "rm ./autoscale_manager.zip ./autoscale_grp.zip ./scale_functions.zip"
            print("Executing Command: " + cmd)
            subprocess.call(cmd, shell=True)
            print("\n")
            print("------------------------- Creating autoscale_manager.zip -------------------------")

            cmd1 = 'cd ' + 'autoscale_manager/' + ' ; pwd '
            list_of_files_autoscale_manager = ['aws.py', '__init__.py', 'manager.py', 'constant.py',
                                               'fmc.py', 'utility.py', 'ngfw.py', configuration_json ]
            cmd2 = 'zip -r ' + '../' + autoscale_manager_zip + ' '
            for file in list_of_files_autoscale_manager:
                cmd2 = cmd2 + file + ' '
            cmd = cmd1 + ' ; ' + cmd2
            print("Executing Command: \n" + cmd)
            subprocess.call(cmd, shell=True)
            print("\n")
            print("--------------------------- Creating autoscale_grp.zip ---------------------------")

            cmd1 = 'cd ' + 'autoscale_grp/' + ' ; pwd '
            list_of_files_autoscale_grp = ['autoscale_grp.py', 'constant.py', 'utility.py', '__init__.py',
                                           'aws_methods.py']
            cmd2 = 'zip -r ' + '../' + autoscale_grp_zip + ' '
            for file in list_of_files_autoscale_grp:
                cmd2 = cmd2 + file + ' '
            cmd = cmd1 + ' ; ' + cmd2
            print("Executing Command: \n" + cmd)
            subprocess.call(cmd, shell=True)
            print("\n")
            print("-------------------------- Creating scale_functions.zip --------------------------")

            cmd1 = 'cd ' + 'scale_functions/' + ' ; pwd '
            list_of_files_scale_functions_zip = ['scaleout.py', 'scalein.py', 'constant.py', 'aws_methods.py',
                                                 'scaleout_cron.py', 'scalein_cron.py']
            cmd2 = 'zip -r ' + '../' + scale_functions_zip + ' '
            for file in list_of_files_scale_functions_zip:
                cmd2 = cmd2 + file + ' '
            cmd = cmd1 + ' ; ' + cmd2
            print("Executing Command: \n" + cmd)
            subprocess.call(cmd, shell=True)

    if args.upload_file and UPLOAD_TO_S3 is True:
        if args.s3_bucket is None:
            print("ERROR: S3 bucket name has to be mentioned, $ python utility.py --upload-file true --s3-bucket <bucket-name> ")
            return

        print("\n")
        print("------------------------- Deleting files if exists in S3 -------------------------")

        s3.Object(args.s3_bucket, asm_yaml).delete()
        s3.Object(args.s3_bucket, asg_yaml).delete()
        s3.Object(args.s3_bucket, deploy_yaml).delete()

        s3.Object(args.s3_bucket, autoscale_manager_zip).delete()
        s3.Object(args.s3_bucket, autoscale_grp_zip).delete()
        s3.Object(args.s3_bucket, scale_functions_zip).delete()

        s3.Object(args.s3_bucket, configuration_json).delete()

        print("\n")
        print("----------------------------- Uploading .zip files -------------------------------")
        try:
            print("Uploading AutoScale Manager Lambda zip file...")
            file_path = './' + autoscale_manager_zip
            transfer.upload_file(file_path, args.s3_bucket, autoscale_manager_zip)
            print("Uploading AutoScale Group Lambda zip file...")
            file_path = './' + autoscale_grp_zip
            transfer.upload_file(file_path, args.s3_bucket, autoscale_grp_zip)
            file_path = './' + scale_functions_zip
            print("Uploading Scale Function Lambda zip file...")
            transfer.upload_file(file_path, args.s3_bucket, scale_functions_zip)
            print("Success!")
        except FileNotFoundError as err:
            print("{}".format(err))
            print("Looks like, script is unable to find zip files, recomendded to run utility.py with argument --create-zip ")
        except Exception as e:
            print("{}".format(e))

        print("\n")
        print("------------------------------ Uploading .yaml files -----------------------------")

        try:
            file_path = filepath1 + asm_yaml
            transfer.upload_file(file_path, args.s3_bucket, asm_yaml)
            # file_url = '%s/%s/%s' % (client.meta.endpoint_url, args.s3_bucket, asm_yaml)
            file_url = 'https://' + args.s3_bucket + '.' + 's3.amazonaws.com/' + asm_yaml
            print("AutoScale Manager Stack template: " + file_url)
            file_path = filepath2 + asg_yaml
            transfer.upload_file(file_path, args.s3_bucket, asg_yaml)
            # file_url = '%s/%s/%s' % (client.meta.endpoint_url, args.s3_bucket, asg_yaml)
            file_url = 'https://' + args.s3_bucket + '.' + 's3.amazonaws.com/' + asg_yaml
            print("AutoScale Group Stack template: " + file_url)
            file_path = './' + deploy_yaml
            transfer.upload_file(file_path, args.s3_bucket, deploy_yaml)
            # file_url = '%s/%s/%s' % (client.meta.endpoint_url, args.s3_bucket, deploy_yaml)
            file_url = 'https://' + args.s3_bucket + '.' + 's3.amazonaws.com/' + deploy_yaml
            print("Nested Stack template: " + file_url)
            print("Please use above template URLs during nested stack deployment")
            print("Success!")
        except FileNotFoundError as err:
            print("{}".format(err))
            print("Looks like, script is unable to find YAML files, recomendded to check cloned repository for YAML files")
        except Exception as e:
            print("{}".format(e))

    print("\n")
    print("--------------------------- Removing .zip Files locally -------------------------")

    delete_zip_files = input("Delete local zip files ?[y/n]: ")
    if re.match(r'^y(es)?$', delete_zip_files.lower()) is not None:
        cmd = "rm ./autoscale_manager.zip ./autoscale_grp.zip ./scale_functions.zip"
        print("Executing Command: " + cmd)
        subprocess.call(cmd, shell=True)
        print("\n")

if __name__ == '__main__':
    main()
