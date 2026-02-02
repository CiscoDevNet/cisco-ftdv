"""
Copyright (c) 2025 Cisco Systems Inc or its affiliates.

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

CloudFormation Stack Deployment Tool for NGFW Infrastructure

This script automates the deployment and deletion of AWS CloudFormation stacks
for Network Gateway Firewall (NGFW) infrastructure. It supports creating a
infrastructure with management, inside, outside, and CCL subnets.

MAKE SURE TO COPY 'cluster_layer.zip' TO 'lambda-python-files' DIRECTORY BEFORE DEPLOYMENT!
ADD NAT EIP TO FMCV SECURITY GROUP FOR LAMBDA ACCESS!
ADD FMCV IP TO NGFWV SECURITY GROUP FOR FMCV ACCESS!

Features:
    - Creates/deletes CloudFormation stacks
    - Handles virtual environment setup
    - Validates templates before deployment
    - Monitors stack creation/deletion progress
    - Displays stack outputs upon successful creation

Usage:
    python3 oneclick_cluster_deploy.py [--mode {create|delete}]

Arguments:
    --mode      Deployment mode (default: create)
                create: Deploy a new stack
                delete: Remove an existing stack

Examples:
    # Create a new stack (default behavior)
    python3 oneclick_cluster_deploy.py

    # Explicitly create a stack
    python3 oneclick_cluster_deploy.py --mode create

    # Delete an existing stack
    python3 oneclick_cluster_deploy.py --mode delete

Configuration:
    Update the CONFIG dictionary in this file to modify:
    - AWS credentials and region
    - Stack name and template path
    - NGFW cluster parameters
    - Network configuration (VPC, subnets)

Requirements:
    - Python 3.6+
    - AWS credentials with appropriate permissions
    - boto3 (installed automatically in virtual environment)
    - Valid CloudFormation template at specified template_path
"""

import argparse
import os
import sys
import venv
import subprocess

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Deploy or delete CloudFormation stack')
    parser.add_argument('--mode', 
                      choices=['create', 'delete'],
                      default='create',
                      help='Deployment mode: create or delete (default: create)')
    return parser.parse_args()

# Configuration Parameters
CONFIG = {
    # AWS Credentials
    'aws_credentials': {
        'aws_access_key_id': 'YOUR_ACCESS_KEY',
        'aws_secret_access_key': 'YOUR_SECRET_KEY',
        'region_name': 'us-east-1'
    },

    # Stack Configuration
    'stack_config': {
        'stack_name': 'ngfw-deployment-stack',
        'template_path': '../templates/deploy_ngfw_cluster.yaml'
    },

    'template_parameters': {
        # Basic Cluster Configuration
        'ClusterGrpNamePrefix': {
            'value': 'Multi-AzCluster',
            'description': 'Prefix for Cluster Group Name (3-18 chars, alphanumeric and hyphens)'
        },
        'ClusterNumber': {
            'value': '1',
            'description': 'Suffix for Cluster Group Name (1-3 digits)'
        },
        'DeploymentType': {
            'value': 'single-arm',
            'description': 'Deployment type (single-arm/dual-arm). Dual-arm needs v7.8.0+'
        },
        'DiagnosticInteface': {
            'value': 'ON',
            'description': 'Diagnostic interface attachment (ON/OFF). OFF needs v7.8.0+'
        },
        'ClusterSize': {
            'value': '3',
            'description': 'Number of FTDv Nodes (1-16)'
        },
        'NotifyEmailID': {
            'value': 'your.email@domain.com',
            'description': 'Email for cluster notifications'
        },
        'S3BktName': {
            'value': 'multi-azinfra-s3bucketcluster-rsx6170089ez',
            'description': 'S3 Bucket containing Lambda files'
        },

        # Network Configuration
        'VpcId': {
            'value': 'vpc-xxxxx',
            'description': 'VPC for Cluster deployment'
        },
        'VpcIdLBE': {
            'value': 'SKIP',
            'description': 'VPC for Gateway Load Balancer Endpoint'
        },
        'NoOfAZs': {
            'value': '3',
            'description': 'Number of AZs (1-3)'
        },
        'AZ': {
            'value': ['us-east-1a', 'us-east-1b', 'us-east-1c'],
            'description': 'List of Availability Zones'
        },
        'MgmtSubnetIds': {
            'value': ['subnet-xxxx1', 'subnet-xxxx2', 'subnet-xxxx3'],
            'description': 'Management subnet IDs'
        },
        'InsideSubnetIds': {
            'value': ['subnet-xxxx4', 'subnet-xxxx5', 'subnet-xxxx6'],
            'description': 'Inside subnet IDs'
        },
        'OutsideSubnetIds': {
            'value': 'subnet-12345678,subnet-12345679,subnet-12345670',
            'description': 'Outside subnet IDs (dual-arm only)'
        },
        'CCLSubnetIds': {
            'value': ['subnet-xxxx10', 'subnet-xxxx11', 'subnet-xxxx12'],
            'description': 'CCL subnet IDs'
        },
        'LambdaSubnets': {
            'value': ['subnet-xxxx13', 'subnet-xxxx14'],
            'description': 'Lambda function subnets (need NAT GW)'
        },
        'CCLSubnetRanges': {
            'value': '10.5.90.4 10.5.90.30,10.5.91.4 10.5.91.30,10.5.92.4 10.5.92.30',
            'description': 'CCL subnet IP ranges'
        },
        'DualArmAppCidrList': {
            'value': '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16',
            'description': 'Application CIDRs for dual-arm'
        },
        'MgmtInterfaceSG': {
            'value': ['sg-xxxxx1'],
            'description': 'Security group for management interface'
        },
        'InsideInterfaceSG': {
            'value': ['sg-xxxxx2'],
            'description': 'Security group for inside interface'
        },
        'OutsideInterfaceSG': {
            'value': 'sg-12345678',
            'description': 'Security group for outside interface'
        },
        'CCLInterfaceSG': {
            'value': ['sg-xxxxx4'],
            'description': 'Security group for CCL interface'
        },
        'LambdaSG': {
            'value': ['sg-xxxxx5'],
            'description': 'Security group for Lambda functions'
        },

        # GWLB Configuration
        'DeployGWLBE': {
            'value': 'No',
            'description': 'Deploy Gateway Load Balancer Endpoint'
        },
        'TargetFailover': {
            'value': 'no_rebalance',
            'description': 'Target failover mode'
        },
        'TgHealthPort': {
            'value': '8080',
            'description': 'Health check port for GWLB'
        },
        'GWLBESubnetId': {
            'value': 'SKIP',
            'description': 'Subnet for GWLB Endpoint'
        },

        # Instance Configuration
        'InstanceType': {
            'value': 'c5.xlarge',
            'description': 'Instance type for NGFWv'
        },
        'LicenseType': {
            'value': 'BYOL',
            'description': 'License type (BYOL/PAYG)'
        },
        'AmiID': {
            'value': 'ami-09963e452646cef87',
            'description': 'AMI ID for NGFWv'
        },
        'AssignPublicIP': {
            'value': 'true',
            'description': 'Assign public IP to management interface'
        },
        'KmsArn': {
            'value': '',
            'description': 'KMS key ARN for encryption'
        },
        'InstanceMetadataServiceVersion': {
            'value': 'V1 and V2 (token optional)',
            'description': 'IMDS version (V2 requires v7.6+)'
        },

        # Security Configuration
        'ngfwPassword': {
            'value': 'YoUrPaSsWoRd@123',
            'description': 'Password for NGFWv instances'
        },

        # FMC Configuration
        'fmcServer': {
            'value': '72.163.4.161',
            'description': 'FMC IP address'
        },
        'fmcOperationsUsername': {
            'value': 'apiuser',
            'description': 'FMC username for operations'
        },
        'fmcOperationsPassword': {
            'value': 'YoUrPaSsWoRd@123',
            'description': 'FMC password for operations'
        },
        'fmcDeviceGrpName': {
            'value': 'ftdv-cluster',
            'description': 'FMC device group name'
        },
        'fmcPublishMetrics': {
            'value': 'true',
            'description': 'Enable FMC metrics publishing'
        },
        'fmcMetricsUsername': {
            'value': 'metricsuser',
            'description': 'FMC metrics username'
        },
        'fmcMetricsPassword': {
            'value': 'YoUrPaSsWoRd@123',
            'description': 'FMC metrics password'
        },

        # Scaling Configuration
        'CpuThresholds': {
            'value': '10,70',
            'description': 'CPU scaling thresholds (lower,upper)'
        },
        'MemoryThresholds': {
            'value': '40,70',
            'description': 'Memory scaling thresholds (lower,upper)'
        }
    }
}

def setup_virtual_env():
    """Create and activate virtual environment, install requirements"""
    if not os.path.exists('venv'):
        print("Setting up virtual environment...")
        venv.create('venv', with_pip=True)
        
        # Determine pip path based on OS
        pip_path = os.path.join('venv', 'bin', 'pip')
        
        # Install required packages
        subprocess.check_call([pip_path, 'install', 'boto3'])
        print("Virtual environment setup complete")

def format_template_parameters():
    """Format parameters for CloudFormation template."""
    params = []
    for key, param_dict in CONFIG['template_parameters'].items():
        value = param_dict['value']
        
        # Format value based on type
        if isinstance(value, list):
            formatted_value = ','.join(map(str, value))
        else:
            formatted_value = str(value)
        
        # Create parameter entry
        param = {
            'ParameterKey': key,
            'ParameterValue': formatted_value
        }
        params.append(param)
    return params

def build_lambda_zips():
    """Build Lambda function zip files using make.py"""
    print("\nBuilding Lambda function zip files...")
    try:
        make_script = os.path.join('..', 'make.py')
        subprocess.check_call([sys.executable, make_script, 'build'])
        print("Successfully built Lambda function zip files")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error building Lambda functions: {str(e)}")
        return False
    
def upload_lambda_zips_to_s3(session):
    """Upload Lambda zip files from target directory to S3"""
    print("\nUploading Lambda zip files to S3...")
    try:
        s3_client = session.client('s3')
        bucket_name = CONFIG['template_parameters']['S3BktName']['value']
        target_dir = os.path.join('..', 'target')
        # Check if target directory exists
        if not os.path.exists(target_dir):
            print(f"Error: Target directory not found at {target_dir}")
            return False
        # Upload each zip file from target directory
        for filename in os.listdir(target_dir):
            if filename.endswith('.zip'):
                file_path = os.path.join(target_dir, filename)
                s3_key = f'{filename}'
                print(f"Uploading {filename} to s3://{bucket_name}/{s3_key}")
                with open(file_path, 'rb') as f:
                    s3_client.upload_fileobj(f, bucket_name, s3_key)
        print("Successfully uploaded all Lambda zip files to S3")
        return True
    except Exception as e:
        print(f"Error uploading Lambda zip files to S3: {str(e)}")
        return False
    
def deploy_stack():
    """Deploy CloudFormation stack with support for large templates and all required capabilities"""
    import boto3
    try:
        # Initialize AWS session
        session = boto3.Session(**CONFIG['aws_credentials'])
        # Build Lambda zips
        if not build_lambda_zips():
            print("Failed to build Lambda functions. Aborting deployment.")
            sys.exit(1)
        # Upload Lambda zips to S3
        if not upload_lambda_zips_to_s3(session):
            print("Failed to upload Lambda functions to S3. Aborting deployment.")
            sys.exit(1)
        cf_client = session.client('cloudformation')
        # Read template file
        template_path = CONFIG['stack_config']['template_path']
        print(f"Reading template from {template_path}")
        # Define stack capabilities
        stack_capabilities = [
            'CAPABILITY_IAM',
            'CAPABILITY_NAMED_IAM',
            'CAPABILITY_AUTO_EXPAND'
        ]
        
        # Check template size
        template_size = os.path.getsize(template_path)
        if template_size > 51200:
            # If template is too large, use S3
            print("Template is too large for direct deployment. Uploading to S3...")
            s3_client = session.client('s3')
            bucket_name = CONFIG['template_parameters']['S3BktName']['value']
            template_key = 'templates/deploy_ngfw_cluster.yaml'
            
            try:
                # Upload template to S3
                with open(template_path, 'rb') as f:
                    s3_client.upload_fileobj(f, bucket_name, template_key)
                print(f"Template uploaded to s3://{bucket_name}/{template_key}")
                
                # Create stack using S3 URL
                template_url = f"https://{bucket_name}.s3.{CONFIG['aws_credentials']['region_name']}.amazonaws.com/{template_key}"
                print("Creating stack using S3 template URL...")
                response = cf_client.create_stack(
                    StackName=CONFIG['stack_config']['stack_name'],
                    TemplateURL=template_url,
                    Parameters=format_template_parameters(),
                    Capabilities=stack_capabilities,
                    OnFailure='DO_NOTHING'  # Keep failed stack for debugging
                )
            except Exception as s3_error:
                print(f"Error uploading template to S3: {str(s3_error)}")
                raise
        else:
            # For smaller templates, use direct deployment
            print("Using direct template deployment...")
            with open(template_path, 'r') as f:
                template_body = f.read()
            
            # Validate template before deployment
            print("Validating template...")
            try:
                cf_client.validate_template(TemplateBody=template_body)
            except Exception as val_error:
                print(f"Template validation failed: {str(val_error)}")
                raise
            
            # Create stack directly
            print("Creating stack...")
            response = cf_client.create_stack(
                StackName=CONFIG['stack_config']['stack_name'],
                TemplateBody=template_body,
                Parameters=format_template_parameters(),
                Capabilities=stack_capabilities,
                OnFailure='DO_NOTHING'  # Keep failed stack for debugging
            )
        
        stack_id = response['StackId']
        print(f"Stack creation initiated. Stack ID: {stack_id}")
        
        # Wait for stack creation to complete
        print("\nWaiting for stack creation to complete (this may take 10-15 minutes)...")
        waiter = cf_client.get_waiter('stack_create_complete')
        try:
            waiter.wait(
                StackName=stack_id,
                WaiterConfig={
                    'Delay': 30,
                    'MaxAttempts': 60
                }
            )
        except Exception as waiter_error:
            # Get stack events on failure
            events = cf_client.describe_stack_events(StackName=stack_id)['StackEvents']
            print("\nStack creation failed! Recent events:")
            for event in events[:5]:  # Show last 5 events
                print(f"- {event['LogicalResourceId']}: {event['ResourceStatus']} - {event.get('ResourceStatusReason', 'No reason provided')}")
            raise     
        print("\nStack deployment successful!")           
    except Exception as e:
        print(f"\nError deploying stack: {str(e)}")
        sys.exit(1)

def delete_stack():
    """Delete CloudFormation stack"""
    import boto3
    try:
        session = boto3.Session(**CONFIG['aws_credentials'])
        cf_client = session.client('cloudformation')
        
        stack_name = CONFIG['stack_config']['stack_name']
        print(f"\nDeleting stack {stack_name}...")
        
        # Delete stack
        cf_client.delete_stack(StackName=stack_name)
        
        # Wait for stack deletion to complete
        print("\nWaiting for stack deletion to complete...")
        waiter = cf_client.get_waiter('stack_delete_complete')
        waiter.wait(
            StackName=stack_name,
            WaiterConfig={
                'Delay': 30,
                'MaxAttempts': 60
            }
        )
        
        print("\nStack deletion successful!")
            
    except Exception as e:
        print(f"\nError deleting stack: {str(e)}")
        sys.exit(1)

def main():
    # Parse command line arguments
    args = parse_args()
    # Setup virtual environment and install dependencies
    setup_virtual_env()
    # Execute based on deployment mode
    if args.mode == 'create':
        deploy_stack()
    elif args.mode == 'delete':
        delete_stack()

if __name__ == "__main__":
    main()
