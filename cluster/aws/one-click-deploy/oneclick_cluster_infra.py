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

CloudFormation Stack Deployment Tool

A comprehensive tool for managing AWS CloudFormation stacks for network infrastructure.
Supports creation and deletion of stacks with detailed monitoring and error handling.

Features:
    - Automated virtual environment setup
    - Template validation before deployment
    - Real-time stack creation/deletion monitoring
    - Detailed error reporting and stack events
    - Support for multiple Availability Zones
    - Configurable network parameters

Usage:
    python3 oneclick_cluster_infra.py [--mode {create|delete}]

Arguments:
    --mode      Deployment mode (default: create)
                create: Deploy a new CloudFormation stack
                delete: Remove an existing stack

Examples:
    1. Create a new stack (default behavior):
       $ python3 oneclick_cluster_infra.py

    2. Explicitly create a stack:
       $ python3 oneclick_cluster_infra.py --mode create

    3. Delete an existing stack:
       $ python3 oneclick_cluster_infra.py --mode delete

Configuration:
    The script uses a CONFIG dictionary that must be configured before use:

    1. AWS Credentials:
       CONFIG['aws_credentials'] = {
           'aws_access_key_id': 'YOUR_ACCESS_KEY',
           'aws_secret_access_key': 'YOUR_SECRET_KEY',
           'region_name': 'us-east-1'
       }

    2. Stack Configuration:
       CONFIG['stack_config'] = {
           'stack_name': 'your-stack-name',
           'template_path': 'path/to/template.yaml'
       }

    3. Network Parameters:
       - VPC CIDR
       - Management subnet configurations
       - Inside/Outside subnet configurations
       - CCL subnet configurations
       - Lambda subnet configurations

Requirements:
    - Python 3.6+
    - AWS credentials with CloudFormation permissions
    - Valid CloudFormation template
    - Internet connection for AWS API access
    - Sufficient AWS service quotas

Environment Setup:
    The script automatically:
    1. Creates a virtual environment
    2. Installs required packages (boto3)
    3. Configures AWS session

Error Handling:
    - Validates template before deployment
    - Shows detailed stack events on failure
    - Preserves failed stacks for debugging
    - Provides clear error messages

Notes:
    - Stack creation typically takes 5-10 minutes
    - Deletion may take 3-5 minutes
    - Keep AWS credentials secure and never commit them
    - Monitor AWS CloudWatch for detailed logs
"""

import argparse
import os
import sys
import venv
import subprocess
import time

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
        'stack_name': 'ngfw-infra-stack',
        'template_path': '../templates/infrastructure.yaml'
    },

    'deployment_mode': None,

    # Template Parameters
    'template_parameters': {
        # Cluster Configuration
        'ClusterName': {
            'value': 'NGFWCluster',
            'description': 'Name prefix for the NGFW cluster (3-18 chars)'
        },
        'ClusterNumber': {
            'value': '1',
            'description': 'Unique identifier for the cluster'
        },
        'DeploymentType': {
            'value': 'single-arm',  # or 'dual-arm'
            'description': 'Deployment mode. Note: dual-arm requires v7.8.0+'
        },
        # Availability Zone Configuration
        'NoOfAZs': {
            'value': '3',
            'description': 'Number of AZs. For v7.6.0+: use 2-3 AZs. Earlier versions: use 1'
        },
        'ListOfAZs': {
            'value': ['us-east-1a', 'us-east-1b', 'us-east-1c'],
            'description': 'List of AZs where resources will be deployed'
        },
        
        # Network Configuration
        'VpcCidr': {
            'value': '10.5.0.0/16',
            'description': 'CIDR block for the VPC)'
        },
        
        # Management Subnet Configuration
        'MgmtSubnetNames': {
            'value': 'MgmtSubnet-1,MgmtSubnet-2,MgmtSubnet-3',
            'description': 'Names for management subnets, one per AZ'
        },
        'MgmtSubnetCidrs': {
            'value': '10.5.250.0/27,10.5.251.0/27,10.5.252.0/27',
            'description': 'CIDR blocks for management subnets (/27 recommended)'
        },
        
        # Inside Network Configuration
        'InsideSubnetNames': {
            'value': 'InsideSubnet-1,InsideSubnet-2,InsideSubnet-3',
            'description': 'Names for inside (trusted) network subnets'
        },
        'InsideSubnetCidrs': {
            'value': '10.5.100.0/27,10.5.101.0/27,10.5.102.0/27',
            'description': 'CIDR blocks for inside network subnets'
        },
        
        # Outside Network Configuration
        'OutsideSubnetNames': {
            'value': 'OutsideSubnet-1,OutsideSubnet-2,OutsideSubnet-3',
            'description': 'Names for outside (untrusted) network subnets'
        },
        'OutsideSubnetCidrs': {
            'value': '10.5.200.0/27,10.5.201.0/27,10.5.202.0/27',
            'description': 'CIDR blocks for outside network subnets'
        },
        
        # Cluster Control Link Configuration
        'CCLSubnetNames': {
            'value': 'CCLSubnet-1,CCLSubnet-2,CCLSubnet-3',
            'description': 'Names for Cluster Control Link subnets'
        },
        'CCLSubnetCidrs': {
            'value': '10.5.90.0/27,10.5.91.0/27,10.5.92.0/27',
            'description': 'CIDR blocks for CCL subnets (cluster communication)'
        },
        
        # Lambda Function Configuration
        'LambdaAZs': {
            'value': ['us-east-1a', 'us-east-1b'],
            'description': 'AZs for Lambda functions (minimum 2 for HA)'
        },
        'LambdaSubnetNames': {
            'value': 'LambdaSubnet-1,LambdaSubnet-2',
            'description': 'Names for Lambda function subnets'
        },
        'LambdaSubnetCidrs': {
            'value': '10.5.50.0/24,10.5.51.0/24',
            'description': 'CIDR blocks for Lambda subnets'
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

def deploy_stack():
    """Deploy CloudFormation stack"""
    import boto3
    try:
        session = boto3.Session(**CONFIG['aws_credentials'])
        cf_client = session.client('cloudformation')
        
        # Read template file
        template_path = CONFIG['stack_config']['template_path']
        print(f"Reading template from {template_path}")
        with open(template_path, 'r') as f:
            template_body = f.read()
            
        # Format parameters
        parameters = format_template_parameters()
        
        stack_name = CONFIG['stack_config']['stack_name']
        print(f"\nDeploying stack {stack_name}...")
        
        # Validate template
        print("Validating template...")
        try:
            cf_client.validate_template(TemplateBody=template_body)
        except Exception as e:
            print(f"Template validation failed: {str(e)}")
            return
        
        # Create stack
        response = cf_client.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Parameters=parameters,
            Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'],
            OnFailure='DO_NOTHING'  # Changed from DELETE to DO_NOTHING
        )
        
        stack_id = response['StackId']
        print(f"Stack creation initiated. Stack ID: {stack_id}")
        
        # Monitor stack creation
        print("\nMonitoring stack creation...")
        while True:
            stack = cf_client.describe_stacks(StackName=stack_id)['Stacks'][0]
            status = stack['StackStatus']
            print(f"Current status: {status}")
            
            if status.endswith('COMPLETE') or status.endswith('FAILED'):
                if status == 'CREATE_COMPLETE':
                    print("\nStack deployment successful!")
                    # Display outputs
                    if 'Outputs' in stack:
                        print("\nStack Outputs:")
                        for output in stack['Outputs']:
                            print(f"{output['OutputKey']}: {output['OutputValue']}")
                else:
                    print("\nStack creation failed!")
                    # Get stack events for debugging
                    events = cf_client.describe_stack_events(StackName=stack_id)['StackEvents']
                    print("\nStack Events (most recent first):")
                    for event in events[:5]:  # Show last 5 events
                        print(f"- {event['LogicalResourceId']}: {event['ResourceStatus']} - {event.get('ResourceStatusReason', 'No reason provided')}")
                break
            
            time.sleep(30)  # Check every 30 seconds
            
    except Exception as e:
        print(f"\nError deploying stack: {str(e)}")
        sys.exit(1)

def empty_s3_bucket(bucket_name, s3_client):
    """Empty an S3 bucket before deletion"""
    try:
        # Delete objects
        paginator = s3_client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket_name):
            if 'Contents' in page:
                objects = [{'Key': obj['Key']} for obj in page['Contents']]
                s3_client.delete_objects(
                    Bucket=bucket_name,
                    Delete={'Objects': objects}
                )

        # Delete versioned objects if bucket has versioning
        paginator = s3_client.get_paginator('list_object_versions')
        try:
            for page in paginator.paginate(Bucket=bucket_name):
                delete_objects = []
                if 'Versions' in page:
                    delete_objects.extend([{'Key': v['Key'], 'VersionId': v['VersionId']}
                                        for v in page['Versions']])
                if 'DeleteMarkers' in page:
                    delete_objects.extend([{'Key': d['Key'], 'VersionId': d['VersionId']}
                                        for d in page['DeleteMarkers']])
                if delete_objects:
                    s3_client.delete_objects(
                        Bucket=bucket_name,
                        Delete={'Objects': delete_objects}
                    )
        except s3_client.exceptions.ClientError:
            pass  # Bucket might not have versioning enabled

        print(f"Successfully emptied bucket: {bucket_name}")
    except Exception as e:
        print(f"Error emptying bucket {bucket_name}: {str(e)}")


def delete_stack():
    """Delete CloudFormation stack"""
    import boto3
    try:
        session = boto3.Session(**CONFIG['aws_credentials'])
        cf_client = session.client('cloudformation')
        s3_client = session.client('s3')
        stack_name = CONFIG['stack_config']['stack_name']
        print(f"\nPreparing to delete stack {stack_name}...")
        # Get stack resources to find S3 buckets
        try:
            resources = cf_client.list_stack_resources(StackName=stack_name)['StackResourceSummaries']
            s3_buckets = [r['PhysicalResourceId']
                         for r in resources
                         if r['ResourceType'] == 'AWS::S3::Bucket']
            # Empty each S3 bucket before deletion
            for bucket in s3_buckets:
                print(f"Emptying S3 bucket: {bucket}")
                empty_s3_bucket(bucket, s3_client)
        except cf_client.exceptions.ClientError as e:
            if 'does not exist' not in str(e):
                raise
        print(f"\nDeleting stack {stack_name}...")
        # Delete stack
        cf_client.delete_stack(StackName=stack_name)
        # Monitor stack deletion
        print("\nMonitoring stack deletion...")
        while True:
            try:
                stack = cf_client.describe_stacks(StackName=stack_name)['Stacks'][0]
                status = stack['StackStatus']
                print(f"Current status: {status}")
                
                if status == 'DELETE_COMPLETE':
                    print("\nStack deletion successful!")
                    break
                elif status == 'DELETE_FAILED':
                    print("\nStack deletion failed!")
                    events = cf_client.describe_stack_events(StackName=stack_name)['StackEvents']
                    print("\nStack Events (most recent first):")
                    for event in events[:5]:
                        print(f"- {event['LogicalResourceId']}: {event['ResourceStatus']} - {event.get('ResourceStatusReason', 'No reason provided')}")
                    break
                    
                time.sleep(30)  # Check every 30 seconds
                
            except cf_client.exceptions.ClientError as e:
                if 'does not exist' in str(e):
                    print("\nStack deletion complete")
                    break
                raise
                
    except Exception as e:
        print(f"\nError deleting stack: {str(e)}")
        sys.exit(1)

def main():
    # Parse command line arguments
    args = parse_args()
    CONFIG['deployment_mode'] = args.mode
    # Setup virtual environment and install dependencies
    setup_virtual_env()
    
    # Execute based on deployment mode
    if CONFIG['deployment_mode'] == 'create':
        deploy_stack()
    elif CONFIG['deployment_mode'] == 'delete':
        delete_stack()

if __name__ == "__main__":
    main()
