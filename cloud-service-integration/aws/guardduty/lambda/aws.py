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

Name:       aws.py
Purpose:    This python file has AWS related helper functions
            These classes will be called in Lambda function as needed
"""
import boto3
from base64 import b64decode

s3_client = boto3.client('s3')
sns_client = boto3.client('sns')
kms_client = boto3.client('kms')

ENCODING = "utf-8"

################################################################################
# S3 utils
################################################################################

def head_bucket(bucket):
    """
    Purpose: This function is to check if the bucket exists
    Parameters:
        bucket - Name of the S3 bucket
    Returns: None if success 
    Raises: Exception if failure
    """
    return s3_client.head_bucket(
        Bucket=bucket,
    )
    
def head_object(bucket, key):
    """
    Purpose: This function is if object exists in the bucket
    Parameters:
        bucket - Name of the S3 bucket
        key - Name of the object in the bucket(here, a blacklist file name)
    Returns: object metadata if found 
    Raises: Exception if failure
    """
    return s3_client.head_object(
        Bucket=bucket,
        Key=key,
    )
    
def get_object(bucket, key):
    """
    Purpose: This function is to retrieve object content from S3 bucket
    Parameters:
        bucket - Name of the S3 bucket
        key - Name of the object to fetch the data in the bucket(here, a blacklist file name)
    Returns: object data
    Raises: Exception if failure
    """
    return s3_client.get_object(
        Bucket=bucket,
        Key=key,
    )

def put_object(bucket, key, data):
    """
    Purpose: This function is add an object to the bucket
    Parameters:
        bucket - Name of the S3 bucket
        key - Name of the object to add the bucket(here, a blacklist file name)
        data - object data/contents
    Returns: put_object response 
    Raises: Exception if failure
    """
    return s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=bytes(data, ENCODING),
        ACL='private',
        ContentType='text/plain',
    )
    
def get_object_url(bucket_name, object_name, expiration=0):
    """
    Purpose: This function is to generate a object URL of S3 object
    Parameters:
        bucket_name - Name of the S3 bucket
        object_name - Name of the object
        expiration - time in seconds
    Returns: object url  
    Raises: Exception if failure
    """
    return s3_client.generate_presigned_url(
        'get_object', 
        Params={'Bucket': bucket_name, 'Key': object_name}, 
        ExpiresIn=expiration)

def get_s3_url(bucket_name, object_name):
    """
    Purpose: This function is to generate a S3 URL of the object
    Parameters:
        bucket_name - Name of the S3 bucket
        object_name - Name of the object
    Returns: s3 url  
    Raises: Exception if failure
    """
    return 's3://' + bucket_name + '/' + object_name

def get_object_acl(bucket_name, object_name):
    """
    Purpose: This function is to get the object's ACL
    Parameters:
        bucket_name - Name of the S3 bucket
        object_name - Name of the object
    Returns: get object acl response
    Raises: Exception if failure
    """
    return s3_client.get_object_acl(
        Bucket=bucket_name,
        Key=object_name,
    )

def put_object_acl(bucket_name, object_name, object_acl):
    """
    Purpose: This function is to update the object's ACL
    Parameters:
        bucket_name - Name of the S3 bucket
        object_name - Name of the object
        object_acl - ACL to update
    Returns: put object acl response
    Raises: Exception if failure
    """
    return s3_client.put_object_acl(
        Bucket=bucket_name,
        Key=object_name,
        AccessControlPolicy= object_acl,
    )

################################################################################
# KMS utils
################################################################################
def get_decrypted_key(ciphertext):
    """
    Purpose:    Decrypts encrypted data using KMS Key given to lambda function
    Parameters: Encrypted key
    Returns:    Decrypted key
    Raises:
    """
    response = kms_client.decrypt(CiphertextBlob=b64decode(ciphertext))['Plaintext']
    decrypted_key = str(response, ENCODING)
    return decrypted_key
    
################################################################################
# SNS utils
################################################################################

def publish_to_topic(topic_arn, subject, sns_message):
    """
    Purpose:    Publish message to SNS Topic
    Parameters: Topic ARN, Subject, Message Body
    Returns:    Response of Message publish
    Raises:     None
    """
    return sns_client.publish(
        TopicArn=topic_arn,
        Message=sns_message,
        Subject=subject)