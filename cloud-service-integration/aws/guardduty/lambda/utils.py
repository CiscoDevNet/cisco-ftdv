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

Name:       utility.py
Purpose:    All static methods without class are written here
            It will be called in all Lambda functions
"""

import os
import sys
import re
import logging
import configparser
import hashlib

def setup_logging(debug_logs='disable'):
    """
    Purpose:    Sets up logging
    Parameters: User input to disable debug logs
    Returns:    logger object
    Raises:
    """
    logging.getLogger('paramiko').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.INFO)
    logger = logging.getLogger()
    for h in logger.handlers:
        logger.removeHandler(h)
    h = logging.StreamHandler(sys.stdout)
    FORMAT = '%(levelname)s [%(asctime)s] (%(funcName)s)# %(message)s'
    h.setFormatter(logging.Formatter(FORMAT))
    logger.addHandler(h)
    logger.setLevel(logging.DEBUG)
    if debug_logs == 'disable':
        logging.disable(logging.DEBUG)
    return logger


def put_line_in_log(var, line_type='dot'):
    """
    Purpose:    This is to help putting lines in logs
    Parameters: Variable to print between lines
    Returns:
    Raises:
    """
    if line_type == 'thick':
        logging.info('======================== < ' + var
                     + ' > ========================')
    if line_type == 'thin':
        logging.info('------------------------ < ' + var
                     + ' > ------------------------')
    if line_type == 'dot':
        logging.info('........................ < ' + var
                     + ' > ........................')
    return


def fetch_object(obj, path):
    """
    Purpose:    This is to help fetch values from a json object
    Parameters: The json object and path to find value
    Returns:    The value from json path or None
    """
    keys = path.split('/')
    scoped_obj = obj

    for key in keys:
        if key in scoped_obj:
            scoped_obj = scoped_obj[key]
        else:
            return None
    return scoped_obj


def parse_config(config_content):
    """
    Purpose:    This is to help parse key and values from a content of INI file
    Parameters: The INI file content
    Returns:    The dict object with parsed entries
    """
    parser = configparser.ConfigParser()
    parser.read_string(config_content)
    entries = []
    for section in parser.sections():
        section_dict = {'name': section}
        for key, value in parser.items(section):
            section_dict[key] = value
        entries.append(section_dict)
    return entries

logger = setup_logging(os.environ['DEBUG_LOGS'])

def print_table(header_row, table):
    """
    Purpose:    This is to get the string form of the results table
    Parameters: The header row and table data
    Returns:    The string representation of the table
    """
    s = '\t'
    for col in header_row:
        s += col + (30 - len(col) % 30) * ' '
    s += '\n\t' + len(header_row)*40 * '-'
    for row in table:
        s += '\n\t'
        for elem in row:
            s += elem + (30 - len(elem) % 30) * ' '
        s = s.rstrip()
    return s

def get_user_input_gd_event_analyser_lambda():
    """
    Purpose:    To get User Inputs from OS.env for guardduty event analyser Lambda function
    Parameters:
    Returns:    To get dict variable of all os.env variable
    Raises:
    """
    user_input = {
        "deployment_name": "",
        "s3_bucket": "",
        "s3_base_path": "",
        "s3_report_key": "",
        "sns_topic_arn": "",
        "kms_arn": "",
        "manager_input_file": None,
        "min_severity": 4.0
    }

    try:
        user_input['deployment_name'] = os.environ['DEPLOYMENT_NAME']
        if user_input['deployment_name'] is None:
            raise Exception("Unable to find deployment name os.env")

        user_input['s3_bucket'] = os.environ['S3_BUCKET']
        if user_input['s3_bucket'] is None:
            raise Exception("Unable to find S3 bucket name in os.env")

        user_input['s3_base_path'] = os.environ['S3_BASE_PATH']
        if user_input['s3_base_path'] is None:
            raise Exception("Unable to find S3 base path in os.env")


        user_input['sns_topic_arn'] = os.environ['SNS_TOPIC']
        if re.match(r'^arn:aws:sns:.*:.*:.*$', user_input['sns_topic_arn']) is None:
            raise Exception("Unable to find valid SNS Topic ARN in os.env")

        if os.environ['MANAGER_DETAILS_FILE'] != "":
            user_input['manager_input_file'] = user_input['s3_base_path'] + os.environ['MANAGER_DETAILS_FILE']

        user_input['kms_arn'] = os.environ['KMS_ARN']
        if user_input['kms_arn'] == "":
            user_input['kms_arn'] = None
        elif re.match(r'^arn:aws:kms:.*:.*:.*$', user_input['kms_arn']) is None:
            raise Exception("Unable to find valid KMS ARN in os.env")

        user_input['min_severity'] = os.environ['MIN_SEVERITY']
        user_input['s3_report_key'] = user_input['s3_base_path'] + user_input['deployment_name'] + '-report.txt'
        user_input['s3_report_md5'] = user_input['s3_base_path'] + user_input['deployment_name'] + '-report-md5.txt'

    except KeyError as e:
        logger.error('Missing environment variable {}' .format(str(e)))
        return None
    except Exception as e:
        logger.error("Error occured: {}" .format(str(e)))
        return None
    return user_input

def get_md5_sum(text):
    """
    Purpose:    To get md5sum of the text
    Parameters: text - value to generate the md5 for
    Returns: md5sum
    Raises:
    """
    return hashlib.md5(text.encode('utf-8')).hexdigest()

class NotifyWithError(Exception):
    """
        This class handles custom exception with a notification message
    """
    def __init__(self, error, message):
        super().__init__(error)
        self.message = message

   
   
   