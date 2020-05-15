"""
Name:       constant.py
Purpose:    This is contains all system constants & descriptions
            This gets called in all project files if necessary
"""

"""
Lifecycle hook constants
It should be updated if updated anything different in AutoScale-group constant file
"""
DIAG_ENI_NAME = "-diag-eni"
INSIDE_ENI_NAME = "-inside-eni"
OUTSIDE_ENI_NAME = "-outside-eni"

""" NIC Configuration method, DHCP/STATIC """
# NIC_CONFIGURE = "STATIC"  # Related to CSCvs17405
NIC_CONFIGURE = "DHCP"

""" Load Balancer Health probe configuration """
AWS_METADATA_SERVER = '169.254.169.254'

""" Encoding constant for password decryption function """
ENCODING = "utf-8"

""" Local Configuration File Name """
JSON_LOCAL_FILENAME = 'Configuration.json'
