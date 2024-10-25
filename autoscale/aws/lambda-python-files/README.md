# lambda-python-files

## Steps to create autoscale_layer.zip for Python3.11

A file named *autoscale_layer.zip* needs to be created to provide some essential Python libraries to Lambda functions.This file can be created in a Linux environment, such as Ubuntu 18.04 / 20.04 with Python 3.11 installed.<br>

Run the following commands to create the autoscale_layer.zip <br>


#!/bin/bash <br />
mkdir -p layer <br />
virtualenv -p /usr/local/bin/python3.11 ./layer/ <br />
source ./layer/bin/activate <br />
pip3 install paramiko==2.11.0 <br />
pip3 install requests==2.23.0 <br />
pip3 install scp==0.13.2 <br />
pip3 install jsonschema==3.2.0 <br />
pip3 install cffi==1.15.0 <br />
pip3 install cryptography==2.9.1 <br />
pip3 install zipp==3.1.0 <br />
pip3 install importlib-metadata==1.6.0 <br />
echo "Copy from ./layer directory to ./python\n" <br />
mkdir -p ./python/ <br />
cp -r ./layer/lib/python3.11/site-packages/* ./python/ <br />
zip -r autoscale_layer.zip ./python <br />
deactivate <br />


The resultant autoscale_layer.zip file must be placed in 'lambda-python-files'

## Create "autoscale_manager.zip", "lifecycle_ftdv.zip" and "custom_metric_fmc.zip"
A make.py file can be found in the cloned repository top directory. Running this will Zip the python files into 4 Zip files and copy to a "target" folder. <br>
These 4 Zip files should then be uploaded to S3 Bucket created by infrastructure template.
In order to do these tasks, the Python 3 environment should be available. <br>

Run to create zip files <br>
```
python3 make.py build 
```

Run to clean <br>
```
python3 make.py clean 
```

### Configuration.json 
This file is used by manager.py/AutoScale manager lambda function, which has FMC related information. <br>
Ensure names of interfaces, Security Zone objects, Device Group and Policies created in FMC are exactly matching with names specified in this file.<br>
If all pre-required objects are not present in FMC before deploying AutoScale Stack, the Lambdas my fail.<br>

You can make the changes below to Configuration.json depending on Deployment type, to specify your own networks instead of the default ones used currently.

For Deployment type Single-arm : "SingleArmTrafficRoutes" is applied to devices <br />
    For the "inside" interface's route:<br />
    (1)Create a network object in FMC specifying the AWS GWLB's VPC CIDR range <br />
    (2)Give this object name in "network" field, instead of "any-ipv4" which is a pre-defined FMC object specifying all IPv4 addresses <br />
    
For Deployment type Dual-arm : "DualArmTrafficRoutes" is applied to devices <br>
    For the "vni-in" route: <br />
    (1) Create a network object group in FMC specifying all Application Networks CIDR ranges in your topology.<br>
    (2) Give this object group name in "network" field. Currently, "network" specifies the pre-defined FMC object "IPv4-Private-All-RFC1918", which includes the RFC 1918 IPv4 Private address range.

### Configuration-schema.json  
Schema to validate Configuration.json  

Sample Configuration.json, Configuration-schema.json files are given in the directory "sample-az-configuration-jsons". <br>
For deploying GWLB single-arm topology: refer sample files with 'gwlb-single-arm' prefix<br>
For deploying GWLB dual-arm topology: refer sample files with 'gwlb-dual-arm' prefix<br>
For deploying NLB single-arm topology: refer sample files with 'nlb' prefix. <br>

Based on your topology, replace the required content in Configuration.json and Configuration-schema.json <br>
    

## Lambda Main files 

### lifecycle_ftdv.py 
This python file contains lamda_handler for lifecycle-lambda function. 

### manager.py
This python file contains lamda_handler for Autoscale manager lambda function.

### custom_metric_fmc.py
This python file contains lamda_handler for custom metrics publisher function.

## Library Files 

### aws.py 
This file contains classes for various AWS services. <br>

### fmc.py
This file contains class for FMC Communications(RESTapi/requests) <br>

### ngfw.py
This file contains classes for NGFW methods & SSH connectivity(Paramiko) <br>

## Other files
### constant.py 
This file contains all the constants used in python functions. 

### utility.py
This file contains static python methods used in other python files
