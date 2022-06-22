# lambda-python-files

## autoscale_layer.zip 

A file named *autoscale_layer.zip* needs to be created to provide some essential Python libraries to Lambda functions.
Below mentioned libraries needs to be available to lambda function. 

>   pycrypto==2.6.1 <br>
    paramiko==2.7.1 <br>
    requests==2.23.0 <br>
    scp==0.13.2 <br>
    jsonschema==3.2.0 <br>


It can be created in Linux environment such as Ubuntu 18.04 environment with Python 3.6 installed. <br>
Example:
```bash
#!/bin/bash
mkdir -p layer
virtualenv -p /usr/bin/python3.6 ./layer/
source ./layer/bin/activate
pip3 install pycrypto==2.6.1
pip3 install paramiko==2.7.1
pip3 install requests==2.23.0
pip3 install scp==0.13.2
pip3 install jsonschema==3.2.0
echo "Copy from ./layer directory to ./python\n"
mkdir -p ./python/.libs_cffi_backend/
cp -r ./layer/lib/python3.6/site-packages/* ./python/
cp -r ./layer/lib/python3.6/site-packages/.libs_cffi_backend/* ./python/.libs_cffi_backend/
zip -r autoscale_layer.zip ./python
```

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

### Configuration.json 
This file is used by manager.py/AutoScale manager lambda function, which has FMC related information. <br>