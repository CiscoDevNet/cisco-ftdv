## autoscale_layer.zip 

A file named **autoscale_layer.zip** needs to be created in this directory to provide some essential Python libraries to Lambda functions.
Below mentioned libraries needs to be available to lambda function. 

>   pycrypto==2.6.1 <br>
    paramiko==2.7.1 <br>
    requests==2.23.0 <br>
    scp==0.13.2 <br>
    jsonschema==3.2.0 <br>


It can be created in Linux environment such as Ubuntu 18.04 environment with Python 3.6 installed. <br>
Example Bash Shell Commands:<br>

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


Link:
https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html

Below link may get brocken as its a forum:<br>
https://medium.com/@adhorn/getting-started-with-aws-lambda-layers-for-python-6e10b1f9a5d


