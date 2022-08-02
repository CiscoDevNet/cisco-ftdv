# Clustering for the Threat Defense Virtual in a Public Cloud
Clustering lets you group multiple threat defense virtuals together as a single logical device. A cluster provides
all the convenience of a single device (management, integration into a network) while achieving the increased
throughput and redundancy of multiple devices. You can deploy threat defense virtual clusters in a public
cloud using Amazon Web Services (AWS) or Google Cloud Platform (GCP). Only routed firewall mode is
supported. <br>

# Prerequisites <br>
## Update FMCv Configuration
Modify cloud-clustering/ftdv-cluster/lambda-python-files/Configuration.json <br>
Login to FMCv, <br>
Create Access policy with same name provided in Configuration.json and create API user. <br>
Note FMCv IP, API username & password. <br>
If you are deploying FMCv & FTDv in same subnet then above process should be done after Infra & FMCv deployment. <br>

## Create "cluster_layer.zip"
The cluster_layer.zip can be created in a Linux environment, such as Ubuntu 18.04 with Python 3.9 installed. <br>

```bash
#!/bin/bash
mkdir -p layer
virtualenv -p /usr/bin/python3.9 ./layer/
source ./layer/bin/activate
pip3 install pycryptodome==3.12.0
pip3 install paramiko==2.7.1
pip3 install requests==2.23.0
pip3 install scp==0.13.2
pip3 install jsonschema==3.2.0
pip3 install cffi==1.14.0
pip3 install zipp==3.1.0
pip3 install importlib-metadata==1.6.0
echo "Copy from ./layer directory to ./python\n"
mkdir -p ./python/
cp -r ./layer/lib/python3.9/site-packages/* ./python/
zip -r cluster_layer.zip ./python
deactivate
```
The resultant cluster_layer.zip file should be copied to the lambda-python-files folder. <br>

## Create "cluster_manager.zip" & "cluster_lifecycle.zip"
A make.py file can be found in the cloned repository top directory. This will Zip the python files into a Zip
file and copy to a target folder. <br>
In order to do these tasks, the Python 3 environment should be available. <br>

Run to create zip files <br>
python3 make.py build <br>

Run to clean <br>
python3 make.py clean <br>

All Zip needs to be uploaded on AWS S3 bucket. <br>

# AWS NGFWv Cluster Deployment Steps <br>
## Deploy "infrastructure.yaml"
Go to "CloudFormation" on AWS Console. <br>
1. Click on "Create stack" and select "With new resources(standard)" <br>
2. Select "Upload a template file", Click on "Choose file" and select "infrastructure.yaml" from target folder. <br>
3. Click on "Next", Read all the Parameter's Label & instructions carefully. Add/Update Template parameters according to your requirement. <br>
4. Click "Next" and "Create stack" <br>
5. Once deployment is complete, go to "Outputs" and note S3 "BucketName". <br>
6. Go to S3, Open S3 bucket which is deployed using infra template. Upload "cluster_layer.zip, "cluster_manager.zip" & "cluster_lifecycle.zip".

## Deploy "deploy_ngfw_cluster.yaml"
Go to "CloudFormation" on AWS Console. <br>
1. Click on "Create stack" and select "With new resources(standard)" <br>
2. Select "Upload a template file", Click on "Choose file" and select "deploy_ngfw_cluster.yaml" from target folder. <br>
3. Click on "Next", Read all the Parameter's Label & instructions carefully. Add/Update/Select Template parameters according to your requirement. <br>
4. Click "Next" and "Create stack" <br>
5. Lambda functions will manage further process and NGFWv devices will be Auto-Registered to FMCv.



