# Clustering for the Threat Defense Virtual in a Public Cloud
Clustering lets you group multiple Threat Defense Virtuals together as a single logical device. A cluster provides
all the convenience of a single device (management, integration into a network) while achieving the increased
throughput and redundancy of multiple devices. You can deploy Threat Defense Virtual clusters in a public
cloud using Amazon Web Services (AWS) or Google Cloud Platform (GCP). Only routed firewall mode is
supported. <br>
From release 7.6 onwards, Cluster deployment in multiple availability zones is supported.

# Prerequisites <br>

## Git Clone repository
Clone the repository 'cisco-ftdv' to your local environment. Navigate to - cisco-ftdv/cluster/aws for the required content

## Update FMCv Configuration
(1) Modify lambda-python-files/Configuration.json <br>
(2) Login to FMCv <br>
(3) Create Access Policy with same name as provided in Configuration.json <br>
(4) Register FMCv to Smart Licensing (highly recommended) <br>
(5) Create 2 API users in FMCv with Administrator permissions <br>
(6) Note FMCv IP, API usernames & passwords <br>
If you are deploying FMCv & FTDv in same subnet then above process should be done after Infra & FMCv deployment <br>

## Create "cluster_layer.zip"
The cluster_layer.zip can be created on an Amazon Linux VM, with Python 3.9 installed. We recommend
creating an EC2 instance using Amazon Linux 2023 AMI or use AWS Cloudshell, which runs the latest version of Amazon Linux. <br>

For creating the cluster-layer.zip file, you need to first create requirements.txt file that consists of the python library package details and then run the shell script. <br>

(1) Create the requirements.txt file by specifying the python package details. <br>

```bash
$ cat requirements.txt 
pycryptodome
paramiko
requests
scp
jsonschema
cffi
zipp
importlib-metadata
```

(2) Run the following commands to create cluster_layer.zip file. <br>
```bash
$ pip3 install --platform manylinux2014_x86_64 
--target=./python/lib/python3.9/site-packages 
--implementation cp --python-version 3.9 --only-binary=:all: 
--upgrade -r requirements.txt
$ zip -r cluster_layer.zip ./python
```

NOTE: If you encounter a dependency conflict during installation,  such as for packages urllib3 or cryptography, it is recommended that you include the conflicting packages along with their recommended versions in the requirements.txt file. After that, you can run the installation again to resolve the conflict. <br>

(3) Copy the resultant cluster_layer.zip file to the directory 'lambda-python-files' present in the cloned repository. <br>

## Create "cluster_manager.zip", "cluster_lifecycle.zip" and "custom_metrics_publisher.zip"
A make.py file can be found in the cloned repository top directory. Running this will Zip the python files into Zip
files and copy to a "target" folder. <br>
In order to do these tasks, the Python3 environment should be available. <br>

Run to create zip files <br>
```bash
python3 make.py build <br>
```

Run to clean <br>
```bash
python3 make.py clean <br>
```

All 4 Zip files need to be uploaded to AWS S3 bucket in a further step. <br>

# AWS NGFWv Cluster Deployment Steps <br>
## Deploy "infrastructure.yaml"
Go to "CloudFormation" on AWS Console. <br>
1. Click on "Create stack" and select "With new resources(standard)" <br>
2. Select "Upload a template file", Click on "Choose file" and select "infrastructure.yaml" from target folder. <br>
3. Click on "Next", Read all the Parameter's Label & instructions carefully. Add/Update Template parameters according to your requirement. <br>
4. Click "Next" and "Create stack" <br>
5. Once deployment is complete, go to "Outputs" and note S3 "BucketName". <br>
6. Go to S3, Open S3 bucket which is deployed using infra template. Upload previously-created "cluster_layer.zip, "cluster_manager.zip", "cluster_lifecycle.zip" and "custom_metrics_publisher.zip" to the S3 Bucket

## Deploy "deploy_ngfw_cluster.yaml"
Go to "CloudFormation" on AWS Console. <br>
1. Click on "Create stack" and select "With new resources(standard)" <br>
2. Select "Upload a template file", Click on "Choose file" and select "deploy_ngfw_cluster.yaml" from target folder. <br>
3. Click on "Next", Read all the Parameter's Label & instructions carefully. Add/Update/Select Template parameters according to your requirement. <br>
4. Click "Next" and "Create stack" <br>
5. Lambda functions will manage further process and NGFWv devices will be Auto-Registered to FMCv.



