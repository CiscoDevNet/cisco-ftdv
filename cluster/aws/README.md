# Clustering for the Threat Defense Virtual in a Public Cloud

Clustering lets you group multiple threat defense virtuals together as a single logical device. A cluster provides
all the convenience of a single device (management, integration into a network) while achieving the increased
throughput and redundancy of multiple devices. You can deploy threat defense virtual clusters in a public
cloud using Amazon Web Services (AWS) or Google Cloud Platform (GCP). Only routed firewall mode is
supported. <br>

# Prerequisites <br>

## Option A: Use pre-built binaries

1. Download the `cluster_aws.zip` file from the repository release [page](https://github.com/CiscoDevNet/cisco-ftdv/releases).
2. Extract the three files `cluster_layer.zip`, `cluster_manager.zip`, and `cluster_lifecycle.zip` from the `cluster_aws.zip` file.
3. Extract the `Configuration.json` file from the `cluster_manager.zip` file.
4. Adjust the configuration in the `Configuration.json` file as needed.
   ```json
   {
     "licenseCaps": ["BASE", "MALWARE", "THREAT"],
     "performanceTier": "FTDv50",
     "fmcIpforDeviceReg": "DONTRESOLVE",
     "RegistrationId": "cisco",
     "NatId": "cisco",
     "fmcAccessPolicyName": "AWS-ACL"
   }
   ```
   The `fmcAccessPolicyName` should match the name of an access policy in the FMC. `performanceTier` is the license tier of the FTDv devices.
5. If changes were made to the `Configuration.json` file add it back into the `cluster_manager.zip` file.
6. These files will be uploaded to an S3 bucket created after the infrastructure stack is deployed.

## Option B: Custom build the deployment package

### Update FMCv Configuration

1. Adjust the `cluster/aws/lambda-python-files/Configuration.json` file with the values to match the enviroment.
2. Configure the FMC:

- Login to FMCv
- Create an access policy (ACP) with same name provided in `Configuration.json`
- Create an API user (with administrative access)<br>
  **If you are deploying FMCv & FTDv in same subnet then above process should be done after Infra & FMCv deployment.**

### Create "cluster_layer.zip"

The cluster_layer.zip can be created in a Linux environment, such as Ubuntu 18.04 with Python 3.9 installed. <br>

```bash
#!/bin/bash
mkdir -p layer
virtualenv -p /usr/bin/python3.9 ./layer/
source ./layer/bin/activate
pip3 install pycryptodome==3.17.0
pip3 install paramiko==2.7.1
pip3 install requests==2.23.0
pip3 install scp==0.13.2
pip3 install jsonschema==3.2.0
pip3 install cffi==1.15.1
pip3 install zipp==3.1.0
pip3 install importlib-metadata==1.6.0
echo "Copy from ./layer directory to ./python\n"
mkdir -p ./python/
cp -r ./layer/lib/python3.9/site-packages/* ./python/
zip -r cluster_layer.zip ./python
deactivate
```

The resultant `cluster_layer.zip` file should be copied to the `lambda-python-files` folder. <br>

## Create `cluster_manager.zip` & `cluster_lifecycle.zip`

1. Change into the `cluster/aws/` directory.
2. Execute the `make.py` script to create the `cluster_manager.zip` & `cluster_lifecycle.zip` files.
   ```bash
   python3 make.py build
   ```
3. The `cluster_manager.zip` & `cluster_lifecycle.zip` files will be created in the `target` folder.
4. The three files `cluster_layer.zip`, `cluster_manager.zip`, and `cluster_lifecycle.zip` will need to be uploaded to the S3 bucket created after the infrastructure stack is deployed.

# AWS NGFWv Cluster Deployment Steps

## Step 1 - Deploy `infrastructure.yaml`

Go to "CloudFormation" on AWS Console.

1. Click on "Create stack" and select "With new resources (standard)"
2. Select "Upload a template file", Click on "Choose file" and select `infrastructure.yaml` from target folder
3. Click on "Next", Read all the Parameter's Label & instructions carefully. Add/Update Template parameters according to your requirement.
4. Click "Next" and "Create stack".
5. Once deployment is complete, go to "Outputs" and note S3 "BucketName"
6. Go to S3, Open the newly created S3 bucket and upload `cluster_layer.zip`, `cluster_manager.zip` & `cluster_lifecycle.zip`.

## Deploy "deploy_ngfw_cluster.yaml"

Go to "CloudFormation" on AWS Console.

1. Click on "Create stack" and select "With new resources (standard)"
2. Select "Upload a template file", Click on "Choose file" and upload `deploy_ngfw_cluster.yaml`.
3. Click on "Next", Read all the Parameter's Label & instructions carefully. Add/Update/Select Template parameters according to your requirement.

- **Note** Carefully validate the paramaters match Security Groups, Subnets and VPCs created in your AWS account.

4. Click "Next" and "Create stack".
5. As the FTDv devices boot, they should form a cluster. The Lambda functions will automatically log into the FTDv and the FMC to register the devices and create a cluster. It is _important_ that the FMC is reachable from both the FTDv management interfaces and from the Lamdba function subnets. This shouln't be an issue if the FMC is deployed on the same management subnet as the FTDv devices but if it is located else where (such as on-premise, over a VPN) then you will need to update the appropriate security groups and routing tables to allow the Lambda functions to reach the FMC.
6. If the devices do _not_ form a cluster, you can check the Lambda logs for the `<cluster name>-manager-lambda` function to understand what actions failed.
