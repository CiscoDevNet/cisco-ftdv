# STEPS TO DEPLOY GWLB AUTOSCALE END-TO-END <br>
This guide covers the Deployment steps for AWS GWLB FTDv AutoScale. <br>

There are 2 supported deployment topologies:
1. Single-arm
2. Dual-arm

And 2 supported IP types:
1. IPv4
2. DualStack (IPv4+IPv6)

------------------------------------------------------------------------------------------------

## Clone the Repository

Clone the 'cisco-ftdv' repository in an AWS CloudShell session or to your local environment. Navigate to the subdirectory "cisco-ftdv/autoscale/aws" for the required content.

## Deploy Infrastructure Stack using "infrastructure_gwlb.yaml"

If you do not have a pre-existing VPC, subnets, and S3 bucket to use, deploy this infrastructure using the following steps:

1. Go to "CloudFormation" in the AWS Console
2. Click "Create stack" and select "With new resources (standard)"
3. Select "Upload a template file", click "Choose file" and select "infrastructure_gwlb.yaml" from the "templates" folder
4. Click "Next", read all the parameters, labels, and instructions carefully. Fill in parameters according to your requirements
5. **Set parameter "DualStack" to "True" for DualStack (IPv4+IPv6) deployment or "False" for IPv4 deployment**
6. Click "Next" and "Create stack"
7. Verify that stack creation is successful. Once done, go to "Outputs" and note the "BucketName"

## FMCv Prerequisites

FMCv can be deployed in the VPC created by the infrastructure stack, or in any other environment. In the latter case, it should be reachable to the infrastructure VPC by public IP.

1. Create the following objects in FMCv:
   - Access Policy
   - Security Zones for interfaces: Inside, Outside, VNI (VNI required for dual-arm only)
   - Device Group for FTDv instances
2. Associate the Access Policy to the Device Group
3. Create 2 API users in FMCv with Administrator privileges:
   - One for Lambda functions to access/configure FMCv
   - One to fetch Memory Metrics
4. **[FOR DUALSTACK-ENABLED DUAL-ARM DEPLOYMENT ONLY]**: Create a Group Object or Network Object in FMCv:
   - An object named "IPv6-Application-CIDRs" specifying Application IPv6 CIDRs is required for East-West traffic routing

**NOTE: FMCv prerequisites MUST be completed correctly before deploying the Autoscale Stack!**

## Update "Configuration.json" and "Configuration-schema.json" File Structure Based on Topology

Configuration.json contains FMC-related information, which is used by the AutoScale manager Lambda function. <br>

Topology-specific sample structures for Configuration.json and Configuration-schema.json files are provided in the directory "cisco-ftdv/autoscale/aws/sample-configuration-jsons". <br>

Navigate to this directory. <br>
* For dual-arm topology: refer to sample files with 'gwlb-dual-arm' prefix <br>
* For single-arm topology: refer to sample files with 'gwlb-single-arm' prefix (default content, no modification needed) <br>

Based on your topology, copy the content from the sample files and paste it into Configuration.json and Configuration-schema.json (located in "cisco-ftdv/autoscale/aws/lambda-python-files"). <br>

This creates the correct file structure. You will need to add actual FMC object values in the next step.

## Update FMCv Object Names in Configuration.json

Update Configuration.json with the EXACT names of:
1. Interfaces
2. Security Zone objects
3. Device Group
4. Access Policy created in FMCv

Platform Policy and NAT Policy (dual-arm ONLY) will be created by the Lambda function.

**WARNING**: If incorrect object names are specified in Configuration.json, the AutoScale Manager Lambda function will fail!

**NOTE**: Routes in "DualArmTrafficRoutesIPv6" or "SingleArmTrafficRoutesIPv6" are applied only if DualStack is enabled.

### Mandatory Changes for Routing

**FOR DUAL-ARM + DUALSTACK DEPLOYMENT ONLY**

1. The object "IPv6-Application-CIDRs" specified in the "network" field of the vni-in interface route under "DualArmTrafficRoutesIPv6" is not a default object and must be created in FMCv
2. This object contains the Application CIDRs for East-West traffic routing

### Optional Changes for Routing

You can make the following changes to Configuration.json to set up routing to your custom networks instead of the default ones currently used. <br>

You should create those Network Objects/Object Groups in FMC and specify them in the routing section of Configuration.json. <br>

#### For Single-arm Deployment: "SingleArmTrafficRoutes" is Applied to FTD Devices <br>

1. For "inside" interface route (used for GWLB Health Checks): <br>
   - Create a network object in FMC specifying the AWS GWLB's VPC CIDR range <br>
   - Provide this object name in the "network" field. Currently, "network" specifies the pre-defined FMC object "any-ipv4" which includes all IPv4 addresses <br>
2. **[IF DUALSTACK-ENABLED]**: A similar change can be made in "SingleArmTrafficRoutesIPv6" for "inside" interface IPv6 route <br>

#### For Dual-arm Deployment: "DualArmTrafficRoutes" is Applied to FTD Devices <br>

1. For "vni-in" interface route (used for East-West Traffic): <br>
   - Create a network object group in FMC specifying all Application Network CIDR ranges in your topology
   - Provide this object group name in the "network" field. Currently, "network" specifies the pre-defined FMC object "IPv4-Private-All-RFC1918", which includes the RFC 1918 IPv4 private address range


## Create Lambda Layer "autoscale_layer.zip" Needed for Lambda Functions

The "autoscale_layer.zip" can be created on an Amazon Linux VM with Python 3.11 installed. We recommend using AWS CloudShell, which runs the latest version of Amazon Linux.

To create the autoscale_layer.zip file, you need to first create a requirements.txt file that contains the Python library package details, then run the shell script.

1. Create the requirements.txt file by specifying the Python package details:
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

2. Run the following commands to create the autoscale_layer.zip file:
```bash
$ pip3 install --platform manylinux2014_x86_64 \
--target=./python/lib/python3.11/site-packages \
--implementation cp --python-version 3.11 --only-binary=:all: \
--upgrade -r requirements.txt
$ zip -r autoscale_layer.zip ./python
```

**NOTE**: If you encounter a dependency conflict during installation (e.g., for packages urllib3 or cryptography), include the conflicting packages along with their recommended versions in the requirements.txt file. Run the installation command again to resolve the conflict.

3. Place the resulting autoscale_layer.zip file in the directory 'cisco-ftdv/autoscale/aws/lambda-python-files'.

## Run make.py to Create Lambda Function Files

This step creates "autoscale_manager.zip", "autoscale_lifecycle.zip", and "custom_metric_fmc.zip".

A make.py file is located in "cisco-ftdv/autoscale/aws". Navigate to this directory.

Running make.py will compress the required Python files into ZIP archives and copy them to a new "target" folder.

Build the make.py file using the following command to create Lambda function ZIP files:
```bash
$ python3 make.py build
```
All required ZIP files will be copied to the "target" folder.

## Upload Lambda Layer and Function Files to S3 Bucket

Upload the ZIP files "autoscale_layer.zip", "autoscale_manager.zip", "autoscale_lifecycle.zip", and "custom_metric_fmc.zip" from the "target" folder to the S3 bucket.

1. **If running on AWS CloudShell**: Run the following command for each of the 4 ZIP files to upload them to the S3 bucket:
   ```bash
   aws s3 cp /path/to/zip/file s3://your-bucket-name/
   ```

2. **If running on a local environment**: In the AWS GUI, navigate to AWS S3 > /your-bucket-name/ and upload the 4 ZIP files to the S3 bucket

## [OPTIONAL] KMS Encryption for FMC and FTD Passwords

If you plan to pass encrypted passwords (not plaintext) to the Autoscale stack:

1. First, create a symmetric key in AWS KMS > Customer Managed Keys
2. Use this key to encrypt your plaintext password using the following command:
```bash
aws kms encrypt \
  --key-id <KMS-Key-ARN> \
  --plaintext <plaintext-password> \
  --cli-binary-format raw-in-base64-out \
  --output text \
  --query CiphertextBlob
```
3. This command will output the encrypted password. Use this command to encrypt all your plaintext passwords. These encrypted passwords can be specified for FTD/FMC password parameters in the Autoscale Stack <br>
4. The encrypted passwords will be decrypted appropriately by the Manager Lambda, and plaintext passwords will be applied to FTD/FMC <br>

## Deploy Autoscale Stack using "deploy_ngfw_autoscale_with_gwlb.yaml"

1. Go to "CloudFormation" in the AWS Console
2. Click "Create stack" and select "With new resources (standard)"
3. Select "Upload a template file", click "Choose file" and select "deploy_ngfw_autoscale_with_gwlb.yaml" from the "target" folder
4. Click "Next", read all the parameter labels and instructions carefully. Update parameters based on your requirements
5. **Set parameter "DualStack" to "True" for DualStack (IPv4+IPv6) deployment or "False" for IPv4 deployment**
6. Set parameter "DeploymentType" to "SINGLE_ARM" or "DUAL_ARM" based on your requirements
7. For parameter "fmcServer", specify the FMCv IPv6 or IPv4 address. **NOTE**: FTDv-FMCv registration will be based on the FMCv IP version
8. If using KMS-encrypted passwords, enter the encrypted passwords in the password fields and the AWS Key ARN in the "KmsArn" field
9. Click "Next" and "Create stack"
10. Verify that stack creation is successful

## Security Group Rules

1. **FMCv - FTDv Connectivity:**
   - Allow FMCv IP (specified in Autoscale Stack parameter "fmcServer") to FTDv instances' Management Security Group
   - This is required for FTDv to register with FMCv

2. **Lambda - FMCv Connectivity:**
   Based on the FMCv IP version, add the corresponding rules to FMCv's Management Security Group. This is required for Lambda functions to access FMCv:
   - **[For IPv4 FMCv]**: Allow Autoscale VPC's NAT Gateway IP (specified in Infrastructure Stack output "EIPforNATgw") to FMCv Security Group
   - **[For IPv6 FMCv]**: Allow Lambda subnets' IPv6 CIDRs to FMCv Security Group

## Launch FTDv Instance(s)

1. Navigate to the AutoScale Group created by the stack. Set Desired Capacity = 1. One FTDv instance will be launched
2. Lambda functions will manage the following processes:
   - FTDv: Attaching multiple interfaces, updating device name, hostname, and password
   - FTDv registration to FMCv
   - Interface configuration including Geneve configs
   - Platform Policy configuration
   - Static Routes configuration
   - **[Dual-arm only]**: Egress NAT
3. **Validate Tags**: A fully-configured FTDv instance's tags should reflect the following values:
   - NGFWvConnectionStatus = "AVAILABLE"
   - NGFWvRegistrationStatus = "DONE"
   - NGFWvConfigurationStatus = "DONE"
   - NGFWvConfigDeployStatus = "DONE"
4. If any of these tags are not as expected, check the CloudWatch Logs of the AutoScale Manager Lambda for error messages 