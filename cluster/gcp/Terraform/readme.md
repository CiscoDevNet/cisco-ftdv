# Clustering for the Threat Defense Virtual in a Public Cloud
Clustering lets you group multiple threat defense virtuals together as a single logical device. A cluster provides
all the convenience of a single device (management, integration into a network) while achieving the increased
throughput and redundancy of multiple devices. You can deploy threat defense virtual clusters in a public
cloud using Amazon Web Services (AWS) or Google Cloud Platform (GCP). Only routed firewall mode is
supported. <br>

# Cloud Formation Template Deployment
## Prerequisites:
Deployment can be run on any macOS/Linux/Windows machine with Google SDK and terraform installed.<br>

## Pre-deployment Steps:
Step-1: Edit "ngfwv_infra/variables.tf", "cluster_function_infra/variables.tf" and "deploy_ngfw_cluster/variables.tf" for resourceNamePrefix and provide required user inputs.Also depending on whether you want the Diagnostic interface or not, set the value of variable withDiagnostic accordingly in "ngfwv_infra/variables.tf" and "deploy_ngfw_cluster/variables.tf".<br>
e.g: resourceNamePrefix = ngfwvcls <br>

Step-2: Enable User Application Default Credentials (ADCs) to use terraform with your GCP project by running the following command: <br>
    
    'gcloud auth application-default login'

<br>
Step-3: Create Bucket with name "ngfwvcls-ftdv-cluster-bucket" for uploading google function src archieve "ftdv_cluster_function.zip" file <br>
a) Create Bucket using below CLI on Google Cloud Shell:<br>

	'gsutil mb --pap enforced gs://ngfwvcls-ftdv-cluster-bucket/'
<br>
b) Create zip using below CLI for macOS/Linux user:<br>

	'zip -j ftdv_cluster_function.zip ../cluster-function/*'

<br>

	Note: if bucket name is different then edit cluster_function_infra/variables.tf in pre-deployment step.<br>
b) Upload google function src archieve to bucket using below CLI on Google Cloud Shell:<br>

	'gsutil cp ftdv_cluster_function.zip gs://ngfwvcls-ftdv-cluster-bucket'
<br>
	Note: if src archieve name is different then edit cluster_function_infra/variables.tf in pre-deployment step.<br>

## Deployment Steps:
Step-4: <br>
Deploy infrastructure for FTDv cluster using below CLI on your terminal: <br>

	'cd ./ngfwv_infra/'
    'terraform init'
    'terraform plan'
    'terraform apply'
<br>
Step-5:<br>
a) Launch and setup FMCv with FTDv management vpc if working with private IP<br>
b) Create vpcConnector for Cloud Functions with FTDv management vpc, use it in step-5:<br>

	'gcloud compute networks vpc-access connectors create <name> --region us-central1 --subnet ngfwvcls-ftdv-mgmt-vpcsubnt'
<br>
	Note: vpcConnector Name will be  used in cluster_function_infra/variables.tf as an input for vpcConnectorName.<br>

Step-6: <br>
 Make sure to set deployWithExternalIP as True in cluster_function_infra/variables.tf and deploy_ngfw_cluster/variables.tf if FTDv require external IP. <br> 
 Deploy FTDv cluster google function using below CLI on your terminal:<br>

	'cd ../cluster_function_infra/'
    'terraform init'
    'terraform plan'
    'terraform apply'
<br>
Step-7: <br>
Deploy FTDv cluster using below CLI on your terminal:<br>

	'cd ../deploy_ngfw_cluster'
    'terraform init'
    'terraform plan'
    'terraform apply'
<br>
