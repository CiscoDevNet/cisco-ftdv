# Clustering for the Threat Defense Virtual in a Public Cloud
Clustering lets you group multiple threat defense virtuals together as a single logical device. A cluster provides
all the convenience of a single device (management, integration into a network) while achieving the increased
throughput and redundancy of multiple devices. You can deploy threat defense virtual clusters in a public
cloud using Amazon Web Services (AWS) or Google Cloud Platform (GCP). Only routed firewall mode is
supported. <br>

# Cloud Formation Template Deployment
## Prerequisites:
Deployment can be run on any macOS/Linux/Windows machine with Google SDK installed OR using google cloud shell. <br>

## Pre-deployment Steps:
Step-1: Edit "infrastructure.yaml" , "cluster_function_infra.yaml" and "north-south/deploy_ngfw_cluster.yaml" or "east-west/deploy_ngfw_cluster.yaml" as applicable for resourceNamePrefix and provide required user inputs.<br>
e.g: resourceNamePrefix = ngfwvcls <br>

Step-2: Create Bucket with name "ngfwvcls-ftdv-cluster-bucket" for uploading google function src archieve "ftdv_cluster_function.zip" file <br>
a) Create Bucket using below CLI on Google Cloud Shell:<br>

	'gsutil mb --pap enforced gs://ngfwvcls-ftdv-cluster-bucket/'
<br>
b) Create zip using below CLI for macOS/Linux user:<br>

	'zip -j ftdv_cluster_function.zip ./cluster-function/*'
<br>
	Note: if bucket name is different then edit cluster_function_infra.yaml in pre-deployment step.<br>
c) Upload google function src archieve to bucket using below CLI on Google Cloud Shell:<br>

	'gsutil cp ftdv_cluster_function.zip gs://ngfwvcls-ftdv-cluster-bucket'
<br>
	Note: if src archieve name is different then edit cluster_function_infra.yaml in pre-deployment step.<br>

## Deployment Steps:
Step-3: Deploy infrastructure for FTDv cluster using below CLI on Google Cloud Shell: <br>

	'gcloud deployment-manager deployments create <name> --config infrastructure.yaml'
<br>
Step-4:<br>
a) Launch and setup FMCv with FTDv management vpc if working with private IP<br>
b) Create vpcConnector for Cloud Functions with FTDv management vpc, use it in step-5:<br>

	'gcloud compute networks vpc-access connectors create <name> --region us-central1 --subnet ngfwvcls-ftdv-mgmt-subnet28'
<br>
	Note: vpcConnector Name will be  used in cluster_function_infra.yaml as an input for vpcConnectorName.<br>

Step-5: <br>
 Make sure to set deployWithExternalIP as True in cluster_function_infra.yaml if FTDv require external IP. Deploy FTDv cluster google function using below CLI on Google Cloud Shell:<br>

	'gcloud deployment-manager deployments create <name> --config cluster_function_infra.yaml'
<br>
Step-6: <br>

Deploy FTDv cluster using below CLI on Google Cloud Shell:<br>
a) For North-South topology deployment<br>

	'gcloud deployment-manager deployments create <name> --config north-south/deploy_ngfw_cluster.yaml'
<br>

b) For East-West topology deployment<br>

	'gcloud deployment-manager deployments create <name> --config east-west/deploy_ngfw_cluster.yaml'
<br>

