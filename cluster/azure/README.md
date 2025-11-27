# Clustering Autoscale for the Threat Defense Virtual in a Public Cloud
Clustering Autoscale lets you group multiple threat defense virtuals together as a single logical device. A cluster provides all the convenience of a single device (management, integration into a network) while achieving the increased throughput and redundancy of multiple devices. You can deploy Threat Defense Virtual clusters in a public cloud using Azure, Amazon Web Services (AWS), Google Cloud Platform (GCP). Only routed firewall mode is supported.<br>
<br>
Note: Version 7.4.1 onwards user can deploy 3-interface FTDv (Management, Inside, Outside) FTDv without Diagnostic interface.<br>


## Deploy the Clustering Autoscale in Azure
You can use the cluster Autoscale with the Azure Gateway Load Balancer or the Standard Load Balancer. To deploy the clustering Autoscale solution, Use the ARM templates and the azure functions provided by Cisco.

## Pre-Requisites
1. Azure Resource Group should be created
2. Virtual Network and the necessary subnets are created
    For Cluster Autoscale with Standard Loadbalancer : Management, Inside, Outside and CCL
    For Cluster Autoscale with GWLB : Management, Data and CCL
3. In FMCv side ensure that
    - FMCv is licensed
    - Access policy is created 
    - Security zone(SZ) object for the interfaces is created
    - Separate User credentials for the azure function to add and configure the FTDv instances to the FMCv
    - Platform settings for the health probe when the cluster group is added to the FMCv
    - Azure CLI is installed on your local computer
    - Download Azure Clustering Autoscale repo to your local computer and execute "python3 make.py build" to create cluster_functions.zip file.

## Deployment Steps

Step 1: Prepare the template.

Clone the github repository to your local folder. See https://github.com/CiscoDevNet/cisco-ftdv/tree/master/cluster/azure.

For GWLB, modify azure_ftdv_gwlb_cluster.json and azure_ftdv_gwlb_cluster_parameters.json with the required parameters. For non-GWLB, modify azure_ftdv_nlb_cluster.json and azure_ftdv_nlb_cluster_parameters.json.
For deploying 3-interface FTDv cluster (GWLB or non-GWLB), use the files with prefix 'withoutDiagnostic'. 

Step 2 : Log into the Azure Portal: https://portal.azure.com.

Step 3 : Create a Resource Group.

Step 4 : For GWLB , create a virtual network with 4 subnets: Management, Diagnostic, CCL and Data subnet. For non-GWLB, create virtual network with 5 subnets : Management, Diagnostic, Data-inside, CCL, Inside and Outside data subnets. 
For 3-interface (withoutDiagnostic) deployments, Diagnostic subnet is not needed. 

Step 5 : Deploy the Custom Template.

Step 6 : Once the custom template deployment is completed, the function app will be created <resourceNamePrefix>-function-app

Step 7 : Get into the target folder and Execute the following command from your local computer to deploy the cluster autoscale azure function to the function app. Upon the successful deployment of the functions, The uploaded functions should be visible in the overview section of the function app.
        az functionapp deployment source config-zip -g <Resource Group Name> -n <Function App Name> --src <cluster_functions.zip> --build-remote true

Step 8 : Once the function app deployment is completed, Click on the logic app created during the template deployment, Click on Logic app code view and remove the existing content. Open the target/logic_app.txt file downloaded in the Clustering Autoscale repo and replace the place holder SUBSCRIPTION_ID with the original subscription id, RESOURCE_GROUP_NAME with the resource group name, FUNCTION_APP_NAME with the function app name.

Step 9 : Copy the logic_app.txt content to logic app's  Logic app code view and click to Save it.

Step 10 : Click on the overview section of the Logic app and click "Enable". Once the logic app is enabled, the run will be triggered and it can be viewed in the overview section.
