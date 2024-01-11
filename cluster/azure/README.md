# Clustering for the Threat Defense Virtual in a Public Cloud
Clustering lets you group multiple threat defense virtuals together as a single logical device. A cluster provides
all the convenience of a single device (management, integration into a network) while achieving the increased
throughput and redundancy of multiple devices. You can deploy Threat Defense Virtual clusters in a public
cloud using Azure, Amazon Web Services (AWS), Google Cloud Platform (GCP). Only routed firewall mode is
supported.<br>
<br>
Note: Version 7.4.1 onwards user can deploy 3-interface FTDv (Management, Inside, Outside) FTDv without Diagnostic interface.<br>


## Deploy the Cluster in Azure
You can use the cluster with the Azure Gateway Load Balancer, or with a non-native load-balancer such as the Cisco Cloud Services Router. To deploy a cluster in Azure, use Azure Resource Manager (ARM) templates to deploy a Virtual Machine Scale Set.

Deploy a Virtual Machine Scale Set for GWLB Using an Azure Resource Manager Template
Deploy the Virtual Machine Scale Set for Azure GWLB using the customized Azure Resource Manager (ARM) template.

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

Step 6 : Once the deployment is done user can register the control node to the FMCv 
