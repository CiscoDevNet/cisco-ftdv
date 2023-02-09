# Clustering for the Threat Defense Virtual in a Public Cloud
Clustering lets you group multiple threat defense virtuals together as a single logical device. A cluster provides
all the convenience of a single device (management, integration into a network) while achieving the increased
throughput and redundancy of multiple devices. You can deploy threat defense virtual clusters in a public
cloud using Amazon Web Services (AWS) or Google Cloud Platform (GCP). Only routed firewall mode is
supported. <br>

## Deploy the Cluster in Azure
You can use the cluster with the Azure Gateway Load Balancer, or with a non-native load-balancer such as the Cisco Cloud Services Router. To deploy a cluster in Azure, use Azure Resource Manager (ARM) templates to deploy a Virtual Machine Scale Set.

Deploy a Virtual Machine Scale Set for GWLB Using an Azure Resource Manager Template
Deploy the Virtual Machine Scale Set for Azure GWLB using the customized Azure Resource Manager (ARM) template.

## Deployment Steps

Step 1: Prepare the template.

Clone the github repository to your local folder. See https://github.com/CiscoDevNet/cisco-ftdv/tree/master/cluster/azure.

For GWLB, modify azure_ftdv_gwlb_cluster.json and azure_ftdv_gwlb_cluster_parameters.json with the required parameters. For non-GWLB, modify azure_ftdv_nlb_cluster.json and azure_ftdv_nlb_cluster_parameters.json.

Step 2 : Log into the Azure Portal: https://portal.azure.com.

Step 3 : Create a Resource Group.

Step 4 : Create a virtual network with four subnets: Management, Diagnostic, Outside, and CCL.

Step 5 : Deploy the Custom Template.

Step 6 : Once the deployment is done user can register the control node to the FMCv 
