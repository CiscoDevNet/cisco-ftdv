# Azure Cisco Secure Firewall Management Center Virtual (CSF-MCv) deployment using VHD and ARM template

In addition to the Marketplace-based deployment, Cisco provides a compressed virtual hard disk (VHD) that you can upload to Azure to simplify the process of deploying the CSF-MCv in Azure. <br>
Using a Image and two JSON files (a Template file and a Parameter File), you can deploy and provision all the resources for the CSF-MCv in a single, coordinated operation. <br>

To deploy using a VHD image, you must upload the VHD image to your Azure storage account. Then, you can create a image using the uploaded disk image and an Azure Resource Manager template.<br>
Azure templates are JSON files that contain resource descriptions and parameter definitions.<br>

[Azure CSF-MCv quick start guide](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/fmcv/fpmc-virtual/fpmc-virtual-azure.html)


## Deployment overview

Please refer the CSF-TDv deployment procedure and this CSF-MCv deployment is very similar to that.<br>
[Azure CSF-MCv quick start guide](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/fmcv/fpmc-virtual/fpmc-virtual-azure.html#id_106502)

1. Download the Firepower Management Center Virtual vhd image from Cisco Download Software download page. <br>
e.g. 7.7.0-91 CSF-MCv image can be downloaded from:<br>
URL  : https://software.cisco.com/download/home/286259687/type/286271056/release/7.7.0<br>
File : [ CSF-MCv v7.7.0 on Azure ]  	Cisco_Secure_FW_Mgmt_Center_Virtual_Azure-7.6.0-91.vhd.bz2<br>

2. Create a linux VM in Azure, un-compress the *.bz2 & upload the VHD image to container in Azure storage account.

3. Create a Image from the VHD and acquire the Resource ID of the newly created Image.

4. Use the ARM template to deploy a Firepower Management Center Virtual using the image.

5. Update the parameters in the parameters template file(json) and use it to provide the parameters to the ARM template.

6. Review and purchase the template to deploy Firepower Management Center Virtual.

7. Configure the CSF-MCv

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCiscoDevNet%2Fcisco-ftdv%2Fmaster%2Fdeployment-templates%2Fazure%2FCiscoSecureFirewallVirtual-7.7.0%2Fcsf-mcv-ipv6-custom-image-template%csf-mcv-ipv6-custom-image-template.json)

## Parameters for the Azure ARM template:

### Pre-requisites:
1. Image ID (created using the downloaded vhd)
2. Virtual network with at least 1 subnet for management interface.

### Parameters:
1. **vmName**: Name the CSF-MCv VM in Azure.<br>
e.g. cisco-mcv

2. **vmImageId**: The ID of the image used for deployment. Internally, Azure associates every resource with a Resource ID.<br>
e.g. /subscriptions/<subscription-id>/resourceGroups/blr-virtual-images-rg/providers/Microsoft.Compute/images/cisco-mcv-77091

3. **adminUsername**: The username for logging into CSF-MCv. This cannot be the reserved name "admin".<br>
e.g. jdoe

4. **adminPassword**: The admin password. This must be 12 to 72 characters long, and include three of the following: 1 lower case, 1 upper case, 1 number, 1 special character.<br>
e.g. Password@2023

5. **customData**: The field to provide Day 0 configuration to the CSF-MCv. By default it has 2 key-value pairs to configure 'admin' user password and the CSF-MCv hostname.<br>
e.g. {"AdminPassword": "Password@2023", "Hostname": "cisco-mcv", "ntp1": "<NTPServer1>", "ntp2": "<NTPServer2>" }

6. **availabilityZone**: Specify the availability zone for deployment, Public IP and the virtual machine will be created in the specified availability zone.<br>
Set it to '0' if you do not need availability zone configuration. Ensure that selected region supports availability zones and value provided is correct.
(This must be an integer between 0-3).<br>
e.g. 0

7. **vmStorageAccount**: Your Azure storage account. You can use an existing storage account or create a new one. The storage account name must be between 3 and 24 characters, and can only contain lowercase letters and numbers.<br>
e.g. testmcvstorage

8. **virtualNetworkResourceGroup**: The name of the virtual network's Resource Group. The CSF-MCv is always deployed into a new Resource Group.<br>
e.g. test-mcv-rg

9. **virtualNetworkName**: The name of the virtual network.<br>
e.g. test-mcv-vnet

10. **mgmtSubnetName**: The management interface will attach to this subnet. This maps to Nic0, the first subnet. Note, this must match an existing subnet name if joining an existing network.<br>
e.g. mgmt

11. **mgmtSubnetIP**: The Management interface IP address.<br>
e.g. 10.4.0.15

12. **vmSize**: The VM size to use for the CSF-MCv. Standard_D4_V2 & Standard_D4 are supported. <br>
e.g. Standard_D4_V2

13. **location**: This shouldn't be changed and should always be set to the below value.<br>
resourceGroup().location

14. **baseStorageURI**: This is used to fetch the storage account and should always be set to the below value.<br>
.blob.core.windows.net

15. **publicInboundPorts**: The ports that are open to the public, choose "none" to create no open ports in network security group.<br>
e.g. none

16. **selectedInboundPorts**: The ports for which the open public rules are created in network security group.<br>
e.g. 22,443,8305


## References
* [Software Downloads Home - CSF-MCv](https://software.cisco.com/download/home/286259687/type/286271056/release/7.7.0)
* [CSF-TDv deployment](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/consolidated_ftdv_gsg/threat-defense-virtual-77-gsg/m-ftdv-azure-gsg.html#id_82702)
* [CSF-MCv deployment](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/fmcv/fpmc-virtual/fpmc-virtual-azure.html#id_106502)
* [CSF-MCv deployment steps](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/fmcv/fpmc-virtual/fpmc-virtual-azure.html#id_82702)

## Licensing Info
This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../../../LICENSE) file for details.

## Copyright
Copyright (c) 2025 Cisco Systems Inc and/or its affiliates.

## Changelog
### 7.7.0
- Deployment templates for Azure resources

### 7.7.0
- Add parameter to select the ports(22,443,8305) to create network security group rules for public access
- API version updates for Azure resources

### 7.4.1
- API version updates for Azure resources

### 7.3.0
- API version updates for Azure resources

### 7.1.0
- API version updates for Azure resources

### 7.0.0
- Changes to support deployment selected in Availability Zones

### 6.7.0
- API version updates for Azure resources
