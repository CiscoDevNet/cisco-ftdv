# Azure Firepower Management Center Virtual deployment using VHD and ARM template

In addition to the Marketplace-based deployment, Cisco provides a compressed virtual hard disk (VHD) that you can upload to Azure to simplify the process of deploying the Firepower Management Center Virtual in Azure. <br>
Using a Image and two JSON files (a Template file and a Parameter File), you can deploy and provision all the resources for the Firepower Management Center Virtual in a single, coordinated operation. <br>

To deploy using a VHD image, you must upload the VHD image to your Azure storage account. Then, you can create a image using the uploaded disk image and an Azure Resource Manager template.<br>
Azure templates are JSON files that contain resource descriptions and parameter definitions.<br>

[Azure FMCv quick start guide](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/fmcv/fpmc-virtual/fpmc-virtual-azure.html)


## Deployment overview

Please refer the NGFWv/FTDv deployment procedure and this FMCv deployment is very similar to that.<br>
[Azure NGFWv quick start guide](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/azure/ftdv-azure-qsg.html)

1. Download the Firepower Management Center Virtual vhd image from Cisco Download Software download page. <br>
e.g. 7.0.0-94 NGFWv image can be downloaded from:<br>
URL  : https://software.cisco.com/download/home/286259687/type/286271056/release/7.0.0 <br>
File : [ Firepower Management Center Virtual v7.0.0 on Azure ]  	Cisco_Firepower_Mgmt_Center_Virtual-7.0.0-94.vhd.bz2<br>

2. Create a linux VM in Azure, un-compress the *.bz2 & upload the VHD image to container in Azure storage account.

3. Create a Image from the VHD and acquire the Resource ID of the newly created Image.

4. Use the ARM template to deploy a Firepower Management Center Virtual using the image.

5. Update the parameters in the parameters template file(json) and use it to provide the parameters to the ARM template.

6. Review and purchase the template to deploy Firepower Management Center Virtual.

7. Configure the FMCv/Firepower Management Center Virtual


## Parameters for the Azure ARM template:

### Pre-requisites:
1. Image ID (created using the downloaded vhd)
2. Virtual network with at least 1 subnet for management interface.

### Parameters:
1. **vmName**: The name the Firepower Management Center Virtual VM will have in Azure.<br>
e.g. cisco-fmcv

2. **vmImageId**: The ID of the image used for deployment. Internally, Azure associates every resource with a Resource ID.<br>
e.g. /subscriptions/f160cf7e-ae69-4e9f-8ad0-b434b9a63755/resourceGroups/blr-virtual-images-rg/providers/Microsoft.Compute/images/cisco-fmcv-70094

3. **adminUsername**: The username for logging into Firepower Management Center Virtual. This cannot be the reserved name "admin".<br>
e.g. jdoe

4. **adminPassword**: The admin password. This must be 12 to 72 characters long, and include three of the following: 1 lower case, 1 upper case, 1 number, 1 special character.<br>
e.g. Password@123123

5. **customData**: The field to provide Day 0 configuration to the FMCv. By default it has 2 key-value pairs to configure 'admin' user password and the FMCv hostname.<br>
e.g. {"AdminPassword": "FmcvPass@123123", "Hostname": "cisco-fmcv", "ntp1": "<NTPServer1>", "ntp2": "<NTPServer2>" }

6. **availabilityZone**: Specify the availability zone for deployment, Public IP and the virtual machine will be created in the specified availability zone.<br>
Set it to '0' if you do not need availability zone configuration. Ensure that selected region supports availability zones and value provided is correct.
(This must be an integer between 0-3).<br>
e.g. 0

7. **vmStorageAccount**: Your Azure storage account. You can use an existing storage account or create a new one. The storage account name must be between 3 and 24 characters, and can only contain lowercase letters and numbers.<br>
e.g. testfmcvstorage

8. **virtualNetworkResourceGroup**: The name of the virtual network's Resource Group. The Firepower Management Center Virtual is always deployed into a new Resource Group.<br>
e.g. test-fmcv-rg

9. **virtualNetworkName**: The name of the virtual network.<br>
e.g. test-fmcv-vnet

10. **mgmtSubnetName**: The management interface will attach to this subnet. This maps to Nic0, the first subnet. Note, this must match an existing subnet name if joining an existing network.<br>
e.g. mgmt

11. **mgmtSubnetIP**: The Management interface IP address.<br>
e.g. 10.4.0.15

12. **vmSize**: The VM size to use for the Firepower Management Center Virtual VM. Standard_D4_V2 & Standard_D4 are supported. <br>
e.g. Standard_D4_V2


## References
* [Software Downloads Home](https://software.cisco.com/download/home/286306503/type/286306337/release/7.0.0)
* [FTDv deployment](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/azure/ftdv-azure-gsg/ftdv-azure-deploy.html#id_82702)
* [FMCv deployment](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/fmcv/fpmc-virtual/fpmc-virtual-azure.html#id_106502)
* [FMCv deployment steps](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/azure/ftdv-azure-qsg.html#pgfId-160281)

## Licensing Info
This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../../../LICENSE) file for details.

## Copyright
Copyright (c) 2020 Cisco Systems Inc and/or its affiliates.

## Changelog
### 7.0.0
- Changes to support deployment selected in Availability Zones

### 6.7.0
- API version updates for Azure resources
