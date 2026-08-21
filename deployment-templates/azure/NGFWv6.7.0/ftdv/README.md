# Azure NGFWv deployment using VHD and ARM template

In addition to the Marketplace-based deployment, Cisco provides a compressed virtual hard disk (VHD) that you can upload to Azure to simplify the process of deploying the Firepower Threat Defense Virtual in Azure. <br>
Using a Image and two JSON files (a Template file and a Parameter File), you can deploy and provision all the resources for the Firepower Threat Defense Virtual in a single, coordinated operation.

To deploy using a VHD image, you must upload the VHD image to your Azure storage account. Then, you can create a image using the uploaded disk image and an Azure Resource Manager template.<br>
Azure templates are JSON files that contain resource descriptions and parameter definitions.

Use the instructions in the quick start guide for NGFWv deployment.<br>

[Azure NGFWv quick start guide](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/azure/ftdv-azure-qsg.html)


## Deployment overview

1. Download the NGFWv vhd image from Cisco Download Software download page.<br>
e.g. 6.6.0-90 NGFWv image can be downloaded from:<br>
URL  : https://software.cisco.com/download/home/286306503/type/286306337/release/6.7.0 <br>
File : [ Firepower NGFW Virtual v6.7.0 on Azure ] : Cisco_Firepower_Threat_Defense_Virtual-6.7.0-65.vhd.bz2<br>

2. Create a linux VM in Azure, un-compress the *.bz2 & upload the VHD image to container in Azure storage account.

3. Create a Image from the VHD and acquire the Resource ID of the newly created Image.

4. Use the ARM template to deploy a Firepower Threat Defense Virtual firewall using the image.\
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCiscoDevNet%2Fcisco-ftdv%2Fmaster%2Fdeployment-templates%2Fazure%2FNGFWv6.7.0%2Fftdv%2Fazure-ftdv-custom-template.json)

5. Update the parameters in the parameters template file(json) and use it to provide the parameters to the ARM template.

6. Review and purchase the template to deploy Firepower Threat Defense Virtual firewall.

7. Configure the NGFWv <br>
    a. Update the Firepower Threat Defense Virtual’s IP configuration in Azure.<br>
    b. Update the Public IP Address Configuration<br>
    c. Optionally, add a public IP address to a data interface.<br>
    d. Configure the Firepower Threat Defense Virtual for management by a Firepower Management Center.<br>
    e. Update the Azure Security Groups.<br>
    f. Register the Firepower Threat Defense Virtual with the Firepower Management Center.<br>
    g. Enable and configure the two data interfaces.<br>
    h. Configure Device Settings<br>


## Parameters for the Azure ARM template:

### Pre-requisites:
1. Image ID (created using the downloaded vhd)
2. Virtual network with 4 subnets corresponding to management, diagnostic, GigabitEthernet0/0 and GigabitEthernet0/1 respectively.

### Parameters:
1. **vmName**: The name the Firepower Threat Defense Virtual VM will have in Azure.<br>
e.g. cisco-ngfw

2. **vmImageId**: The ID of the image used for deployment. Internally, Azure associates every resource with a Resource ID.<br>
e.g. /subscriptions/f160cf7e-ae69-4e9f-8ad0-b434b9a63755/resourceGroups/blr-virtual-images-rg/providers/Microsoft.Compute/images/cisco-ftdv-67065

3. **adminUsername**: The username for logging into Firepower Threat Defense Virtual. This cannot be the reserved name ‘admin’.<br>
e.g. jdoe

4. **adminPassword**: The admin password. This must be 12 to 72 characters long, and include three of the following: 1 lower case, 1 upper case, 1 number, 1 special character.<br>
e.g. Password@123123

5. **vmStorageAccount**: Your Azure storage account. You can use an existing storage account or create a new one. The storage account name must be between 3 and 24 characters, and can only contain lowercase letters and numbers.<br>
e.g. ciscongfwstorage

6. **customData**: The field to provide Day 0 configuration to the FTDv. By default it has 3 key-value pairs to configure 'admin' user password, the FMCv hostname and whether to use FDM or FMC for management.<br>
'ManageLocally : yes' - will configure the FDM to be used as FTDv manager.<br>
e.g. {"AdminPassword": "FtdvPass@123123", "Hostname": "cisco-fmcv", "ManageLocally": "Yes"}<br>
You can configure the FMCv as FTDv manager and also give the inputs for fields required to configure the same on FTDv.<br>
e.g. {"AdminPassword": "FtdvPass@123123", "Hostname": "cisco-fmcv", "ManageLocally": "No", "FmcIp": "<fmcIp>", "FmcRegKey": "<fmcRegKey>", "FmcNatId": "<fmcNatId>" }<br>

7. **virtualNetworkResourceGroup**: The name of the virtual network's Resource Group. The Firepower Threat Defense Virtual is always deployed into a new Resource Group.<br>
e.g. test-ngfw-rg

8. **virtualNetworkName**: The name of the virtual network.<br>
e.g. test-ngfw-vnet

9. **mgmtSubnetName**: The management interface will attach to this subnet. This maps to Nic0, the first subnet. Note, this must match an existing subnet name if joining an existing network.<br>
e.g. mgmt

10. **mgmtSubnetIP**: The Management interface IP address.<br>
e.g. 10.8.0.55

11. **diagSubnetName**: The diagnostic interface will attach to this subnet. This maps to Nic1, the second subnet. Note, this must match an existing subnet name if joining an existing network.<br>
e.g. diag

12. **diagSubnetIP**: The diagnostic interface IP address.<br>
e.g. 10.8.1.55

13. **data1SubnetName**: The data1 interface will attach to this subnet. This maps to Nic2, the third subnet. Note, this must match an existing subnet name if joining an existing network.<br>
e.g. inside

14. **data1SubnetIP**: The data1 interface IP address. This is for Firepower Threat Defense Virtual’s first data interface.<br>
e.g. 10.8.2.55

15. **data2SubnetName**: The data2 interface will attach to this subnet. This maps to Nic3, the third subnet. Note, this must match an existing subnet name if joining an existing network.<br>
e.g. outside

16. **data2SubnetIP**: The data2 interface IP address. This is for Firepower Threat Defense Virtual’s second data interface.<br>
e.g. 10.8.3.55

17. **vmSize**: The VM size to use for the Firepower Threat Defense Virtual VM. Standard_D3_V2 is the default.<br>
Supported sizes: Standard_D3_V2, Standard_D3, Standard_D4_v2 & Standard_D5_v2<br>
e.g. Standard_D3_V2 or Standard_D3 or Standard_D4_v2 or Standard_D5_v2


## References
* [Software Downloads Home](https://software.cisco.com/download/home/286306503/type/286306337/release/6.7.0)
* [FTDv deployment](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/azure/ftdv-azure-gsg/ftdv-azure-deploy.html#id_82702)
* [FMCv deployment](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/fmcv/fpmc-virtual/fpmc-virtual-azure.html#id_106502)

## Licensing Info
This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../../../LICENSE) file for details.

## Copyright
Copyright (c) 2020 Cisco Systems Inc and/or its affiliates.

## Changelog

### 6.7.0
- Accelerated Networking enabled on data interfaces for 6.7 and above
- API Version changes for Azure resources


