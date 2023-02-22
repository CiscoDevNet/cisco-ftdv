# Azure Cisco Secure Firewall Threat Defense Virtual (CSF-TDv) deployment using VHD and ARM template

In addition to the Marketplace-based deployment, Cisco provides a compressed virtual hard disk (VHD) that you can upload to Azure to simplify the process of deploying the CSF-TDv in Azure. <br>
Using a Image and two JSON files (a Template file and a Parameter File), you can deploy and provision all the resources for the CSF-TDv in a single, coordinated operation.

To deploy using a VHD image, you must upload the VHD image to your Azure storage account. Then, you can create a image using the uploaded disk image and an Azure Resource Manager template.<br>
Azure templates are JSON files that contain resource descriptions and parameter definitions.

Use the instructions in the quick start guide for CSF-TDv deployment.<br>

[Azure CSF-TDv quick start guide](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/consolidated_ftdv_gsg/threat-defense-virtual-73-gsg/m-ftdv-azure-gsg.html)


## Deployment overview

1. Download the CSF-TDv vhd image from Cisco Download Software download page.<br>
e.g. 7.3.0-44 CSF-TDv image can be downloaded from:<br>
URL  : https://software.cisco.com/download/home/286306503/type/286306337/release/7.3.0 <br>
File : [ CSF-TDv v7.3.0 on Azure ] : Cisco_Firepower_Threat_Defense_Virtual-7.3.0-69.vhd.bz2<br>

2. Create a linux VM in Azure, un-compress the *.bz2 & upload the VHD image to container in Azure storage account.

3. Create a Image from the VHD and acquire the Resource ID of the newly created Image.

4. Use the ARM template to deploy a Firepower Threat Defense Virtual firewall using the image.

5. Update the parameters in the parameters template file(json) and use it to provide the parameters to the ARM template.

6. Review and purchase the template to deploy Firepower Threat Defense Virtual firewall.

7. Configure the CSF-TDv <br>
    a. Update the CSF-TDv IP configuration in Azure.<br>
    b. Update the Public IP Address Configuration<br>
    c. Optionally, add a public IP address to a data interface.<br>
    d. Configure the CSF-TDv for management by a CSF-MCv.<br>
    e. Update the Azure Security Groups.<br>
    f. Register the CSF-TDv with the CSF-MCv.<br>
    g. Enable and configure the two data interfaces.<br>
    h. Configure Device Settings<br>

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCiscoDevNet%2Fcisco-ftdv%2Fmaster%2Fdeployment-templates%2Fazure%2FCiscoSecureFirewallVirtual-7.2.0%2Fftdv%2Fazure-ftdv-custom-template.json)

## Parameters for the Azure ARM template:

### Pre-requisites:
1. Image ID (created using the downloaded vhd)
2. Virtual network with 4 subnets corresponding to management, diagnostic, GigabitEthernet0/0 and GigabitEthernet0/1 respectively.

### Parameters:
1. **vmName**: Name the CSF-TDv VM in Azure.<br>
e.g. cisco-tdv

2. **vmImageId**: The ID of the image used for deployment. Internally, Azure associates every resource with a Resource ID.<br>
e.g. /subscriptions/<subscription-id>/resourceGroups/blr-virtual-images-rg/providers/Microsoft.Compute/images/cisco-tdv-72082

3. **adminUsername**: The username for logging into CSF-TDv. This cannot be the reserved name ‘admin’.<br>
e.g. jdoe

4. **adminPassword**: The admin password. This must be 12 to 72 characters long, and include three of the following: 1 lower case, 1 upper case, 1 number, 1 special character.<br>
e.g. Password@2023

5. **vmStorageAccount**: Your Azure storage account. You can use an existing storage account or create a new one. The storage account name must be between 3 and 24 characters, and can only contain lowercase letters and numbers.<br>
e.g. ciscotdvstorage

6. **availabilityZone**: Specify the availability zone for deployment, Public IP and the virtual machine will be created in the specified availability zone.<br>
Set it to '0' if you do not need availability zone configuration. Ensure that selected region supports availability zones and value provided is correct.
(This must be an integer between 0-3).<br>
e.g. 0

7. **customData**: The field to provide Day 0 configuration to the CSF-TDv. By default it has 3 key-value pairs to configure 'admin' user password, the CSF-MCv hostname and whether to use CSF-MCv or CSF-DM for management.<br>
'ManageLocally : yes' - will configure the CSF-DM to be used as CSF-TDv manager.<br>
e.g. {"AdminPassword": "Password@2023", "Hostname": "cisco", "ManageLocally": "Yes"}<br>
You can configure the CSF-MCv as CSF-TDv manager and also give the inputs for fields required to configure the same on CSF-MCv.<br>
e.g. {"AdminPassword": "Password@2023", "Hostname": "cisco", "ManageLocally": "No", "FmcIp": "<fmcIp>", "FmcRegKey": "<fmcRegKey>", "FmcNatId": "<fmcNatId>" }<br>

8. **virtualNetworkResourceGroup**: The name of the virtual network's Resource Group. The CSF-TDv is always deployed into a new Resource Group.<br>
e.g. test-tdv-rg

9. **virtualNetworkName**: The name of the virtual network.<br>
e.g. test-tdv-vnet

10. **mgmtSubnetName**: The management interface will attach to this subnet. This maps to Nic0, the first subnet. Note, this must match an existing subnet name if joining an existing network.<br>
e.g. mgmt

11. **mgmtSubnetIP**: The Management interface IP address.<br>
e.g. 10.8.0.55

12. **diagSubnetName**: The diagnostic interface will attach to this subnet. This maps to Nic1, the second subnet. Note, this must match an existing subnet name if joining an existing network.<br>
e.g. diag

13. **diagSubnetIP**: The diagnostic interface IP address.<br>
e.g. 10.8.1.55

14. **data1SubnetName**: The data1 interface will attach to this subnet. This maps to Nic2, the third subnet. Note, this must match an existing subnet name if joining an existing network.<br>
e.g. inside

15. **data1SubnetIP**: The data1 interface IP address. This is for CSF-TDv first data interface.<br>
e.g. 10.8.2.55

16. **data2SubnetName**: The data2 interface will attach to this subnet. This maps to Nic3, the third subnet. Note, this must match an existing subnet name if joining an existing network.<br>
e.g. outside

17. **data2SubnetIP**: The data2 interface IP address. This is for CSF- TDv second data interface.<br>
e.g. 10.8.3.55

18. **vmSize**: The VM size to use for the CSF-TDv VM. Standard_D3_V2 is the default.<br>
e.g. Standard_D4_v2 <br>
Supported sizes: <br>
  * Standard_D3_V2
  * Standard_D3
  * Standard_D4_v2
  * Standard_D5_v2
  * Standard_D8s_v3#
  * Standard_D16s_v3#
  * Standard_F8s_v2#
  * Standard_F16s_v2#
    '#' : requires ASAv version 7.1 or above.

19. **location**: This shouldn't be changed and should always be set to the below value.<br>
resourceGroup().location

20. **baseStorageURI**: This is used to fetch the storage account and should always be set to the below value.<br>
.blob.core.windows.net

## References
* [Software Downloads Home - CSF-TDv](https://software.cisco.com/download/home/286306503/type/286306337/release/7.3.0)
* [CSF-TDv deployment](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/consolidated_ftdv_gsg/threat-defense-virtual-73-gsg/m-ftdv-azure-gsg.html#id_82702)
* [CSF-MCv deployment](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/fmcv/fpmc-virtual/fpmc-virtual-azure.html#id_106502)

## Licensing Info
This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../../../LICENSE) file for details.

## Copyright
Copyright (c) 2022 Cisco Systems Inc and/or its affiliates.

## Changelog
### 7.3.0
- API version updates for Azure resources

### 7.1.0
- Changes to support new VM sizes (for 7.1 and above): Standard_D8s_v3, Standard_D16s_v3, Standard_F8s_v2, Standard_F16s_v2
- API Version changes for Azure resources

### 7.0.0
- Changes to support deployment selected in Availability Zones

### 6.7.0
- Accelerated Networking enabled on data interfaces for 6.7 and above
- API Version changes for Azure resources
