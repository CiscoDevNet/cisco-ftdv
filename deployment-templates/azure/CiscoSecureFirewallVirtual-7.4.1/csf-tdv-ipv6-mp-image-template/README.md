# Azure Cisco Secure Firewall Threat Defense Virtual (CSF-TDv) deployment using VHD and ARM template

In addition to the Marketplace-based deployment, Cisco provides ARM templates to deploy CSF-TDv for software version listed in Azure marketplace. <br>
Using a Image and two JSON files (a Template file and a Parameter File), you can deploy and provision all the resources for the CSF-TDv in a single, coordinated operation.

To deploy marketplace offer using ARM template, Update the value for softwareVersion in json file with the offer version you wish to deploy.<br>
Azure templates are JSON files that contain resource descriptions and parameter definitions.

Use the instructions in the quick start guide for CSF-TDv deployment.<br>

[Azure CSF-TDv quick start guide](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/consolidated_ftdv_gsg/threat-defense-virtual-74-gsg/m-ftdv-azure-gsg.html)


## Deployment overview

1. Software Version to deploy.<br>

2. Use the ARM template to deploy a Firepower Threat Defense Virtual firewall.

3. Update the parameters in the parameters template file(json) and use it to provide the parameters to the ARM template.

4. Review and purchase the template to deploy Firepower Threat Defense Virtual firewall.

5. Configure the CSF-TDv <br>
    a. Update the CSF-TDv IP configuration in Azure.<br>
    b. Update the Public IP Address Configuration.<br>
    c. Optionally, add a public IP address to a data interface.<br>
    d. Configure the CSF-TDv for management by a CSF-MCv.<br>
    e. Update the Azure Security Groups.<br>
    f. Register the CSF-TDv with the CSF-MCv.<br>
    g. Enable and configure the two data interfaces.<br>
    h. Configure Device Settings.<br>

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCiscoDevNet%2Fcisco-ftdv%2Fmaster%2Fdeployment-templates%2Fazure%2FCiscoSecureFirewallVirtual-7.4.1%2Fcsf-tdv-ipv6-mp-image-template%2Fcsf-tdv-ipv6-mp-image-template.json)

## Parameters for the Azure ARM template:

### Pre-requisites:
1. Software Version to depoy.
2. Virtual network with 4 subnets corresponding to management, diagnostic, GigabitEthernet0/0 and GigabitEthernet0/1 respectively.

### Parameters:
1. **vmName**: Name the CSF-TDv VM in Azure.<br>
e.g. cisco-tdv

2. **softwareVersion**: The software version text, this is the image version from the VM offer.<br>
e.g. 7.6.0-113

3. **billingType**: Billing type to use BYOL or PAYG. PAYG is supported only for 6.5 and above versions.<br>
e.g. BYOL
 
4. **adminUsername**: The username for logging into CSF-TDv. This cannot be the reserved name ‘admin’.<br>
e.g. jdoe

5. **adminPassword**: The admin password. This must be 12 to 72 characters long, and include three of the following: 1 lower case, 1 upper case, 1 number, 1 special character.<br>
e.g. Password@2023

6. **vmStorageAccount**: Your Azure storage account. You can use an existing storage account or create a new one. The storage account name must be between 3 and 24 characters, and can only contain lowercase letters and numbers.<br>
e.g. ciscotdvstorage

7. **availabilityZone**: Specify the availability zone for deployment, Public IP and the virtual machine will be created in the specified availability zone.<br>
Set it to '0' if you do not need availability zone configuration. Ensure that selected region supports availability zones and value provided is correct.
(This must be an integer between 0-3).<br>
e.g. 0

8. **customData**: The field to provide Day 0 configuration to the CSF-TDv. By default it has 3 key-value pairs to configure 'admin' user password, the CSF-MCv hostname and whether to use CSF-MCv or CSF-DM for management.<br>
'ManageLocally : yes' - will configure the CSF-DM to be used as CSF-TDv manager.<br>
e.g. {"AdminPassword": "Password@2023", "Hostname": "cisco", "ManageLocally": "Yes"}<br>
You can configure the CSF-MCv as CSF-TDv manager and also give the inputs for fields required to configure the same on CSF-MCv.<br>
e.g. {"AdminPassword": "Password@2023", "Hostname": "cisco", "ManageLocally": "No", "FmcIp": "<fmcIp>", "FmcRegKey": "<fmcRegKey>", "FmcNatId": "<fmcNatId>" }<br>

9. **virtualNetworkNewOrExisting**: This parameters determines whether a new Virtual Network should be created or an existing Virtual Network is to be used.<br>
e.g. new

10. **virtualNetworkResourceGroup**: The name of the virtual network's Resource Group. The CSF-TDv is always deployed into a new Resource Group.<br>
e.g. test-tdv-rg

11. **virtualNetworkName**: The name of the virtual network<br>
e.g. test-tdv-vnet

12. **virtualNetworkAddressPrefixes**: IPv4 address prefix for the virtual network, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. 10.151.0.0/16

13. **virtualNetworkv6AddressPrefixes**: IPv6 address prefix for the virtual network, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. ace:cab:deca::/48

14. **Subnet1Name**:  Management subnet name.<br>
e.g. mgmt

15. **Subnet1Prefix**: Management subnet IPv4 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. 10.151.1.0/24

16. **Subnet1IPv6Prefix**: Management subnet IPv6 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. ace:cab:deca:1111::/64

17. **subnet1StartAddress**: CSF-TDv IPv4 address on the mgmt interface.<br>
e.g. 10.151.1.4

18. **subnet1v6StartAddress**: CSF-TDv IPv6 address on the mgmt interface.<br>
e.g ace:cab:deca:1111::6

19. **Subnet2Name**: The CSF-TDv diagnostic0/0 interface will attach to this subnet.<br>
e.g. diag

20. **Subnet2Prefix**: Diag Subnet IPv4 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. 10.151.2.0/24

21. **Subnet2IPv6Prefix**: Diag Subnet IPv6 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. ace:cab:deca:2222::/64

22. **subnet2StartAddress**: CSF-TDv IPv4 address on the diag interface.<br>
e.g. 10.151.2.4

23. **subnet2v6StartAddress**: CSF-TDv IPv6 address on the diag interface.<br>
e.g ace:cab:deca:2222::6

24. **Subnet3Name**: CSF-TDv data1 interface will attach to this subnet.<br>
e.g. inside

25. **Subnet3Prefix**: CSF-TDv data1 Subnet IPv4 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. 10.151.3.0/24

26. **Subnet3IPv6Prefix**: CSF-TDv data1 Subnet IPv6 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. ace:cab:deca:3333::/64

27. **subnet3StartAddress**: The IPv4 address on the data1 interface.<br>
e.g. 10.151.3.4

28. **subnet3v6StartAddress**: The IPv6 address on the data1 interface.<br>
e.g ace:cab:deca:3333::6

29. **Subnet4Name**: The CSF-TDv data2 interface will attach to this subnet.<br>
e.g. outside

30. **Subnet4Prefix**: The CSF-TDv data2 Subnet IPv4 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. 10.151.4.0/24

31. **Subnet4IPv6Prefix**: The CSF-TDv data2 Subnet IPv6 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. ace:cab:deca:4444::/64

32. **subnet4StartAddress**: The IPv4 address on the data2 interface.<br>
e.g. 10.151.4.4

33. **subnet4v6StartAddress**: The IPv6 address on the data2 interface.<br>
e.g ace:cab:deca:4444::6

34. **vmSize**: The VM size to use for the CSF-TDv VM. Standard_D3_V2 is the default.<br>
e.g. Standard_D3_v2 <br>
Supported sizes: <br>
  * Standard_D3
  * Standard_D3_v2
  * Standard_D4_v2
  * Standard_D5_v2
  * Standard_D8s_v3#
  * Standard_D16s_v3#
  * Standard_F8s_v2#
  * Standard_F16s_v2#
    '#' : requires ASAv version 7.1 or above.

34. **location**: This shouldn't be changed and should always be set to the below value.<br>
resourceGroup().location

35. **baseStorageURI**: This is used to fetch the storage account and should always be set to the below value.<br>
.blob.core.windows.net

## References
* [Software Downloads Home - CSF-TDv](https://software.cisco.com/download/home/286306503/type/286306337/release/7.6.0)
* [CSF-TDv deployment](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/consolidated_ftdv_gsg/threat-defense-virtual-74-gsg/m-ftdv-azure-gsg.html#id_82702)
* [CSF-MCv deployment](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/fmcv/fpmc-virtual/fpmc-virtual-azure.html#id_106502)

## Licensing Info
This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../../../LICENSE) file for details.

## Copyright
Copyright (c) 2022 Cisco Systems Inc and/or its affiliates.

## Changelog
### 7.4.1
- API version updates for Azure resources

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
