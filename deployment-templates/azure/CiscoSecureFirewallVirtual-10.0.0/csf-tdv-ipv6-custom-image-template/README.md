# Azure Cisco Secure Firewall Threat Defense Virtual (CSF-TDv) deployment using VHD and ARM template

In addition to the Marketplace-based deployment, Cisco provides a compressed virtual hard disk (VHD) that you can upload to Azure to simplify the process of deploying the CSF-TDv in Azure. <br>
Using a Image and two JSON files (a Template file and a Parameter File), you can deploy and provision all the resources for the CSF-TDv in a single, coordinated operation.

To deploy using a VHD image, you must upload the VHD image to your Azure storage account. Then, you can create a image using the uploaded disk image and an Azure Resource Manager template.<br>
Azure templates are JSON files that contain resource descriptions and parameter definitions.

Use the instructions in the quick start guide for CSF-TDv deployment.<br>

[Azure CSF-TDv quick start guide](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/consolidated_ftdv_gsg/threat-defense-virtual-10-0-gsg/m-ftdv-azure-gsg.html)


## Deployment overview

1. Download the CSF-TDv vhd image from Cisco Download Software download page.<br>
e.g. 10.0.0-140 CSF-TDv image can be downloaded from:<br>
URL  : https://software.cisco.com/download/home/286306503/type/286306337/release/10.0.0 <br>
File : [ CSF-TDv v10.0.0 on Azure ] : Cisco_Secure_Firewall_Threat_Defense_Virtual-10.0.0-140.vhd.bz2<br>

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
    h. Configure Device Settings.<br>

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCiscoDevNet%2Fcisco-ftdv%2Fmaster%2Fdeployment-templates%2Fazure%2FCiscoSecureFirewallVirtual-7.4.1%2Fcsf-tdv-ipv6-custom-image-template%2Fcsf-tdv-ipv6-custom-image-template.json)

## Parameters for the Azure ARM template:

### Pre-requisites:
1. Image ID (created using the downloaded vhd)
2. Virtual network with 4 subnets corresponding to management, Ethernet0/0, Ethernet0/1 and Ethernet0/2 respectively.

### Parameters:
1. **vmName**: Name the CSF-TDv VM in Azure.<br>
e.g. cisco-tdv

2. **vmImageId**: The ID of the image used for deployment. Internally, Azure associates every resource with a Resource ID.<br>
e.g. /subscriptions/{subscription-id}/resourceGroups/blr-virtual-images-rg/providers/Microsoft.Compute/images/cisco-tdv-73044

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

7. **customData**: The field to provide Day 0 configuration to the CSF-TDv. By default it has 5 key-value pairs to configure 'admin' user password, the CSF-TDv hostname, whether to use CSF-MCv or CSF-DM for management, whether to use or not use the Diagnostic interface, and IPv6 mode.<br>
'ManageLocally : yes' - will configure the CSF-DM to be used as CSF-TDv manager.<br>
'Diagnostic : OFF' - configures 3-NIC deployment mode (Ethernet0/0, Ethernet0/1, Ethernet0/2). Remove this to enable 4-NIC mode with diagnostic interface.<br>
e.g. {"AdminPassword": "Password@2023", "Hostname": "cisco", "ManageLocally": "Yes", "Diagnostic": "OFF", "IPv6Mode": "DHCP"}<br>
You can configure the CSF-MCv as CSF-TDv manager and also give the inputs for fields required to configure the same on CSF-MCv.<br>
e.g. {"AdminPassword": "Password@2023", "Hostname": "cisco", "ManageLocally": "No", "Diagnostic": "OFF", "IPv6Mode": "DHCP", "FmcIp": "<fmcIp>", "FmcRegKey": "<fmcRegKey>", "FmcNatId": "<fmcNatId>" }<br>

8. **virtualNetworkNewOrExisting**: This parameters determines whether a new Virtual Network should be created or an existing Virtual Network is to be used.<br>
e.g. new

9. **virtualNetworkResourceGroup**: The name of the virtual network's Resource Group. The CSF-TDv is always deployed into a new Resource Group.<br>
e.g. test-tdv-rg

10. **virtualNetworkName**: The name of the virtual network.<br>
e.g. test-tdv-vnet

11. **virtualNetworkAddressPrefixes**: IPv4 address prefix for the virtual network, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. 10.151.0.0/16

12. **virtualNetworkv6AddressPrefixes**: IPv6 address prefix for the virtual network, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. ace:cab:deca::/48

13. **Subnet1Name**:  Management subnet name.<br>
e.g. mgmt

14. **Subnet1Prefix**: Management subnet IPv4 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. 10.151.1.0/24

15. **Subnet1IPv6Prefix**: Management subnet IPv6 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. ace:cab:deca:1111::/64

16. **subnet1StartAddress**: CSF-TDv IPv4 address on the mgmt interface.<br>
e.g. 10.151.1.4

17. **subnet1v6StartAddress**: CSF-TDv IPv6 address on the mgmt interface.<br>
e.g ace:cab:deca:1111::6

18. **Subnet2Name**: CSF-TDv data1 interface will attach to this subnet (Ethernet0/0 by default when Diagnostic is OFF).<br>
e.g. data1

19. **Subnet2Prefix**: Data1 Subnet IPv4 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. 10.151.2.0/24

20. **Subnet2IPv6Prefix**: Data1 Subnet IPv6 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. ace:cab:deca:2222::/64

21. **subnet2StartAddress**: CSF-TDv IPv4 address on the data1 interface (Ethernet0/0 by default when Diagnostic is OFF).<br>
e.g. 10.151.2.4

22. **subnet2v6StartAddress**: CSF-TDv IPv6 address on the data1 interface (Ethernet0/0 by default when Diagnostic is OFF).<br>
e.g ace:cab:deca:2222::6

23. **Subnet3Name**: CSF-TDv data2 interface will attach to this subnet (Ethernet0/1 by default when Diagnostic is OFF).<br>
e.g. data2

24. **Subnet3Prefix**: CSF-TDv data2 Subnet IPv4 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. 10.151.3.0/24

25. **Subnet3IPv6Prefix**: CSF-TDv data2 Subnet IPv6 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. ace:cab:deca:3333::/64

26. **subnet3StartAddress**: The IPv4 address on the data2 interface (Ethernet0/1 by default when Diagnostic is OFF).<br>
e.g. 10.151.3.4

27. **subnet3v6StartAddress**: The IPv6 address on the data2 interface (Ethernet0/1 by default when Diagnostic is OFF).<br>
e.g ace:cab:deca:3333::6

28. **Subnet4Name**: CSF-TDv data3 interface will attach to this subnet (Ethernet0/2 by default when Diagnostic is OFF).<br>
e.g. data3

29. **Subnet4Prefix**: CSF-TDv data3 Subnet IPv4 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. 10.151.4.0/24

30. **Subnet4IPv6Prefix**: CSF-TDv data3 Subnet IPv6 Prefix, this is required only if 'virtualNetworkNewOrExisting' is set to 'new'.<br>
e.g. ace:cab:deca:4444::/64

31. **subnet4StartAddress**: The IPv4 address on the data3 interface (Ethernet0/2 by default when Diagnostic is OFF).<br>
e.g. 10.151.4.4

32. **subnet4v6StartAddress**: The IPv6 address on the data3 interface (Ethernet0/2 by default when Diagnostic is OFF).<br>
e.g ace:cab:deca:4444::6

33. **vmSize**: The VM size to use for the CSF-TDv VM. Standard_D8s_v3 is the default.<br>
e.g. Standard_D8s_v3 <br>
Supported Gen2 VM sizes for 10.0: <br>
  * Standard_D8s_v3
  * Standard_D16s_v3
  * Standard_F8s_v2
  * Standard_F16s_v2
  * Standard_D8_v4
  * Standard_D16_v4
  * Standard_D8s_v4
  * Standard_D16s_v4
  * Standard_D8_v5
  * Standard_D16_v5
  * Standard_D8s_v5
  * Standard_D16s_v5

34. **location**: This shouldn't be changed and should always be set to the below value.<br>
resourceGroup().location

35. **baseStorageURI**: This is used to fetch the storage account and should always be set to the below value.<br>
.blob.core.windows.net

36. **publicInboundPorts**: Whether public inbound ports are allowed or not.<br>
e.g. None or AllowSelectedPorts

37. **selectedInboundPorts**: Selected public inbound ports to be allowed in network security group.<br>
e.g. ["443", "22", "8305"]

38. **enableSecureBoot**: Enable Secure Boot for the VM (Trusted Launch feature).<br>
e.g. false (default) or true

## References
* [Software Downloads Home - CSF-TDv](https://software.cisco.com/download/home/286306503/type/286306337/release/10.0.0)
* [CSF-TDv deployment](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/consolidated_ftdv_gsg/threat-defense-virtual-10-0-gsg/m-ftdv-azure-gsg.html#deploy_azure_ipv6_vhd-cus-templatetask_gl1_mvw_byb)
* [CSF-MCv deployment](https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/management-center-virtual/management-center-virtual-gsg/fpmc-virtual-azure.html#id_82702)

## Licensing Info
This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../../../LICENSE) file for details.

## Copyright
Copyright (c) 2026 Cisco Systems Inc and/or its affiliates.

## Changelog
### 10.0.0
- Added Trusted Launch support with Secure Boot option (enableSecureBoot parameter)
- Changes to support new gen2 instance types
- API version updates for Azure resources
- Updated to use Ethernet interface naming
- Added 3-NIC support(Diagnostic OFF) as a default configuration

### 7.7.0
- Changes to support new VM sizes
- Added public inbound ports configuration (publicInboundPorts, selectedInboundPorts parameters)

### 7.6.0
- Template updates for Azure resources

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
