# Cisco Secure Firewall - Azure

## Azure Deployment

In addition to the Marketplace-based deployment, Cisco provides a compressed virtual hard disk (VHD) that you can upload to Azure to simplify the process of deploying the CSF-TDv and CSF-MCv in Azure.<br>
Using a Image and two JSON files (a Template file and a Parameter File), you can deploy and provision all the resources for the Cisco Secure Firewall Threat Defense Virtual (CSF-TDv) and Cisco Secure Firewall Management Center Virtual (CSF-MCv) in a single, coordinated operation.<br>

To deploy using a VHD image, you must upload the VHD image to your Azure storage account. Then, you can create a image using the uploaded disk image and an Azure Resource Manager template.<br>
Azure templates are JSON files that contain resource descriptions and parameter definitions.

Use the instructions in the quick start guides for CSF-TDv and CSF-MCv deployment.<br>

[Azure CSF-TDv quick start guide](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/consolidated_ftdv_gsg/threat-defense-virtual-10-0-gsg/m-ftdv-azure-gsg.html)

[Azure CSF-MCv quick start guide](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/fmcv/fpmc-virtual/fpmc-virtual-azure.html)

## Azure Resource Manager Templates
Azure Resource Manager templates are JSON files that contain resource descriptions and parameter definitions.<br>

* **Template File** — This is the main resources file that deploys all the components within the resource group.<br>
* **Parameter File** — This file includes the parameters required to successfully deploy the CSF-TDv/CSF-MCv. It includes details such as the subnet information, virtual machine tier and size, username and password, the name of the storage container, etc.<br>
You can customize this file for your Azure deployment environment.<br>

*Example: Azure Resource Manager JSON Template File*
```
{
    "$schema": "",
    "contentVersion": "",
    "parameters": {  },
    "variables": {  },
    "resources": [  ],
    "outputs": {  }
}
```

## References
* [Software Downloads Home - Secure Firewall Threat Defense Virtual](https://software.cisco.com/download/home/286306503/type/286306337/release/10.0.0)
* [Software Downloads Home - Secure Firewall Management Center Virtual](https://software.cisco.com/download/home/286259687/type/286271056/release/10.0.0)
* [CSF-TDv deployment](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/consolidated_ftdv_gsg/threat-defense-virtual-10-0-gsg/m-ftdv-azure-gsg.html)
* [CSF-MCv deployment](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/fmcv/fpmc-virtual/fpmc-virtual-azure.html)

## Licensing Info
This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../LICENSE) file for details.

## Copyright
Copyright (c) 2026 Cisco Systems Inc and/or its affiliates.
