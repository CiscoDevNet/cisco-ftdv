# Cisco Secure Firewall - Azure

## Azure Deployment

In addition to the Marketplace-based deployment, Cisco provides a compressed virtual hard disk (VHD) that you can upload to Azure to simplify the process of deploying the CSFTDv and CSFMCv in Azure.<br>
Using a Managed Image and two JSON files (a Template file and a Parameter File), you can deploy and provision all the resources for the Cisco Secure Firewall Threat Defense Virtual(CSFTDv) and Cisco Secure Firewall Management Center Virtual(CSFMCv) in a single, coordinated operation.<br>

To deploy using a VHD image, you must upload the VHD image to your Azure storage account. Then, you can create a managed image using the uploaded disk image.<br>

## Azure Resource Manager Templates
Azure Resource Manager templates are JSON files that contain resource descriptions and parameter definitions.<br>

* **Template File** — This is the main resources file that deploys all the components within the resource group.<br>
* **Parameter File** — This file includes the parameters required to successfully deploy the CSFTDv. It includes details such<br>
as the subnet information, virtual machine tier and size, username and password for the CSFTDv, the name of the storage container, etc.<br>
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
* [Software Downloads Home - Secure Firewall Threat Defense Virtual](https://software.cisco.com/download/home/286306503/type/286306337/release/7.2.0)
* [Software Downloads Home - Secure Firewall Management Center Virtual](https://software.cisco.com/download/home/286259687/type/286271056/release/7.2.0)
* [CSFTDv deployment](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/azure/ftdv-azure-gsg/ftdv-azure-deploy.html#id_82702)
* [CSFMCv deployment](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/fmcv/fpmc-virtual/fpmc-virtual-azure.html#id_106502)

## Licensing Info
This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../LICENSE) file for details.

## Copyright
Copyright (c) 2022 Cisco Systems Inc and/or its affiliates.
