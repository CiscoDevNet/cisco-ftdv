# Cisco Firepower NGFW Virtual (NGFWv) - Azure

## Azure Deployment

In addition to the Marketplace-based deployment, Cisco provides a compressed virtual hard disk (VHD) that you can upload to Azure to simplify the process of deploying the NGFWv/FTDv and FMCv in Azure.<br>
Using a Managed Image and two JSON files (a Template file and a Parameter File), you can deploy and provision all the resources for the Firepower Threat Defense Virtual(FTDv) and Firepower Management Center Virtual(FMCv) in a single, coordinated operation.<br>

To deploy using a VHD image, you must upload the VHD image to your Azure storage account. Then, you can create a managed image using the uploaded disk image.<br>

## Azure Resource Manager Templates
Azure Resource Manager templates are JSON files that contain resource descriptions and parameter definitions.<br>

* **Template File** — This is the main resources file that deploys all the components within the resource group.<br>
* **Parameter File** — This file includes the parameters required to successfully deploy the FTDv. It includes details such<br>
as the subnet information, virtual machine tier and size, username and password for the FTDv, the name of the storage container, etc.<br>
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
* [Software Downloads Home](https://software.cisco.com/download/home/286306503/type/286306337/release/6.7.0)
* [FTDv deployment](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/azure/ftdv-azure-gsg/ftdv-azure-deploy.html#id_82702)
* [FMCv deployment](https://www.cisco.com/c/en/us/td/docs/security/firepower/quick_start/fmcv/fpmc-virtual/fpmc-virtual-azure.html#id_106502)

## Licensing Info
This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../LICENSE) file for details.

## Copyright
Copyright (c) 2020 Cisco Systems Inc and/or its affiliates.

