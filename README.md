## FTDv Autoscaling

This Repository provides resources to bring up FTDv Auto Scale solution.

Some of the key features of the FTDv Auto Scale include:

* Complete serverless implementation!
* Completely automated FTDv instance registration and de-registration with FMC.
* NAT policy, Access Policy, IP and Routes are automatically applied to scaled-out FTDv instance.
* Support for Enabling / Disabling Auto Scaling feature.


## Cloud Deployment Templates

This provides set of templates for deployment of NGFWv in public clouds.

### Azure Templates

Azure Resource Manager(ARM) templates to deploy Cisco's NGFWv/FTDv and FMCv in Azure public cloud using custom image.

**Azure Resource Manager Templates**<br>
Azure Resource Manager templates are JSON files that contain resource descriptions and parameter definitions.
* Template file: This is the main resources file that deploys all the components within the resource group.
* Parameter file: This file includes the parameters required to successfully deploy the FTDv.

## Resources

* FTDv Auto Scaling for Azure : [Code](autoscale/azure/NGFWv6.6.0/)     |     [README](autoscale/azure/NGFWv6.6.0/README.md)     |     [Deployment/Configuration Guide](autoscale/azure/NGFWv6.6.0/deploy-ftdv-auto-scale-for-azure.pdf)


* FTDv Auto Scaling for AWS [Code](autoscale/aws/NGFWv6.6.0/)     |     [README](autoscale/aws/NGFWv6.6.0/README.md)     |     [Deployment/Configuration Guide](autoscale/aws/NGFWv6.6.0/deploy-ftdv-auto-scale-for-aws.pdf)


* Azure NGFWv Deployment Template: [README](deployment-templates/azure/README.md) | [NFWv/FTDv](deployment-templates/azure/NGFWv6.6.0/ftdv/README.md)  |   [FMCv](deployment-templates/azure/NGFWv6.6.0/fmcv/README.md)
