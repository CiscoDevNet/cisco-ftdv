# Cisco Secure Firewall Threat Defense Virtual (formerly FTDv/NGFWv) 
## TDv Autoscaling

This Repository provides resources to bring up TDv (Threat Defence Virtual) Auto Scale solution.

Some of the key features of the TDv Auto Scale include:

* Complete serverless implementation!
* Completely automated TDv instance registration and de-registration with FMC.
* NAT policy, Access Policy, IP and Routes are automatically applied to scaled-out TDv instance.
* Support for Enabling / Disabling Auto Scaling feature.

## AWS GuardDuty Integration with Cisco Secure Firewall
This solution make use of the threat analysis data/results from Amazon GuardDuty (malicious IPs generating threats, attacks etc.) and feeds that information(malicious IP) to the Cisco Secure Firewall Threat Defense Virtual via the managers: *Cisco Secure Firewall Management Center Virtual* , *Cisco Secure Firewall Device Manager* to protect the underlying network and applications against future threats originating from these sources(malicious IP).

## Cloud Deployment Templates

This provides set of templates for deployment of NGFWv in public clouds.

### Azure Templates

Azure Resource Manager(ARM) templates to deploy Cisco's NGFWv/FTDv and FMCv in Azure public cloud using custom image.

**Azure Resource Manager Templates**<br>
Azure Resource Manager templates are JSON files that contain resource descriptions and parameter definitions.
* Template file: This is the main resources file that deploys all the components within the resource group.
* Parameter file: This file includes the parameters required to successfully deploy the FTDv.

### Openstack Templates

This conatains heat template files to deploy the Secure Firewall Threat Defense Virtual (TDv) and Secure Firewall Management Center Virtual (MCv) on OpenStack environment.

## Resources

### FTDv Autoscale

* On Azure for NGFWv6.7.0 & Above: [Code](autoscale/azure/)     |     [README](autoscale/azure/README.md)     |     [Deployment/Configuration Guide](autoscale/azure/ftdv-azure-autoscale-v67.pdf)

* On AWS for NGFWv6.7.0 & Above: [Code](autoscale/aws/)     |     [README](autoscale/aws/README.md)     |     [Deployment/Configuration Guide](autoscale/aws/deploy-ftdv-auto-scale-for-aws.pdf)

* On OCI for NGFWv7.1.0 & Above: [Code](autoscale/oci/)     |     [README](autoscale/oci/README.md)     |     [Deployment/Configuration Guide](autoscale/oci/deploy_autoscale_tdv_oci.pdf)
* On GCP for CSF7.2.0 & Above: [Code](autoscale/gcp/)     |     [README](autoscale/gcp/README.md)     |     [Deployment/Configuration Guide](autoscale/gcp/deploy-tdv-auto-scale-for-gcp.pdf)

### Cloud Service Integration    

* AWS Guardduty: [Code](cloud-service-integration/aws/guardduty/)     |     [README](cloud-service-integration/aws/guardduty/README.md)     |     [Deployment/Configuration Guide](cloud-service-integration/aws/guardduty/Cisco_NGFWv_AWS_GuardDuty_Integration_User_Configuration_Guide.pdf)


### Deployment Template
* Azure NGFWv Deployment Template: [README](deployment-templates/azure/README.md) | [NFWv/FTDv](deployment-templates/azure/NGFWv6.6.0/ftdv/README.md)  |   [FMCv](deployment-templates/azure/NGFWv6.6.0/fmcv/README.md)
* Openstack NGFWv Heat Deployment Template: [README](deployment-templates/openstack/README.md) | [NFWv/FTDv](deployment-templates/openstack/FTDv/README.md)  |   [FMCv](deployment-templates/openstack/FMCv/README.md)


***Archived***
* FTDv Auto Scaling for Azure for NGFWv6.6.0 : [Code](archive/autoscale/azure/NGFWv6.6.0/)     |     [README](autoscale/azure/NGFWv6.6.0/README.md)     |     [Deployment/Configuration Guide](autoscale/azure/NGFWv6.6.0/deploy-ftdv-auto-scale-for-azure.pdf)
* FTDv Auto Scaling for AWS for NGFWv6.6.0 : [Code](archive/autoscale/aws/NGFWv6.6.0/)     |     [README](autoscale/aws/NGFWv6.6.0/README.md)     |     [Deployment/Configuration Guide](autoscale/aws/NGFWv6.6.0/deploy-ftdv-auto-scale-for-aws.pdf)

