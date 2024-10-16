# Cisco Secure Firewall Threat Defense Virtual (formerly FTDv/NGFWv) 
## Threat Defense Virtual Autoscaling

This Repository provides resources to bring up CSFTDv (Threat Defence Virtual) Auto Scale solution.

Some of the key features of the CSFTDv Auto Scale include:

* Complete serverless implementation!
* Completely automated CSFTDv instance registration and de-registration with FMC.
* NAT policy, Access Policy, IP and Routes are automatically applied to scaled-out CSFTDv instance.
* Support for Enabling / Disabling Auto Scaling feature.

### Resources

* On Azure for CSFTDv6.7.0 & Above: [Code](autoscale/azure/)     |     [README](autoscale/azure/README.md)     |     [Deployment/Configuration Guide](autoscale/azure/ftdv-azure-autoscale.pdf)

* On AWS for CSFTDv6.7.0 & Above: [Code](autoscale/aws/)     |     [README](autoscale/aws/README.md)     |     [Deployment/Configuration Guide](autoscale/aws/deploy-ftdv-auto-scale-for-aws.pdf)

* On OCI for CSFTDv7.1.0 & Above: [Code](autoscale/oci/)     |     [README](autoscale/oci/README.md)     |     [Deployment/Configuration Guide](autoscale/oci/deploy_autoscale_tdv_oci.pdf)

* On GCP for CSFTDv7.2.0 & Above: [Code](autoscale/gcp/)     |     [README](autoscale/gcp/README.md)     |     [Deployment/Configuration Guide](autoscale/gcp/deploy-tdv-auto-scale-for-gcp.pdf)

## Threat Defense Virtual Cluster
* Clustering lets you group multiple threat defense units together as a single logical device. 
* A cluster provides all the convenience of a single device (management, integration into a network) while achieving the increased throughput and redundancy of multiple devices.

### Resources

* On GCP for CSFTDv7.2.0 and above: [Code](cluster/gcp/)     |     [README](cluster/gcp/README.md)         |     [Deployment/Configuration Guide](cluster/gcp/ftdv-cluster-public.pdf)

* On AWS for CSFTDv7.2.0 and above: [Code](cluster/aws/)     |     [README](cluster/aws/README.md)     |     [Deployment/Configuration Guide](cluster/aws/ftdv-cluster-public.pdf)

* On Azure for CSFTDv7.3.0 and above: [Code](cluster/azure/)     |     [README](cluster/azure/README.md)         |     [Deployment/Configuration Guide](cluster/azure/ftdv-cluster-public.pdf)

## AWS GuardDuty Integration with Cisco Secure Firewall
This solution make use of the threat analysis data/results from Amazon GuardDuty (malicious IPs generating threats, attacks etc.) and feeds that information(malicious IP) to the Cisco Secure Firewall Threat Defense Virtual via the managers: *Cisco Secure Firewall Management Center Virtual* , *Cisco Secure Firewall Device Manager* to protect the underlying network and applications against future threats originating from these sources(malicious IP).

### Resources
* AWS Guardduty: [Code](cloud-service-integration/aws/guardduty/)     |     [README](cloud-service-integration/aws/guardduty/README.md)     |     [Deployment/Configuration Guide](cloud-service-integration/aws/guardduty/CSFTDv_AWS_GuardDuty_Integration_User_Configuration_Guide.pdf)

## Cloud Deployment Templates

This provides set of templates for deployment of CSFTDv in public clouds.

### Azure Templates

Azure Resource Manager(ARM) templates to deploy CSFTDv and CSFMCv in Azure public cloud using custom image.

**Azure Resource Manager Templates**<br>
Azure Resource Manager templates are JSON files that contain resource descriptions and parameter definitions.
* Template file: This is the main resources file that deploys all the components within the resource group.
* Parameter file: This file includes the parameters required to successfully deploy the CSFTDv.

#### Resources
* Azure CSFTDv Deployment Template: [README](deployment-templates/azure/README.md) | [CSFTDv](deployment-templates/azure/CiscoSecureFirewallVirtual-7.4.1/csf-tdv/README.md)  |   [CSFMCv](deployment-templates/azure/CiscoSecureFirewallVirtual-7.4.1/csf-mcv/README.md)

### Openstack Templates

This conatains heat template files to deploy the Secure Firewall Threat Defense Virtual (TDv) and Secure Firewall Management Center Virtual (MCv) on OpenStack environment.

#### Resources
* Openstack CSFTDv Heat Deployment Template: [README](deployment-templates/openstack/README.md) | [CSFTDv](deployment-templates/openstack/FTDv/README.md)  |   [CSFMCv](deployment-templates/openstack/FMCv/README.md)


### ***Archived***
* FTDv Auto Scaling for Azure for CSFTDv6.6.0 : [Code](archive/autoscale/azure/NGFWv6.6.0/)     |     [README](autoscale/azure/NGFWv6.6.0/README.md)     |     [Deployment/Configuration Guide](autoscale/azure/NGFWv6.6.0/deploy-ftdv-auto-scale-for-azure.pdf)
* FTDv Auto Scaling for AWS for CSFTDv6.6.0 : [Code](archive/autoscale/aws/NGFWv6.6.0/)     |     [README](autoscale/aws/NGFWv6.6.0/README.md)     |     [Deployment/Configuration Guide](autoscale/aws/NGFWv6.6.0/deploy-ftdv-auto-scale-for-aws.pdf)
