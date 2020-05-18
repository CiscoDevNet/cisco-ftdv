# Automated Horizontal Scaling of FTDv in Azure

## Feature Overview

FTDv Auto Scale solution is a complete serverless implementation which makes use of serverless
infrastructure provided by Azure (Logic App, Azure Functions, Load Balancers, Virtual Machine Scale Set.. etc.)

Some of the key features of the FTDv Auto Scale for Azure implementation include:
*	Completely automated FTDv instance registration and de-registration with FMC
*	NAT policy, Access Policy, IP and Routes are automatically applied to scaled-out FTDv instance
*	Support for Standard Load Balancers
*	Supports FTDv deployment in Multi-availability zones
*	Support for Enabling / Disabling Auto Scaling feature
*	Azure Resource Manager (ARM) template based deployment 
*	Support to deploy FTDv with PAYG or BYOL licensing mode 
   (Note: PAYG is applicable only for FTDv software version 6.5 and onwards)


## Deployment

ARM template is used to deploy resources required by FTDv Auto Scale feature in Azure

*  ARM template will deploy serverless components (Virtual Machine Scale Set, Load Balancers, Function App, Logic App etc)
*  Function App is responsible to trigger Scale-In / Scale-Out operations, Register/De-Register FTDv with FMC and Configuration of FTDv
   (Note: User needs to build Function App from the source code using Visual Studio)
*  Logic App acts as an Orchestrator to sequence the operation

Please refer Deployment Guide for detailed instructions on how to Build, Deploy, Configure and Manage Auto Scale solution. 
Also please refer Deployment Guide to understand the known limitations of this feature.

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../../LICENSE) file for details
