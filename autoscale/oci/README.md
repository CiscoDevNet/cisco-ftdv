# Cisco Threat Defence Virtual (TDv) AutoScale Solution for OCI

Cisco provides CloudFormation Templates and scripts for deploying an auto-scaling tier of TDv firewalls
using several OCI services, including Oracle Functions, instance pools, Loadbalancer, Oralce Notification Service, and Alarms.
TDv Auto Scale in OCI is a complete serverless implementation (i.e. no helper VMs involved in the
automation of this feature) that adds horizontal auto scaling capability to TDv instances in the OCI
environment.<br>

The TDv Auto Scale solution is a terraform template-based deployment that provides:

* Completely automated TDv instance registration and de-registration with the MC.
* NAT policy, Access Policy, and Routes automatically applied to scaled-out TDv instances.
* Support for Load Balancers
* Works only with MC; the Firepower Device Manager is not supported.

*Disclaimer: It is required to have prior understanding of OCI deployments & resources*


## Use-case

In this use-case, TDv four network interfaces are in use: management, diagnostic, inside and outside. Inside(Gig0/0) is to be placed in trusted zone same as applications or different. This interface doesn't require default route to internet. User can change Network Security Group for these interfaces for the subnet. Outside(Gig0/1) is to be placed in un-trusted zone, where default route is set to internet. Also ports that needs to be opened on External Load Balancer, has to be opened on the network security groups. Management interface needs to be placed in a subnet where FMC connection is possible. This is like a application front-end, where traffic from un-trusted zone is passed to applications through TDv firewall. These connections flow through TDv, however Ingress traffic (inbound connections initiated) to internet/un-trusted zone will not go through TDv. Please refer Configuration guide where use-case is briefly explained.

## Steps-to-deploy

Please refer Configuration Guide for detailed explanation

## Licensing Info

This project is licensed under the Apache License, Version 2.0 - see the License file for details.
