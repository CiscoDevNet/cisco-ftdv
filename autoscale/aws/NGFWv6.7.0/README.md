# Cisco NGFWv AutoScale Solution for AWS - Phase 2

Cisco provides CloudFormation Templates and scripts for deploying an auto-scaling tier of NGFWv firewalls
using several AWS services, including Lambda, auto scaling groups, Elastic Load Balancing (ELB), Amazon
S3 Buckets, SNS, and CloudWatch.
NGFWv Auto Scale in AWS is a complete serverless implementation (i.e. no helper VMs involved in the
automation of this feature) that adds horizontal auto scaling capability to NGFWv instances in the AWS
environment.<br>

The NGFWv Auto Scale solution is a CloudFormation template-based deployment that provides:

* Completely automated NGFWv instance registration and de-registration with the FMC.
* NAT policy, Access Policy, and Routes automatically applied to scaled-out NGFWv instances.
* Support for Load Balancers and multi-availability zones.
* Support for enabling and disabling the Auto Scale feature.
* Works only with FMC; the Firepower Device Manager is not supported.

*Disclaimer: It is required to have prior understanding of AWS deployments & resources*

**Note: Please refer [Configuration Guide](./deploy-ftdv-auto-scale-for-aws.pdf) for detailed explanation**

## Use-case

Use case remains same as previous release.

## Enhancements

*	Public IP requirement made optional for NGFWv Management interface
*	Lambda Functions are placed in VPC (Allowing user to make secured inbound-connection rule for FMC & NGFWv)
*	Lambda Layer created by CloudFormation stack itself (User still has to create zip file)
*	Enabling AutoScale Manager Lambda to do FMC validation
*	Usage Launch Template for AutoScale group instead of Launch Configuration
*	All Target Groups under External-LB can be updated with Gig0/1 interface IP(Allowing user to have more than one ports on LB)
*	Provided Infrastructure template ( From scratch deployment )
*	Added Custom Metric Publisher Lambda for NGFWv memory publish from FMC ( python serverless function & AWS Scheduled Event)
*	Migrated all constants to constant.py file
*	Made it easier to deploy ( removed nested stack concept )
*	Removed custom scaling ( no exceptional value addition as of now )
*	Separate Thresholds for CPU & Memory provided
*	Optionally can choose CPU only, Memory only or Both for scaling
*	Avoided too many emails to User (Introduce a new SNS topic only for User publication )
*	Tags gets created for EC2 instance & AutoScale group with current status

## Solution-design-modifications
In this solution, <br>
Resources are to be deployed using CloudFormation stack, Lambda functions are used to
handle automation of initial tasks of bringing NGFWv up, registering, deploying configuration on it.

There are by default 2 Lambda functions and 1 conditional Lambda  function,
1. AutoScale group/Life Cycle Lambda <br>
    This lambda is responsible for adding additional 3 interfaces, attaching/detaching Gig0/1 to/from Target Groups of specified
    CloudFormation ports opened on LB input.
    *   Health doctor module is moved to Manager lambda to gain oprational ease.

2. AutoScale Manager Lambda <br>
    This lambda is responsible for below tasks:<br>
    *   When a new NGFWv VMs launches & becomes reachable via SSH: Register, Configure & Deploy them in FMC
    *   When a existing NGFWv terminates: De-register in FMC
    *   Health Doctor module is added to this Lambda, also it is modified to receive hourly trigger instead of un-healthy events.
        Reason to make it as cron/scheduled job is to enable Lambda function to check FMC availability as well.
        * Checks if there are any un-healthy IPs in Target groups. If there are any then if corresponding instance is an NGFWv which is running for more than an hour
          then delete the instance & AWS will launch new instance to re-fill it.
          If instance is running for less than an hour, then ignore it.
          If IP address belongs to any other instance or not from any instance, then de-register IP address

3. Custom Metric Publisher Lambda <br>
    This lambda is responsible for publishing custom metrics from FMC to CloudWatch Metrics. <br>
    *   This lambda resource gets created only if User wants to have memory metric for scaling.
    *   It collects Memory metric(REST get method) from FMC for devices present in both AWS & FMC,
    *   Publishes them on CloudWatch Metric. In case there no devices found from AWS group, it DISABLEs Scheduled event, it automatically gets
    ENABLE when an instance is launched.

As Custom Scaling option is removed to make solution simple,
Optional Lambda functions: ScaleIn, cron-ScaleIn, ScaleOut & cron-ScaleOut Lambda functions are not available anymore. <br>
Scaling Policies can be created based on CPU and/or memory using AWS Dynamic Scaling only.

## Steps-to-deploy

Please refer [Configuration Guide](./deploy-ftdv-auto-scale-for-aws.pdf) for detailed explanation

## Licensing Info

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../../LICENSE) file for details.
