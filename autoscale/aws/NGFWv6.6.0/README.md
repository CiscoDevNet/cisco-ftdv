# Cisco NGFWv AutoScale Solution for AWS

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

**Note: Please refer Configuration Guide for detailed explanation**

## Use-case

In this use-case, NGFWv three network interfaces are in use: management, inside and outside.
Inside(Gig0/0) is to be placed in trusted zone same as applications or different. This interface
doesn't require default route to internet. User can change Security Group for these interfaces & ACLs for subnet.
Outside(Gig0/1) is to be placed in un-trusted zone, where default route is set to
internet. Also ports that needs to be opened on External Load Balancer, has to be opened on
security group & ACLs. Management interface needs to be placed in a subnet where FMC connection is possible.
This is like a application front-end, where traffic from un-trusted zone is passed to applications through NGFWv firewall.
These connections flow through NGFWv, however Ingress traffic (inbound connections initiated) to internet/un-trusted zone will not go through NGFWv.
Please refer Configuration guide where use-case is briefly explained.

## Solution-design
In this solution, <br>
Resources are to be deployed using CloudFormation stack, Lambda functions are used to
handle automation of initial tasks of bringing NGFWv up, registering, deploying configuration on it.

There are by default 2 Lambda functions,
1. AutoScale group <br>
    This lambda is responsible for adding additional 3 interfaces, attaching/detaching Gig0/1 to/from Target Groups of specified
    CloudFormation ports opened on LB input.
        * If Un-healthy alarm for one of TG goes to ALARM state,
        * Check if there are any un-healthy IPs in Target groups. If there are any then if corresponding instance is an NGFWv which is running for more than an hour
          then delete the instance & AWS will launch new instance to re-fill it.
          If instance is running for less than an hour, then ignore it.
          If IP address belongs to any other instance or not from any instance, then de-register IP address
2. AutoScale Manager lambda <br>
    This lambda is responsible for below tasks:<br>
    *   When a new NGFWv VMs launches & becomes reachable via SSH: Register, Configure & Deploy them in FMC
    *   When a existing NGFWv terminates: De-register in FMC

There are optional Lambda functions, <br>
ScaleIn, cron-ScaleIn, ScaleOut & cron-ScaleOut Lambda functions. <br>
    These Lambda functions will increase or decrease desired_no of instance on AutoScale Group. Providing control on scale-in & scale-out.

Scaling Policies can be created based on CPU either using AWS Dynamic Scaling or Custom Scaling (using above 4 optional Lambdas)

## Steps-to-deploy

1. Download/Clone this repository

1. Create Device-Group, Objects, Security-Zones, Access-Policy, NAT-Policy in FMC
    * Dedicated FMC user for AutoScale Operations (Registration, Configuration & Deployment)
        * User with Network Admin & Maintenance privilege
    * Device Group for instances from AutoScale Group in AWS
    * Host Objects for AWS MetaData server 169.254.169.254 & application IPs
    * Network objects if required for static routes
    * Port objects for LB health-probe & application ports
    * Access Policy allowing health-probe port connections to Metadata server & other configurations
    * NAT Policy, doing manual NAT for LB health probes to AWS Metadata service
1. Update Configuration.json file in autoscale_manager directory
    * Update FMC registration requirements (FMC IP, Reg ID, NAT Id)
    * Access Policy & NAT policy names (Note: These are already existing, won't be created new )
    * Update interface configuration with security-zone, interface-name & mtu etc
    * Update static route with required routes
1. Using utility.py file in top directory, to build & produce lambda functions zip files

    ```bash
    $ python utility.py --create-zip-file true \
    > --upload-file true --s3-bucket shridhar-autoscale-lambda
    ```

    Output looks similar like below:

    ```bash
    $ python utility.py --create-zip-file true --upload-file true --s3-bucket shridhar-autoscale-lambda


    ---------------------- Removing .zip File if exists locally ----------------------
    Executing Command: rm ./autoscale_manager.zip ./autoscale_grp.zip ./scale_functions.zip
    rm: ./autoscale_manager.zip: No such file or directory
    rm: ./autoscale_grp.zip: No such file or directory
    rm: ./scale_functions.zip: No such file or directory


    ------------------------- Creating autoscale_manager.zip -------------------------
    Executing Command:
    cd autoscale_manager/ ; pwd  ; zip -r ../autoscale_manager.zip aws.py __init__.py manager.py constant.py fmc.py utility.py ngfw.py Configuration.json
    /Users/shrshanb/Documents/Work/AutoScale/AWS/Code/aws_ngfw_autoscale-1.8/autoscale_manager
      adding: aws.py (deflated 78%)
      adding: __init__.py (stored 0%)
      adding: manager.py (deflated 83%)
      adding: constant.py (deflated 41%)
      adding: fmc.py (deflated 84%)
      adding: utility.py (deflated 76%)
      adding: ngfw.py (deflated 80%)
      adding: Configuration.json (deflated 63%)


    --------------------------- Creating autoscale_grp.zip ---------------------------
    Executing Command:
    cd autoscale_grp/ ; pwd  ; zip -r ../autoscale_grp.zip autoscale_grp.py constant.py utility.py __init__.py aws_methods.py
    /Users/shrshanb/Documents/Work/AutoScale/AWS/Code/aws_ngfw_autoscale-1.8/autoscale_grp
      adding: autoscale_grp.py (deflated 79%)
      adding: constant.py (deflated 35%)
      adding: utility.py (deflated 70%)
      adding: __init__.py (stored 0%)
      adding: aws_methods.py (deflated 82%)


    -------------------------- Creating scale_functions.zip --------------------------
    Executing Command:
    cd scale_functions/ ; pwd  ; zip -r ../scale_functions.zip scaleout.py scalein.py constant.py aws_methods.py scaleout_cron.py scalein_cron.py
    /Users/shrshanb/Documents/Work/AutoScale/AWS/Code/aws_ngfw_autoscale-1.8/scale_functions
      adding: scaleout.py (deflated 63%)
      adding: scalein.py (deflated 64%)
      adding: constant.py (deflated 87%)
      adding: aws_methods.py (deflated 81%)
      adding: scaleout_cron.py (deflated 61%)
      adding: scalein_cron.py (deflated 60%)


    ------------------------- Deleting files if exists in S3 -------------------------


    ----------------------------- Uploading .zip files -------------------------------


    ------------------------------ Uploading .yaml files -----------------------------
    https://shridhar-autoscale-lambda.s3.amazonaws.com/asm.yaml
    https://shridhar-autoscale-lambda.s3.amazonaws.com/asg.yaml
    https://shridhar-autoscale-lambda.s3.amazonaws.com/deploy.yaml


    --------------------------- Removing .zip Files locally -------------------------
    Delete local zip files ?[y/n]: y
    Executing Command: rm ./autoscale_manager.zip ./autoscale_grp.zip ./scale_functions.zip

    $

    ```

1. Collect AutoScale Stack parameters list (AWS, FMC & NGFWv details)
1. Deploy deploy.yaml CloudFormation template
1. Modify resources & configurations on AWS Dashboard & FMC GUI as needed

## Licensing Info

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](../../../LICENSE) file for details.
