# Cisco NGFWv Autoscale Solution for GCP

* The FTDv Auto Scale for GCP is an automated horizontal scaling solution that positions an FTDv instance group sandwiched between a GCP Internal load balancer (ILB) and a GCP
  External load balancer (ELB).
* The ELB distributes traffic from the Internet to FTDv instances in the instance group; the FTDv then forwards traffic to the application.
* The ILB distributes outbound Internet traffic from an application to FTDv instances in the instance group; the FTDv then forwards traffic to the Internet.
* A network packet will never pass through both (internal & external) load balancers in a single connection.
* The number of FTDv instances in the scale set will be scaled and configured automatically based on load conditions.

***Note: Cloud Editor commands can be run directly from the terminal if Gcloud SDK is installed.***

## Use-case

In this use-case, TDv four network interfaces are in use: management, diagnostic, inside and outside. Inside(Gig0/0) is to be placed in trusted zone same as applications or different. This interface doesn't require default route to internet. User can change Network Security Group for these interfaces for the subnet. Outside(Gig0/1) is to be placed in un-trusted zone, where default route is set to internet. Also ports that needs to be opened on External Load Balancer, has to be opened on the network security groups. Management interface needs to be placed in a subnet where FMC connection is possible. This is like a application front-end, where traffic from un-trusted zone is passed to applications through TDv firewall. These connections flow through NGFWv, however Ingress traffic (inbound connections initiated) to internet/un-trusted zone will not go through TDv. Please refer Configuration guide where use-case is briefly explained.

*Disclaimer: It is required to have prior understanding of GCP deployments & resources*

## Basic Steps:

* Create 4 VPCs and Subnets for Inside, Outside, Management and Diag and in the Management VPC we need to have /28 subnet say 10.8.2.0/28
* We need 4 firewall rules for the interfaces Inside, Outside, Management and Diag, and a Firewall rule to allow the health check probes. 

* Ips for health checks:
	* 35.191.0.0/16
	* 130.211.0.0/22
	* 209.85.152.0/22
	* 209.85.204.0/22
* Create the VPC Connector gcloud beta compute networks vpc-access connectors create --region --subnet=</28 subnet name>
* Clone the git repository to the Local Folder git clone git_url -b branch_name
* Create the bucket in gcloud CLI gsutil mb -c nearline gs://bucket_name
* In main.py file in scaleout_action folder we can choice of internal_ip or external_ip to use for the login into FTDv using the google functions.
* Make the Zip Files of the following files of the Folders (scalein_action and scaleout_action) 
	* main.py
	* basic_functions.py 
	* requirements.txt 
* Rename them to ftdv_scaleout.zip and ftdv_scalein.zip and upload the zips to the storage bucket. Note: Make sure you just compress the files and not the folder.
* Upload the following files from Deployment-Manager-Template to Cloud Editor Workspace 
	* ftdv_template.jinja 
	* ftdv_parameters.yaml 
	* ftdv_predeployment.jinja 
	* ftdv_predeployment.yaml
* Update the Parameters in jinja and yaml files for the Pre-Deployment and FTDv Autoscale Deployment.
* In ftdv_template.jinja there is choice for user to use External IP for Management Interface.
	* Search for and fill a suitable value. The recommended value or type is commented in the same line. 
	* In scaleout_functions/main.py, use the ssh_ip based on whether the FTDv has private or public IP.
* Create 2 secrets fmc-password and ftdv-new-password using Secret Manager GUI Link: https://console.cloud.google.com/security/secret-manager

## FMCv Setup

* Deploy an FMCv on any public cloud platform with a public IP.
* Create a user “restapi” for FMCv and use the same password saved in fmc-password secret.
* Create 
	* Device Group 
	* Access Policy, Access Rule
	* Objects, Security Zone(Interface Objects)
	* NAT Policy, NAT Rules
* Objects to be created:
	* object network hc1
		subnet 35.191.0.0 255.255.0.0
	* object network metadata
		host 169.254.169.254
	* object network ilb-ip
		host 10.52.1.218
	* object network hc2
		subnet 130.211.0.0 255.255.252.0
	* object network elb-ip
		host 34.85.214.40
	* object network hc3
		subnet 209.85.152.0 255.255.252.0
	* object network hc4
		subnet 209.85.204.0 255.255.252.0
	* object network inside-linux
		host 10.52.1.217
	* object network outside-gateway
		host <>
	* object network inside-gateway
		host <>
* Create two interface objects(security zones):
	* inside-security-zone
	* outside-security-zone

## NAT rules to be deployed:

* nat (inside,outside) source dynamic hc1 interface destination static ilb-ip metadata service SVC_4294968559 SVC_4294968559
* nat (inside,outside) source dynamic hc2 interface destination static ilb-ip metadata service SVC_4294968559 SVC_4294968559
* nat (inside,outside) source dynamic any interface
* nat (outside,inside) source dynamic hc1 interface destination static elb-ip metadata service SVC_4294968559 SVC_4294968559
* nat (outside,inside) source dynamic hc2 interface destination static elb-ip metadata service SVC_4294968559 SVC_4294968559
* nat (outside,inside) source dynamic hc3 interface destination static elb-ip metadata service SVC_4294968559 SVC_4294968559
* nat (outside,inside) source dynamic hc4 interface destination static elb-ip metadata service SVC_4294968559 SVC_4294968559
* nat (outside,inside) source dynamic any interface destination static elb-ip inside-linux

## Deploying Templates
* Deploy the Pre-Deployments cloud deployment-manager deployments create --config ftdv_predeployment.yaml
* Deploy the FTDv Autoscale Template gcloud deployment-manager deployments create --config ftdv_autoscale_params.yaml

## Ensuring Traffic Flow

## Create Route for ILB to forward the packets from inside application to internet
	gcloud beta compute routes create <ilb-route-name> --network=<inside-vpc-name> --priority=1000 --destination-range=0.0.0.0/0 --next-hop-ilb=<ilb-forwarding-rule-name> --next-hop-ilb-region=<region>

## Troubleshooting:
* main.py not found. • Make sure that zip is made only from the files. You can go to Cloud Functions and check the file tree. There should not be any folder.
* Error while deploying Template.
	* Make sure that all the parameter values within “<>” are filled in .jinja and .yaml as well or the deployment by the same name exists already.
	* Iferrors with parameters, use the recommended value.
* Google Function cannot reach FTDv • Make sure that the VPC connector is created and the same name is given in the yaml parameter file
* Traffic blocked: 
	* Check for the Access Policy and Rules. 
	* Check that all the Object IPs are correct.
