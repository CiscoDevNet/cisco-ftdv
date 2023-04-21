# One Click scripts

## System requirements

The one-click deploy/delete scripts can be run in any Windows/Linux/MacOS machine that has python3 installed

## Prerequisites

For one-click-deployment, the below files should be kept in a single directory<br>
    (1) zip files: cluster_layer.zip, cluster_lifecycle.zip, cluster_manager.zip<br>
    (2) yaml files:  infrastructure.yaml, deploy_ngfw_cluster_auto.yaml<br>
    (3) deployment script: aws_one_click_deploy.py<br>

The one-click delete script does not have any prerequisites other than the system requirements mentioned above.

## aws_one_click_deploy.py

This script is intended to automate the two-step manual deployment process to a single-click deployment.
It will install the boto3 and cfn_flip packages to a virtual environment if not already present in the machine.
It performs the deployment of the infrastructure stack, uploads the zip files to the s3 bucket created by the infrastructure stack and then deploys the NGFWv cluster stack.
Resources created by the infrastructure stack are auto-detected and utilised for the NGFWv cluster stack, saving the job of manually choosing them.

## Parameters in aws_one_click_deploy.py

For a truly one-click deployment, set all the required parameters to valid values in the beginning of the script.

  1. AWS_SESSION_PARAMS are required to initiate an AWS session; if unset or invalid, user is prompted for input during execution until correct set of credentials are provided.
  2. DEPLOYMENT_MODE parameter is to be set to '1' for deploying only cluster stack over existing infrastructure. For this, an infrastructure stack with the same PRIME_INFRA_PARAMS as ones being used need to already exist (previously been deployed by the one-click script). When doing a fresh deployment, always set this to anything other than '1'.
  3. PRIME_INFRA_PARAMS determine the nature of the stack. An infrastructure stack deployed with use_gwlb='y' can only support cluster deployments with use_gwlb='y'. Therefore, when deploying only cluster stack with deployment_mode='1', an infrastructure stack must have been deployed previously with the same PRIME_INFRA_PARAMS.
  4. INFRASTRUCTURE_STACK_PARAMS_FOR_POD_CONFIGURATION are the parameters for infrastructure stack. The script prompts for user input during execution when any of these parameters are unassigned, but the user has to ensure they are valid.
  5. NGFWV_CLUSTER_STACK_PARAMS are the parameters for NGFWv stack.<br>
      (i) Parameters email_for_notif and kms_arn will be ignored if left empty.<br>
      (ii) Parameter deploy_gwlbe is ignored if not using gateway load balancer (controlled by use_gwlb).<br>
      (iii) Parameters gwlbe_vpc, gwlbe_subnet and health_port are ignored if not using gateway load balancer or the endpoint (controlled by use_gwlb and deploy_gwlbe).<br>
      (iv) Parameter ngfwv_instance_type is ignored if not using gateway load balancer (controlled by use_gwlb), in which case it will be force set to c5.4xlarge.<br>
    All other parameters are required.
    For any parameter that is not ignored, user will be prompted for input if it is unassigned.
    However, user has to ensure they are valid.

## aws_one_click_delete.py

This script is intended to automate the manual delete process to a single-click delete.
It will install the boto3 package to a virtual environment if not already present in the machine.
It provides various delete options as described in the below section.

## Parameters in aws_one_click_delete.py

1. AWS_SESSION_PARAMS are required to initiate an AWS session; if unset or invalid, user is prompted for input during execution until correct set of credentials are provided.

2. The STACK_PARAMS are used to set the names of NGFWv-cluster and infrastructure stacks to be deleted and the control_delete parameter is used to choose what all to delete:<br>
  (i) When control_delete is set to '1', only the NGFWv-cluster stack is deleted, and the 'infra_stack_name' parameter is ignored. Manual deployment of NGFWv-cluster stack can be done later, over existing infrastructure.<br>
  (ii) When control_delete is set to '2', the NGFWv-cluster stack is deleted, and the s3 bucket holding the lambda zips is emptied. A fresh upload of the required zips can done later manually, followed by a manual deployment of NGFWv-cluster stack, over the existing infrastructure.<br>
  (iii) When control_delete is set to 3, both the stacks (including the s3 bucket) are deleted.<br>
  (iv) When control_delete is set to 4, the script deletes all that is mentioned in (iii). In addition to this, any virtual environment created by the one-click scripts is also removed from the machine.
