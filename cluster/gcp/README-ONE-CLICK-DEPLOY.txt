######################################################### One Click Deployment #################################################

System requirements: macOS/Linux/Windows machine with
  (1) python3 (and hence pip3) command working
  (2) google cloud SDK installed: gcloud and gsutil commands working
    (can be checked with 'gcloud --version' and 'gsutil --version')
  (3) If the machine is Windows: the contents of cluster-function should
      be compressed to ftdv_cluster_function.zip (donot include the
    cluster-function directory in the zip file - include only its contents)
    and kept in the same directory as this script

GCP side requirements: google cloud SDK is properly configured -
  (1) 'gcould init' has run atleast once before running this script
  (2) project name for the deployment is set as required (can be checked
    by running 'gcloud init')

Single click deployment of Cisco NGFWv Clustering for GCP

DEFAULT DEPLOYMENT mode:

This script deploys all required infrastructure first.
(1) If the fmc_ip is assigned a non-empty string, then that value will be
    used for function deployment, after which cluster is deployed.
  fmc_ip should be assigned a value only if FMC is already deployed, or to be
  deployed with the fixed assigned IP.
  If the user plans to deploy the FMC after infrastructure creation, the
  fmc_ip parameter must be left blank
(2) If fmc_ip is empty (''), user will be given 2 options-
    (a) Leave the script running but waiting until user enters the fmc_ip. In
      this time, FMC can be deployed, after which fmc_ip and any parameter
    left empty in the GOOGLE_FUNCTION_PARAMS and CLUSTER_DEPLOYMENT_PARAMS
    can be entered.
      After this, the script will continue and deploy the funtion and cluster.
  (b) Exit the execution, use CONTROLLED DEPLOYMENT-1 after FMC deployment

CONTROLLED DEPLOYMENT mode:

To override deafault behavior, use parameters in CONTROL_DEPLOYMENT section
(1) in CONTROLLED DEPLOYMENT-1 mode:
  only function and cluster is created using the COMMON_PARAMS,
  GOOGLE_FUNCTION_PARAMS and CLUSTER_DEPLOYMENT_PARAMS
(2) in CONTROLLED DEPLOYMENT-2 mode, only cluster is created using the
  COMMON_PARAMS and CLUSTER_DEPLOYMENT_PARAMS
  see the CONTROL_DEPLOYMENT section parameters for setting the mode

######## Uncomment below lines [58-62] in north-south/deploy_ngfw_cluster.jinja for deploying with public/external IP #######
          #accessConfigs:
          #- kind: compute#accessConfig
            #name: External NAT
            #type: ONE_TO_ONE_NAT
            #networkTier: PREMIUM
################ After uncommenting make sure 'deploy_with_externalIP' set as True in gcp_one_click_deploy.py ###############

After assigning values for parameters, move to the downloaded folder containing the 
gcp_one_click_deploy.py and run

python3 gcp_one_click_deploy.py

and then NGFWV-cluster will be deployed.

#################################################################################################################################
