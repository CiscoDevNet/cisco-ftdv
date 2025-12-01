# Terraform Deployment Guide
This guide provides step-by-step instructions to deploy infrastructure using Terraform with Google Cloud Infrastructure Manager.

## Prerequisites
Ensure the following are installed and configured before proceeding:

1. **Google Cloud SDK**: Install and configure using: `gcloud init `
2. **Terraform**: Install Terraform from [Terraform's official website](https://developer.hashicorp.com/terraform/downloads).
3. **Permissions**: Ensure you have the required IAM roles: 
   * `roles/iam.serviceAccountUser`
   * `roles/resourcemanager.projectIamAdmin`
   * `roles/compute.admin`

4. **Service Account**: Ensure that the service account is created and has necessary permissions.

## Deployment Methods
### 1. Deployment via CLI Command
```sh
gcloud infra-manager deployments \
    apply "projects/YOUR_PROJECT_ID/locations/YOUR_REGION/deployments/YOUR_DEPLOYMENT_NAME" \
    --location="YOUR_REGION" \
    --git-source-repo="<repo name>" \
    --git-source-directory="<infrastructure / cluster_deployment>" \
    --git-source-ref="<branch name>" \
    --service-account="projects/YOUR_PROJECT_ID/serviceAccounts/YOUR_SERVICE_ACCOUNT" \
    --artifacts-gcs-bucket="gs://YOUR_BUCKET_NAME/artifacts" \
    --inputs-file="/path/to/your/infra.tfvars"  
```
**Note:** A sample `tfvars` file can be found in the respective directory.

### 2. Deployment via Infrastructure Manager UI
1. Navigate to **Google Cloud Console**.
2. Go to **Infrastructure Manager**.
3. Click **Create Deployment**.
4. Fill in the required details, including:
   * Deployment name
   * Location
   * Source bucket (`gs://YOUR_BUCKET_NAME/gcloud-terraform/infrastructure`)
   * Service account
   * Input variables file

5. Click **Deploy** to start the deployment.

### 3. Deployment via Terraform Locally
#### a) Configure Authentication
Ensure that your credentials are set up:

```sh
gcloud auth application-default login  
```
Alternatively, set the service account key:

```sh
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"  
```
#### b) Initialize Terraform
```sh
terraform init  
```
#### c) Apply Terraform Deployment
```sh
terraform apply -var-file="infra.tfvars"  
```
Confirm with `yes` when prompted.

### Verify Deployment
Check the deployment status:

```sh
gcloud infra-manager deployments describe YOUR_DEPLOYMENT_NAME --location=YOUR_REGION  
```
### Destroy the Deployment (If Needed)
```sh
gcloud infra-manager deployments delete YOUR_DEPLOYMENT_NAME --location=YOUR_REGION  
```
## Troubleshooting
* **Permission Issues**: Verify the IAM roles assigned to the service account.
* **API Enablement**: Ensure required APIs are enabled.
* **State Lock Issues**: If using remote state, ensure the state file is not locked by another process.

## Additional Resources
* [Google Cloud Infrastructure Manager Docs](https://cloud.google.com/infrastructure-manager/docs)
* [Terraform GCP Provider](https://registry.terraform.io/providers/hashicorp/google/latest/docs)