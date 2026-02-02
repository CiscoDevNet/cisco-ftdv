# Clustering Autoscale for the Threat Defense Virtual in GCP Cloud

Clustering enables you to group multiple Threat Defense Virtual (FTDv) devices into a single logical unit. This provides the convenience of managing a single device while achieving increased throughput and redundancy from multiple devices. Our updated solution now supports autoscaling, which ensures optimal performance and resource utilization based on demand fluctuations.

> **NOTE:** Starting with version 7.4.1, you can deploy FTDv clusters without the Diagnostic interface (Outside, Inside, Management, CCL).  
> To use this capability, set the `with_diagnostic` variable to `False` in your cluster deployment parameters.

## Deployment Flow

### Prerequisites
- Terraform (version 1.7.0 or newer)
- Google Cloud SDK installed locally or access to GCP Cloud Shell
- Service account with appropriate permissions for resource creation

### Deployment Option 1: Using GCP Infrastructure Manager

Execute the following CLI command to deploy using GCP Infrastructure Manager:

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

**Note:** Sample `tfvars` files are available in each respective directory for reference.

### Deployment Option 2: Using Local Terraform

#### Step 1: Configure Authentication

Set up your credentials using one of these methods:

```sh
# Option A: Login with your user account
gcloud auth application-default login  

# Option B: Use a service account key
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"  
```

#### Step 2: Deploy Infrastructure

**Note:** You can either use our infrastructure template to create VPC, subnets, and firewall rules, or provide your existing resource names directly in the cluster deployment.

Configure and deploy the infrastructure:

```bash
# 1. Edit infrastructure parameters
cd FTDV/infrastructure
# Modify infrastructure_params.tfvars with your settings

# 2. Deploy infrastructure
terraform init
terraform apply -var-file=infrastructure_params.tfvars
```

#### Step 3: Create Required Secrets

For FTDv deployments, create Secret Manager secrets for your passwords:

```bash
# Create FTDv password secret
gcloud secrets create ftdv-password --replication-policy="automatic"
echo -n "your-ftdv-password" | gcloud secrets versions add ftdv-password --data-file=-

# Create FMC password secret
gcloud secrets create fmc-password --replication-policy="automatic"
echo -n "your-fmc-password" | gcloud secrets versions add fmc-password --data-file=-
```

#### Step 4: Deploy the Cluster

Configure and deploy your cluster:

```bash
cd FTDV/cluster_deployment
# Modify cluster_params.tfvars with your settings

terraform init
terraform apply -var-file=cluster_params.tfvars
```

### Cleaning Up Resources

To remove all deployed resources:

```bash
# 1. First remove the cluster
cd FTDV/cluster_deployment
terraform destroy -var-file=cluster_params.tfvars

# 2. Then remove the infrastructure
cd FTDV/infrastructure
terraform destroy -var-file=infrastructure_params.tfvars
```

**Note:** Deployments performed via GCP Infrastructure Manager are visible in the GCP console, allowing you to easily list and verify all deployed resources. These can be cleaned up directly from the GCP UI. In contrast, local Terraform deployments must be managed through Terraform state files and will not appear in the Infrastructure Manager section of the GCP console.