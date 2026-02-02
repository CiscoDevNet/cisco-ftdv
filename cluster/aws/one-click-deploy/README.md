# NGFWv Multi AZ Dual ARM Deployment One Click Scripts

## Infrastructure Deployment Script (`oneclick_cluster_infra.py`)

A comprehensive tool for managing AWS CloudFormation stacks for network infrastructure.
Supports creation and deletion of stacks with detailed monitoring and error handling.

### Features
- Automated virtual environment setup
- Template validation before deployment
- Real-time stack creation/deletion monitoring
- Detailed error reporting and stack events
- Support for multiple Availability Zones
- Configurable network parameters

### Usage
```bash
python3 oneclick_cluster_infra.py [--mode {create|delete}]
```

### Arguments
| Argument | Description |
|----------|-------------|
| `--mode` | Deployment mode (default: create)<br>`create`: Deploy a new CloudFormation stack<br>`delete`: Remove an existing stack |

### Examples
1. Create a new stack (default behavior):
```bash
python3 oneclick_cluster_infra.py
```

2. Explicitly create a stack:
```bash
python3 oneclick_cluster_infra.py --mode create
```

3. Delete an existing stack:
```bash
python3 oneclick_cluster_infra.py --mode delete
```

### Configuration
The script uses a CONFIG dictionary that must be configured before use:

1. AWS Credentials:
```python
CONFIG['aws_credentials'] = {
    'aws_access_key_id': 'YOUR_ACCESS_KEY',
    'aws_secret_access_key': 'YOUR_SECRET_KEY',
    'region_name': 'us-east-2'
}
```

2. Stack Configuration:
```python
CONFIG['stack_config'] = {
    'stack_name': 'your-stack-name',
    'template_path': 'path/to/template.yaml'
}
```

3. Network Parameters:
- VPC CIDR
- Management subnet configurations
- Inside/Outside subnet configurations
- CCL subnet configurations
- Lambda subnet configurations

### Requirements
- Python 3.6+
- AWS credentials with CloudFormation permissions
- Valid CloudFormation template
- Internet connection for AWS API access
- Sufficient AWS service quotas

### Environment Setup
The script automatically:
1. Creates a virtual environment
2. Installs required packages (boto3)
3. Configures AWS session

## Deployment Script (`oneclick_cluster_deploy.py`)

This script automates the deployment and deletion of AWS CloudFormation stacks
for Network Gateway Firewall (NGFW) infrastructure. It supports creating
infrastructure with management, inside, outside, and CCL subnets. <br>

MAKE SURE TO COPY 'cluster_layer.zip' TO 'lambda-python-files' DIRECTORY BEFORE DEPLOYMENT!<br>
ADD NAT EIP TO FMCV SECURITY GROUP FOR LAMBDA ACCESS! <br>
ADD FMCV IP TO NGFWV SECURITY GROUP FOR FMCV ACCESS!<br>

### Features
- Creates/deletes CloudFormation stacks
- Handles virtual environment setup
- Validates templates before deployment
- Monitors stack creation/deletion progress
- Displays stack outputs upon successful creation

### Usage
```bash
python3 oneclick_cluster_deploy.py [--mode {create|delete}]
```

### Arguments
| Argument | Description |
|----------|-------------|
| `--mode` | Deployment mode (default: create)<br>`create`: Deploy a new stack<br>`delete`: Remove an existing stack |

### Examples
```bash
# Create a new stack (default behavior)
python3 oneclick_cluster_deploy.py

# Explicitly create a stack
python3 oneclick_cluster_deploy.py --mode create

# Delete an existing stack
python3 oneclick_cluster_deploy.py --mode delete
```

### Configuration
Update the CONFIG dictionary in this file to modify:
- AWS credentials and region
- Stack name and template path
- NGFW cluster parameters
- Network configuration (VPC, subnets)

### Requirements
- Python 3.6+
- AWS credentials with appropriate permissions
- boto3 (installed automatically in virtual environment)
- Valid CloudFormation template at specified template_path