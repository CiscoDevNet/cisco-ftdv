# Clustering for the Threat Defense Virtual in a Public Cloud
Clustering lets you group multiple Threat Defense Virtuals together as a single logical device. A cluster provides
all the convenience of a single device (management, integration into a network) while achieving the increased
throughput and redundancy of multiple devices. You can deploy Threat Defense Virtual clusters in a public
cloud using Amazon Web Services (AWS) or Google Cloud Platform (GCP). Only routed firewall mode is
supported. <br>
From release 7.6 onwards, Cluster deployment in multiple availability zones is supported.

# Prerequisites <br>

## Git Clone repository
Clone the repository 'cisco-ftdv' to your local environment. Navigate to - cisco-ftdv/cluster/aws for the required content

## Update FMCv Configuration
(1) Modify lambda-python-files/Configuration.json <br>
(2) Login to FMCv <br>
(3) Create Access Policy with same name as provided in Configuration.json <br>
(4) Register FMCv to Smart Licensing (highly recommended) <br>
(5) Create 2 API users in FMCv with Administrator permissions <br>
(6) Note FMCv IP, API usernames & passwords <br>
If you are deploying FMCv & FTDv in same subnet then above process should be done after Infra & FMCv deployment <br>

## Create "cluster_layer.zip"
The cluster_layer.zip can be created on an Amazon Linux VM, after installing Python 3.13 on it. We recommend creating an AmazonLinux-2023 EC2 Instance or using AWS Cloudshell, which runs the latest version of Amazon Linux. <br>

**Steps to prepare the environment (if not already done):**
*   Install `git`:
    ```bash
    sudo yum install git -y
    ```
*   Install and initialize `pyenv`:
    ```bash
    curl https://pyenv.run | bash
    echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
    echo '[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
    echo 'eval "$(pyenv init -)"' >> ~/.bashrc
    echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.bashrc
    source ~/.bashrc
    ```
*   Install development tools and libraries required for Python compilation:
    ```bash
    sudo yum groupinstall -y "Development Tools"
    sudo yum install -y gcc openssl-devel bzip2-devel libffi-devel zlib-devel readline-devel sqlite-devel wget make
    ```
*   Install Python 3.13.5 using `pyenv` and set it as global:
    ```bash
    pyenv install 3.13.5
    pyenv global 3.13.5
    pyenv rehash
    ```

**Steps to create `cluster_layer.zip`:**
*   Create and activate a Python 3.13 virtual environment:
    ```bash
    python3.13 -m venv myenv
    source myenv/bin/activate
    ```
*   Create file `requirements.txt` listing the required packages:
    ```
    cat > requirements.txt << EOF
    pycryptodome
    paramiko
    requests
    scp
    jsonschema
    cffi
    zipp
    importlib-metadata
    EOF
    ```
*   Install them using the following command:
    ```bash
    pip3 install --platform manylinux2014_x86_64 --target=./python/lib/python3.13/site-packages --implementation cp --python-version 3.13 --only-binary=:all: --upgrade -r requirements.txt
    ```
*   Copy to`cluster_layer.zip` file:
    ```bash
    zip -r cluster_layer.zip ./python
    ```
*   Deactivate the virtual environment.

(3) Copy the resultant cluster_layer.zip file to the directory 'lambda-python-files' present in the cloned repository. <br>

(4) If you are using private ip for FMCv registration then make sure that you change "USE_PUBLIC_IP_FOR_FMC_CONN" to "False" in ../lambda-python-files/constant.py.

## Create "cluster_manager.zip", "cluster_lifecycle.zip" and "custom_metrics_publisher.zip"
A make.py file can be found in the cloned repository top directory. Running this will Zip the python files into Zip
files and copy to a "target" folder. <br>
In order to do these tasks, the Python3 environment should be available. <br>

Run to create zip files <br>
```bash
python3 make.py build <br>
```

Run to clean (if facing any errors) <br>
```bash
python3 make.py clean <br>
```

All 4 Zip files need to be uploaded to AWS S3 bucket in a further step. <br>

# AWS NGFWv Cluster Deployment Steps <br>
## Deploy "infrastructure.yaml"
Go to "CloudFormation" on AWS Console. <br>
1. Click on "Create stack" and select "With new resources(standard)" <br>
2. Select "Upload a template file", Click on "Choose file" and select "infrastructure.yaml" from target folder. <br>
3. Click on "Next", Read all the Parameter's Label & instructions carefully. Add/Update Template parameters according to your requirement. <br>
4. Click "Next" and "Create stack" <br>
5. Once deployment is complete, go to "Outputs" and note S3 "BucketName". <br>
6. Go to S3, Open S3 bucket which is deployed using infra template. Upload previously-created "cluster_layer.zip, "cluster_manager.zip", "cluster_lifecycle.zip" and "custom_metrics_publisher.zip" to the S3 Bucket <br>
7. Add EIP of Lambda NAT Gateway in FMCv's security group.

## Deploy "deploy_ngfw_cluster.yaml"
Go to "CloudFormation" on AWS Console. <br>
1. Click on "Create stack" and select "With new resources(standard)" <br>
2. Select "Upload a template file", Click on "Choose file" and select "deploy_ngfw_cluster.yaml" from target folder. <br>
3. Click on "Next", Read all the Parameter's Label & instructions carefully. Add/Update/Select Template parameters according to your requirement. <br>
4. Click "Next" and "Create stack" <br>
5. Lambda functions will manage further process and NGFWv devices will be Auto-Registered to FMCv.



