# lambda-python-files
 
## cluster_layer.zip
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

The resultant `cluster_layer.zip` file should be copied to the `lambda-python-files` folder.

## Lambda Main files 
### lifecycle_ftdv.py 

This python file contains lamda_handler for lifecycle-lambda function. 

### manager.py

This python file contains lamda_handler for Cluster manager lambda function.

## Library Files 

### aws.py 
This file contains classes for various AWS services. <br>

### fmc.py
This file contains class for FMC Communications(RESTapi/requests) <br>

### ngfw.py
This file contains classes for NGFW methods & SSH connectivity(Paramiko) <br>

## Other files
### constant.py 
This file contains all the constants used in python functions. 

### utility.py
This file contains static python methods used in other python files

### Configuration.json 
This file is used by manager.py/Cluster manager lambda function, which has FMC related information. <br>
