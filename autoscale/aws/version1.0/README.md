# Cisco NGFWv Autoscale Solution deployment on AWS

Cisco NGFWv Autoscale Solution is recommended to be deployed using **deploy.yaml** , this deploys a Nested stack.
<br>

Nested stacks are:<br>
   1. Autoscale Manager stack
   2. Autoscale Group stack


**Note**<br>
In case if Nested stack is not preferred, Autoscale Manager should be deployed first,
this forces user to input Autoscale Group name prior to its deployment.
User has to use the same name while deploying Autoscale Group stack.

## Deployment:

Please refer detailed User Guide: Cisco_NGFWv_AWS_Autoscale_Solution_User_Configuration_guide.docx

### Upload S3 files, YAML, JSON files

Post cloning the repository and modification of Configuration.json, please use below command to create and upload files to S3<br>

```bash
$ python utility.py --create-zip-file true \
> --upload-file true --s3-bucket shridhar-autoscale-lambda
```

Output looks like below:

```bash

(venv2) SHRSHANB-M-N1CG:aws_ngfw_autoscale-1.8 shrshanb$ python utility.py --create-zip-file true --upload-file true --s3-bucket shridhar-autoscale-lambda


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


(venv2) SHRSHANB-M-N1CG:aws_ngfw_autoscale-1.8 shrshanb$

```
