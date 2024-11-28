#  Templates

## Infrastructure template 

User should update/modify YAML based CloudFormation template(infrastructure_gwlb.yaml) as per requirements. <br />

Please go through Resource section of YAML for all the resources to be deployed. <br/>

* During deletion of the stack it may fail as to not able to delete various resources <br/>
    1. S3 bucket - If objects present then it will fail to delete the S3 bucket.
    1. Security Groups - Sometime it fails as other resources might be using the same.
    1. Lambda subnets - It is observed that lambda interfaces take more time to be deleted by AWS 
       hence its subnets fail to delete immediately
 
 ## NGFW Autoscale template
 
User should update/modify YAML based CloudFormation template(deploy_ngfw_autoscale_with_gwlb.yaml ) as per requirements. <br />

Please go through Resource section of YAML for all the resources to be deployed. <br/>

Avoid modifying "Name" property of any resources, any new resources to be created follow the similar patterns. <br>
Reason: Resources Name is fed to other resources as parameters or os.env  <br>

Various parameters are kept default & is not being explicitly asked on stack parameter inputs.<br>
Those can be modified in the template itself, but user should have clear understanding of resources and usage. <br>

Deployment type "DUAL_ARM" is supported Release 7.6 onwards

