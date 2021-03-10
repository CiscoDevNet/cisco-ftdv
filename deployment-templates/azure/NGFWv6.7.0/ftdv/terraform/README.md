# Azure NGFWv deployment using Terraform
simple terraform template to deploy 1 FTDv in Azure into an availability set


## desc
terraform will crate 1 ngfw instance, 1 vnet, 4 subnets, 4 network security groups, 1 availability set and 1 public ip adress for management

## usage

initialize terraform\
`terraform init`\
create ressources\
`terraform apply`\
delete ressources\
`terraform destroy`\
