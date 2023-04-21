variable "region" {
  type = string
  default = "us-central1"
}

variable "zone" {
  type = string
  default = "us-central1-c"
}

variable "resourceNamePrefix" {
  type = string
  default = "ngfwvcls"
}

variable "function_archieve_object" {
    type = string
    default = "ftdv_cluster_function.zip"
}

variable "deployWithExternalIP" {
    type = string
    default = "False"
}
variable "retryCount" {
  type = string
  default = "16"
}

variable "regID" {
  type = string
  default = "cisco"
}

variable "natID" {
  type = string
  default = "cisco"
}

variable "policyID" {
    type = string
    default = "ftdv-acl-policy"
}

variable "fmcIP" {
  type = string
  default = "34.121.151.170"
}

variable "fmcPassword" {
  type = string
  default = "C15co123!"
}

variable "fmcUsername" {
  type = string
  default = "testuser"
}

variable "ftdvPassword" {
  type = string
  default = "Cisco@123123"
}

variable "licenseCAPS" {
  type = string
  default = "BASE,MALWARE,URLFilter,THREAT"
}

variable "performanceTier" {
  type = string
  default = "FTDv50"
}

variable "vpcConnectorName" {
  type = string
  default = "ngfwvcls-ssh"
}

variable "bucket_name" {
  type = string
  default = "ngfwvclstf-ftdv-cluster-bucket"
}
