variable "resourceNamePrefix" {
  type = string
  default = "ngfwvcls"
}

variable "insideIpCidrRange" {
  type = string
  default = "10.10.53.0/24"
}

variable "outsideIpCidrRange" {
  type = string
  default = "10.10.54.0/24"
}

variable "mgmtIpCidrRange" {
  type = string
  default = "10.10.51.0/24"
}

variable "mgmtVPCConnectorIpCidrRange" {
  type = string
  default = "10.10.0.0/28"
}

variable "diagIpCidrRange" {
  type = string
  default = "10.10.52.0/24"  
}

variable "cclIpCidrRange" {
  type = string
  default = "10.10.55.0/24"
}

variable "region" {
  type = string
  default = "us-central1"
}

variable "zone" {
  type = string
  default = "us-central1-c"
}

variable "project_id" {
  type = string
  default = "asavgcp-poc-4krn"
}




