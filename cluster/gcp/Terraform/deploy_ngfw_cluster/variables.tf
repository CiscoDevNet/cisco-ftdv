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

variable "machineType" {
    type = string
    default = "e2-standard-8"
}

variable "sourceImageURL" {
    type = string
    default = "projects/asavgcp-poc-4krn/global/images/ftdv-7-3-0-44"
  
}

variable "adminPassword" {
  type = string
  default = "Cisco@123123"
}

variable "hostname" {
  type = string
  default = "ciscoftdv"
}

variable "cclSubnetRange" {
  type = string
  default = "10.10.55.2 10.10.55.253"
}

variable "serviceAccountMailId" {
  type = string
  default = "<project-number>-compute@developer.gserviceaccount.com"
}

variable "ftdvTimeoutSec" {
  type = string
  default = 300
}
variable "ftdvCheckIntervalSec" {
  type = string
  default = 300
}

variable "ftdvUnhealthyThreshold" {
  type = string
  default = 4
}

variable "ftdvHealthCheckPort" {
  type = string
  default = "22"
}

variable "ftdvReplicas" {
  type = string
  default = 4
}

variable "cpuUtilizationTarget" {
  type = string
  default = "0.8"
}

variable "ilbProtocol" {
  type = string
  default = "TCP"
}

variable "ilbDrainingTimeoutSec" {
  type = string
  default = "60"
}

variable "project_name" {
  type = string
  default = "asavgcp-poc-4krn"
}
variable "ilbPort" {
  type = string
  default = "80"
}

variable "ilbCheckIntervalSec" {
  type = string
  default = "10"
}

variable "ilbTimeoutSec" {
  type = string
  default = "5"
}

variable "elbTimeoutSec" {
  type = string
  default = "5"
}

variable "ilbUnhealthyThreshold" {
  type = string
  default = "4"
}

variable "elbUnhealthyThreshold" {
  type = string
  default = "4"
}

variable "elbPort" {
  type = string
  default = "80"
  
}

variable "portName" {
  type = string
  default = "tcp"
}

variable "elbProtocol" {
  type = string
  default = "TCP"
}

variable "elbIpProtocol" {
  type = string
  default = "TCP"
}

variable "elbFePorts" {
  type = list(string)
  default = [ "443", "80", "22" ]
}

variable "targetSize" {
  type = string
  default = "1"
}

variable "withDiagnostic" {
  type = bool
  default = true
}

variable "deployUsingExternalIP" {
  type = bool
  default = true
}