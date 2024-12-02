variable "rg_name" {
  type = string
}
variable "location" {
  type    = string
  default = "West Europe"
}
variable "ngfw_name" {
  type = string
}
variable "ngfw_version" {
  type    = string
  default = "latest"
}
variable "ngfw_count" {
  type    = number
  default = 1
}
variable "custom_data" {
  type = map(string)
  default = {
    AdminPassword = "Admin123"
    Hostname      = "FTD"
    FmcIp         = ""
    FmcRegKey     = ""
    FmcNatId      = ""
    ManageLocally = "No"
  }
}
variable update_domain_count {
  type = number
  default = 5
}
variable fault_domain_count {
  type = number
  default = 3
}
variable "vm_size" {
  type    = string
  default = "Standard_D3_v2"
}
variable "vnet" {
  type = map(string)
  default = {
    name  = "vnet01",
    space = "192.168.0.0/16"
  }
}
variable "subnet_0" {
  type = map(string)
  default = {
    name  = "subnet_0",
    space = "192.168.0.0/24"
  }
}
variable "subnet_1" {
  type = map(string)
  default = {
    name  = "subnet_1",
    space = "192.168.1.0/24"
  }
}
variable "subnet_2" {
  type = map(string)
  default = {
    name  = "subnet_2",
    space = "192.168.2.0/24"
  }
}
variable "subnet_3" {
  type = map(string)
  default = {
    name  = "subnet_3",
    space = "192.168.3.0/24"
  }
}
