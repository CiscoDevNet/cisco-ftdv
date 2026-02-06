variable "access_key" {
    type = string
    default = "__access_key__"
}
variable "secret_key" {
    type = string
    default = "__secret_key__"
}
variable "region" {
    type = string
    default = "__region__"
}
variable "prefix" {
    type = string
    default = "__prefix__"
}
variable "vpc_name" {
    type = string
    default = "__vpc_name__"
}
variable "vpc_cidr" {
    type = string
    default = "__vpc_cidr__"
}
variable "mgmt_vswitch_cidr" {
    type = string
    default = "__mgmt_vswitch_cidr__"
}
variable "inside_vswitch_cidr" {
    type = string
    default = "__inside_vswitch_cidr__"
}
variable "outside_vswitch_cidr" {
    type = string
    default = "__outside_vswitch_cidr__"
}
variable "diag_vswitch_cidr" {
    type = string
    default = "__diag_vswitch_cidr__"
}
variable "device_type" {
    type = string
    default = "__device_type__"
}
variable "disable_diag" {
    type = bool
    default = __disable_diag__
}
variable "ipv4_security_group_rules" {
    type = list(string)
    default = __ipv4_security_group_rules__
}

variable "ipv6_security_group_rules" {
    type = list(string)
    default = __ipv6_security_group_rules__
}