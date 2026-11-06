terraform {
  required_version = "= 1.13.4"

  required_providers {
    ibm = {
      source  = "IBM-Cloud/ibm"
      version = "2.4.0"
    }
  }
}
