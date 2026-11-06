# A null override leaves authentication to the provider's environment/runtime.
# Keep the explicit override for existing callers; never hard-code credentials.
provider "ibm" {
  ibmcloud_api_key = var.ibmcloud_api_key
  region           = var.region
}
