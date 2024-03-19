locals {
  networks_default = [{
    name = "${var.resourceNamePrefix}-ftdv-inside-vpc",
    subnet = [{
      subnet_name = "${var.resourceNamePrefix}-ftdv-inside-subnet"
      subnet_ip = var.insideIpCidrRange
      subnet_region = var.region
    }]
    protocol = "tcp"
    ports = ["80","443","22"]
  },
  {
    name = "${var.resourceNamePrefix}-ftdv-outside-vpc",
    subnet = [{
      subnet_name = "${var.resourceNamePrefix}-ftdv-outside-subnet"
      subnet_ip = var.outsideIpCidrRange
      subnet_region = var.region
    }]
    protocol = "tcp"
    ports = ["80","443","22"]
  }, {
    name = "${var.resourceNamePrefix}-ftdv-mgmt-vpc",
    subnet = [{
      subnet_name = "${var.resourceNamePrefix}-ftdv-mgmt-subnet"
      subnet_ip = var.mgmtIpCidrRange
      subnet_region = var.region
    },{
      subnet_name = "${var.resourceNamePrefix}-ftdv-mgmt-vpcsubnt"
      subnet_ip = var.mgmtVPCConnectorIpCidrRange
      subnet_region = var.region
    }]
    protocol = "tcp"
    ports = ["22", "443", "8305"]
  },{
    name = "${var.resourceNamePrefix}-ftdv-ccl-vpc"
    subnet = [{
      subnet_name = "${var.resourceNamePrefix}-ftdv-ccl-subnet"
      subnet_ip = var.cclIpCidrRange
      subnet_region = var.region
    }]
    protocol = "all"
    ports = []
  }]

  network_diagonistic = [{
    name = "${var.resourceNamePrefix}-ftdv-diag-vpc"
    subnet = [{
      subnet_name = "${var.resourceNamePrefix}-ftdv-diag-subnet"
      subnet_ip = var.diagIpCidrRange
      subnet_region = var.region
    }]
    protocol = "tcp"
    ports = ["22", "8305"]
  }]
}

locals {
  networks =  var.withDiagnostic ? concat(local.networks_default, local.network_diagonistic) : local.networks_default
}

locals {
    networks_list = { for x in local.networks: "${x.name}" => x}
}
