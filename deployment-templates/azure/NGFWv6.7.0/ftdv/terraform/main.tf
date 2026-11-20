# TODO
# conditional for availablity zone 
# conditional for public ip, availabilit set/zone

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "rg" {
  name     = var.rg_name
  location = var.location
}

resource "azurerm_virtual_network" "vnet" {
  name                = var.vnet.name
  address_space       = [var.vnet.space]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "subnet_0" {
  name                 = var.subnet_0.name
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = [var.subnet_0.prefix]
}
resource "azurerm_network_security_group" "subnet_0" {
  name                = "${var.subnet_0.name}-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  security_rule {
    name                       = "allow-ssh"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "TCP"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
resource "azurerm_subnet_network_security_group_association" "subnet_0" {
  subnet_id                 = azurerm_subnet.subnet_0.id
  network_security_group_id = azurerm_network_security_group.subnet_0.id
}
resource "azurerm_subnet" "subnet_1" {
  name                 = var.subnet_1.name
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = [var.subnet_1.prefix]
}
resource "azurerm_network_security_group" "subnet_1" {
  name                = "${var.subnet_1.name}-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name


}
resource "azurerm_subnet_network_security_group_association" "subnet_1" {
  subnet_id                 = azurerm_subnet.subnet_1.id
  network_security_group_id = azurerm_network_security_group.subnet_1.id
}
resource "azurerm_subnet" "subnet_2" {
  name                 = var.subnet_2.name
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = [var.subnet_2.prefix]
}
resource "azurerm_network_security_group" "subnet_2" {
  name                = "${var.subnet_2.name}-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  security_rule {
    name                       = "allow-any"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
resource "azurerm_subnet_network_security_group_association" "subnet_2" {
  subnet_id                 = azurerm_subnet.subnet_2.id
  network_security_group_id = azurerm_network_security_group.subnet_2.id
}
resource "azurerm_subnet" "subnet_3" {
  name                 = var.subnet_3.name
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = [var.subnet_3.prefix]
}
resource "azurerm_network_security_group" "subnet_3" {
  name                = "${var.subnet_3.name}-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  security_rule {
    name                       = "allow-any"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
resource "azurerm_subnet_network_security_group_association" "subnet_3" {
  subnet_id                 = azurerm_subnet.subnet_3.id
  network_security_group_id = azurerm_network_security_group.subnet_3.id
}
resource "azurerm_public_ip" "ngfw_pip" {
  name                = "${var.ngfw_name}-pip"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  domain_name_label   = "${var.ngfw_name}-pip"
  sku                 = "Standard"
  allocation_method   = "Static"
}

resource "azurerm_network_interface" "nic0" {
  name                 = "${var.ngfw_name}-nic-0"
  location             = azurerm_resource_group.rg.location
  resource_group_name  = azurerm_resource_group.rg.name
  enable_ip_forwarding = true

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet_0.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.ngfw_pip.id
  }
}
resource "azurerm_network_interface" "nic1" {
  name                 = "${var.ngfw_name}-nic-1"
  location             = azurerm_resource_group.rg.location
  resource_group_name  = azurerm_resource_group.rg.name
  enable_ip_forwarding = true

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet_1.id
    private_ip_address_allocation = "Dynamic"
  }
}
resource "azurerm_network_interface" "nic2" {
  name                          = "${var.ngfw_name}-nic-2"
  location                      = azurerm_resource_group.rg.location
  resource_group_name           = azurerm_resource_group.rg.name
  enable_ip_forwarding          = true
  enable_accelerated_networking = true

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet_2.id
    private_ip_address_allocation = "Dynamic"
  }
}
resource "azurerm_network_interface" "nic3" {
  name                          = "${var.ngfw_name}-nic-3"
  location                      = azurerm_resource_group.rg.location
  resource_group_name           = azurerm_resource_group.rg.name
  enable_ip_forwarding          = true
  enable_accelerated_networking = true

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet_3.id
    private_ip_address_allocation = "Dynamic"
  }
}
resource "azurerm_availability_set" "avset" {
  name                = "${var.ngfw_name}-aset"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  platform_update_domain_count = var.update_domain_count
  platform_fault_domain_count = var.fault_domain_count
}

resource "azurerm_linux_virtual_machine" "ngfw" {
  name                            = var.ngfw_name
  resource_group_name             = azurerm_resource_group.rg.name
  location                        = azurerm_resource_group.rg.location
  size                            = var.vm_size
  admin_username                  = "adminuser"
  admin_password                  = "iDCMzxcGSVScGFya$3eH"
  disable_password_authentication = false # needed for admin access to ngfw clish
  availability_set_id             = azurerm_availability_set.avset.id
  network_interface_ids = [
    azurerm_network_interface.nic0.id,
    azurerm_network_interface.nic1.id,
    azurerm_network_interface.nic2.id,
    azurerm_network_interface.nic3.id
  ]


  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  plan {
    name      = "ftdv-azure-byol"
    product   = "cisco-ftdv"
    publisher = "cisco"
  }

  source_image_reference {
    publisher = "cisco"
    offer     = "cisco-ftdv"
    sku       = "ftdv-azure-byol"
    version   = var.ngfw_version
  }

  custom_data = base64encode("{\"AdminPassword\": \"${var.custom_data.AdminPassword}\",\"Hostname\": \"${var.custom_data.Hostname}\",\"FmcIp\": \"${var.custom_data.FmcIp}\",\"FmcRegKey\":\"${var.custom_data.FmcRegKey}\",\"FmcNatId\":\"${var.custom_data.FmcNatId}\",\"ManageLocally\":\"${var.custom_data.ManageLocally}\"}")
}

output "instance_ips" {
  value = azurerm_public_ip.ngfw_pip.fqdn
}
