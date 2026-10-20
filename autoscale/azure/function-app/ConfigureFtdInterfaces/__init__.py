"""
Copyright (c) 2026 Cisco Systems Inc or its affiliates.

All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
--------------------------------------------------------------------------------

Name:       __init__.py
Purpose:    This python file is used for configuring FTD interfaces in FMC.
"""

import os
import azure.functions as func
import logging as log
from SharedCode.Utils import FMC, getFtdDeviceId, resolveFmcInterfaceForAzureNic

fmc_ip = os.environ.get("FMC_IP")
domain_uuid = os.environ.get("FMC_DOMAIN_UUID")

def main(req: func.HttpRequest):
    fmc = FMC()
    gwlbSupport = os.environ.get("GWLB_SUPPORT")
    log.info("ConfigureFtdInterfaces:::: GWLB Support Value : {}".format(gwlbSupport))
    if gwlbSupport != "YES":
        fmc_inside_zone = os.environ.get("INSIDE_ZONE")
        fmc_inside_nic_name = os.environ.get("INSIDE_NIC_NAME")
        inside_interface_mtu = 1300
        outside_interface_mtu = 1300
    else:
        outside_interface_mtu = 1500

    fmc_outside_zone = os.environ.get("OUTSIDE_ZONE")
    fmc_outside_nic_name = os.environ.get("OUTSIDE_NIC_NAME")
    outside_azure_nic_name = os.environ.get("OUTSIDE_AZURE_NIC_NAME") or "outsideNic"
    inside_azure_nic_name = os.environ.get("INSIDE_AZURE_NIC_NAME") or "insideNic"
    fmc_registration_url = "https://" + fmc_ip + "/api/fmc_config/v1/domain/" + domain_uuid + "/devices/devicerecords/"

    req_body = req.get_json()
    ftdv_name = req_body.get('ftdDevName')
    log.warning("ConfigureFtdInterfaces:::: Started Device Configuration for {}".format(ftdv_name))

    # ------------Get resource Ids------------------------------------------
    log.info("ConfigureFtdInterfaces:::: Getting FTD device ID")
    dev_id = getFtdDeviceId(fmc, req_body)
    if (dev_id == "ERROR"):
        log.error("ConfigureFtdInterfaces:::: Failed to get Device ID")
        return func.HttpResponse("Unable to get Device Group ID",status_code=400)

    if gwlbSupport != "YES":
        log.info("ConfigureFtdInterfaces:::: Resolving Inside NIC from Azure NIC {}".format(inside_azure_nic_name))
        inside_interface = resolveFmcInterfaceForAzureNic(fmc, dev_id, req_body, inside_azure_nic_name, "inside")
        if inside_interface is None:
            log.error("ConfigureFtdInterfaces:::: Failed to map Azure inside NIC to FMC interface")
            return func.HttpResponse("FMC interface inventory is not ready for Azure inside NIC mapping", status_code=503)
        fmc_inside_nic = inside_interface.get("name")
        inside_nic_id = inside_interface.get("id")
        log.info("ConfigureFtdInterfaces:::: Inside NIC {} ID {}".format(fmc_inside_nic, inside_nic_id))

    log.info("ConfigureFtdInterfaces:::: Resolving Outside NIC from Azure NIC {}".format(outside_azure_nic_name))
    outside_interface = resolveFmcInterfaceForAzureNic(fmc, dev_id, req_body, outside_azure_nic_name, "outside")
    if outside_interface is None:
        log.error("ConfigureFtdInterfaces:::: Failed to map Azure outside NIC to FMC interface")
        return func.HttpResponse("FMC interface inventory is not ready for Azure outside NIC mapping", status_code=503)
    fmc_outside_nic = outside_interface.get("name")
    outside_nic_id = outside_interface.get("id")
    log.info("ConfigureFtdInterfaces:::: Outside NIC {} ID {}".format(fmc_outside_nic, outside_nic_id))

    # ------------Get zone Id by name------------------------------------------
    if gwlbSupport != "YES":
        inside_zone_id = fmc.getDevIdByName(fmc_inside_zone, "ZONE")
        if inside_zone_id == "ERROR":
            log.error("ConfigureFtdInterfaces:::: Failed to get inside zone Id")
            return func.HttpResponse("Failed to get Inside Zone Id",status_code=400)

        log.info("ConfigureFtdInterfaces:::: Inside zone ID : {}".format(inside_zone_id))

    outside_zone_id = fmc.getDevIdByName(fmc_outside_zone, "ZONE")
    if outside_zone_id == "ERROR":
        log.error("ConfigureFtdInterfaces:::: Failed to get outside zone Id")
        return func.HttpResponse("Failed to get Outside Zone Id",status_code=400)

    log.info("ConfigureFtdInterfaces:::: Outside zone ID : {}".format(outside_zone_id))

    # -------------------Configure inside interface
    if gwlbSupport != "YES":
        url = fmc_registration_url + dev_id + "/physicalinterfaces/" + inside_nic_id
        put_data = {
            "type": "PhysicalInterface",
            "managementOnly": "false",
            "MTU": inside_interface_mtu,
            "ipv4": {
                "dhcp": {
                    "enableDefaultRouteDHCP": "false",
                    "dhcpRouteMetric": 1
                    }
                },
            "securityZone": {
                "id": inside_zone_id,
                "type": "SecurityZone"
            },
            "mode": "NONE",
            "ifname":fmc_inside_nic_name ,
            "enabled": "true",
            "name": fmc_inside_nic,
            "id": inside_nic_id
        }

        r = fmc.rest_put(url, put_data)

        if not (200 <= r.status_code <= 300):
            log.error("ConfigureFtdInterfaces:::: Failed to configure inside interface")
            log.info("ConfigureFtdInterfaces::::  Configure inside interface status - {}".format(r.content))
            return func.HttpResponse("Failed to configure inside interface", status_code=400)

        log.info("ConfigureFtdInterfaces:::: Successfully configured Inside Interface")

    # -------------------Configure outside interface
    url = fmc_registration_url + dev_id + "/physicalinterfaces/" + outside_nic_id
    put_data = {
        "type": "PhysicalInterface",
        "managementOnly": "false",
        "MTU": outside_interface_mtu,
        "ipv4": {
            "dhcp": {
                "enableDefaultRouteDHCP": "false",
                "dhcpRouteMetric": 1
            }
        },
        "securityZone": {
            "id": outside_zone_id,
            "type": "SecurityZone"
        },
        "mode": "NONE",
        "ifname":fmc_outside_nic_name ,
        "enabled": "true",
        "name": fmc_outside_nic,
        "id": outside_nic_id
    }

    r = fmc.rest_put(url, put_data)

    if not (200 <= r.status_code <= 300):
        log.error("ConfigureFtdInterfaces:::: Failed to configure outside interface")
        log.info("ConfigureFtdInterfaces::::  Configure outside interface status - {}".format(r.content))
        return func.HttpResponse("Failed to configure outside interface",status_code=400)

    # Configuring VTEP and VNI Interfaces
    if gwlbSupport == "YES":
        vxlan_port = int(os.environ.get("VXLAN_ENCAP_PORT_FOR_VTEP"))
        peer_ip = os.environ.get("GWLB_IP_ADDRESS")
        internal_seg_id = int(os.environ.get("TUNNEL_IDENTIFIER_INTERNAL"))
        external_seg_id = int(os.environ.get("TUNNEL_IDENTIFIER_EXTERNAL"))
        internal_port_no = int(os.environ.get("TUNNEL_PORT_INTERNAL"))
        external_port_no = int(os.environ.get("TUNNEL_PORT_EXTERNAL"))

        # Configuring VTEP Interface
        url = "https://" + fmc_ip + "/api/fmc_config/v1/domain/" + domain_uuid + "/devices/devicerecords/" + dev_id + "/vteppolicies"
        existing_vtep = fmc.rest_get(url + "?expanded=true&limit=100").json().get("items", [])
        if existing_vtep:
            log.info("ConfigureFtdInterfaces:::: VTEP policy already exists")
        else:
            put_data = {
                "nveEnable" : True,
                "vtepEntries": [
                    {
                    "sourceInterface" : {
                        "name": fmc_outside_nic,
                        "type": "PhysicalInterface",
                        "id": outside_nic_id
                    },
                    "nveNeighborAddress": {
                        "literal": {
                            "type": "Host",
                            "value": peer_ip
                        }
                    },
                    "nveDestinationPort": vxlan_port,
                    "nveNeighborDiscoveryType": "STATIC_PEER_IP",
                    "nveEncapsulationType": "VXLAN",
                    "nveVtepId": 1
                    }
                ],
                "type": "VTEPPolicy"
            }
            r = fmc.rest_put(url, put_data)
            log.info("ConfigureFtdInterfaces:::: VTEP Interface Creation Response : {}".format(r))

        # Configure VNI Interface
        url = "https://" + fmc_ip + "/api/fmc_config/v1/domain/" + domain_uuid + "/devices/devicerecords/" + dev_id + "/vniinterfaces"
        existing_vni = fmc.rest_get(url + "?expanded=true&limit=100").json().get("items", [])
        if any(item.get("name") == "vni1" for item in existing_vni):
            log.info("ConfigureFtdInterfaces:::: VNI interface vni1 already exists")
        else:
            put_data = {
                "type": "VNIInterface",
                "vniId": 1,
                "vtepID": 1,
                "enabled": True,
                "ifname": "vni1",
                "name": "vni1",
                "enableProxy": True,
                "internalSegmentId": internal_seg_id,
                "externalSegmentId": external_seg_id,
                "internalPort": internal_port_no,
                "externalPort": external_port_no,
                "securityZone": {
                    "id": outside_zone_id,
                    "type": "SecurityZone"
                }
            }
            r = fmc.rest_put(url, put_data)
            log.info("ConfigureFtdInterfaces:::: VNI Interface Creation Response : {}".format(r))

    log.info("ConfigureFtdInterfaces:::: Successfully configured Outside Interface")
    return func.HttpResponse("SUCCESS",status_code=200)
