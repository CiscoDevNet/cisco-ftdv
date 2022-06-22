import io
import json
import logging

import datetime
from dateutil.tz import tzutc
import oci
import time
import paramiko
import socket

from fdk import response

logging.basicConfig(force=True, level="INFO")
logging.getLogger("paramiko").setLevel(logging.WARNING)
logger = logging.getLogger()

class OCIInstance:

    def __init__(self, compartmentId, instacneId):
        self.auth = self.get_signer()
        self.computeClient = oci.core.ComputeClient(config={}, signer= self.auth)
        self.virtualNetworkClient = oci.core.VirtualNetworkClient(config={}, signer= self.auth)
        self.computeManagementClient = oci.core.ComputeManagementClient(config={}, signer= self.auth)
        self.loadBalancerClient = oci.load_balancer.LoadBalancerClient(config={}, signer= self.auth)
        self.ons_client = oci.ons.NotificationDataPlaneClient(config={}, signer= self.auth)
        self.retries = 3
        self.SUCCESS = 'SUCCESS'
        self.FAIL = 'FAIL'
        self.instanceId = instacneId
        self.compartmentId = compartmentId
        self.vm_name = ''

    def get_signer(self):
        try:
            auth = oci.auth.signers.get_resource_principals_signer()
            return auth
        except Exception as e:
            logger.error("FTDv:  ERROR IN OBTAINING SIGNER  "+repr(e))
            return None

    def get_instance_pool_info(self, instancePoolId):
        """
        Purpose:   To get information of the Instance Pool 
        Parameters: 
        Returns:    List(Instances)
        Raises:
        """
        for i in range(0,self.retries):
            try:
                get_instance_pool_response = self.computeManagementClient.get_instance_pool(instance_pool_id = instancePoolId).data
                return get_instance_pool_response
            except Exception as e:
                logger.error("FTDv: ERROR IN RETRIEVING INSTANCE POOL INFORMATION, RETRY COUNT: {0}, ERROR: {1}".format(str(i), repr(e)))
                continue
        
        return None

    def get_all_instances_id_in_pool(self, instancePoolId):
        """
        Purpose:   To get OCID of all Instances in the Instance Pool 
        Parameters: Compartment OCID, Instance Pool OCID
        Returns:    List(Instance OCID)
        Raises:
        """
        for i in range(0, self.retries):
            try:
                all_instances_in_instance_pool = self.computeManagementClient.list_instance_pool_instances(compartment_id = self.compartmentId, instance_pool_id = instancePoolId).data
                all_instances_id = [instance.id for instance in all_instances_in_instance_pool]
                return all_instances_id

            except Exception as e:
                logger.error("FTDv:  ERROR IN GETTING INSTANCE LIST FROM INSTANCE POOL, RETRY COUNT:{0}, REASON:{1}".format(str(i+1), repr(e)))
                continue
        
        return None

    def terminate_instance(self):
        """
        Purpose:   To Terminate any Instance in the Instance Pool (Not Scale-In)
        Parameters: Instance OCID to delete.
        Returns:    Boolean
        Raises:
        """
        for i in range(0, self.retries):
            try:
                terminate_instance_response = self.computeClient.terminate_instance(instance_id = self.instanceId, preserve_boot_volume=False)
                logger.info(f"FTDv {self.instanceId[-5:]}:  INSTANCE HAS BEEN TERMINATED ")
                return True
            
            except Exception as e:
                logger.info("FTDv: ERROR OCCURRED WHILE TERMINATING INSTANCE {}, RETRY COUNT:{}, REASON:{}".format(self.instanceId, str(i+1), repr(e)))
                continue
        return False

    def get_instance_interface_info(self, insideInterfaceName, outsideInterfaceName):
        """
        Purpose:    
        Parameters:
        Returns: Dict Example: {insideInterfaceName: '10.0.100.139','outside_ip': '10.0.200.116'}   
        Raises:
        """
        interface_info = {}
        try:
            vnic_attachments = oci.pagination.list_call_get_all_results(
            self.computeClient.list_vnic_attachments,
            compartment_id = self.compartmentId,
            instance_id = self.instanceId
            ).data
        except Exception as e:
            logger.error("FTDv: ERROR IN RETRIEVING VNIC ATTACHMENT "+repr(e))
            return None

        vnics = [self.virtualNetworkClient.get_vnic(va.vnic_id).data for va in vnic_attachments]
        try:
            for vnic in vnics:
                if vnic.display_name == insideInterfaceName:
                    ip_response = vnic.private_ip
                    interface_info[insideInterfaceName+"_ip"] = str(ip_response)

                    cidr, netmask = self.get_netmask_from_subnet_cidr(vnic.subnet_id)
                    if netmask != None:
                        interface_info[insideInterfaceName+"_netmask"] = str(netmask)
                        interface_info[insideInterfaceName+"_cidr"] = str(cidr)

                elif vnic.display_name == outsideInterfaceName:
                    ip_response = vnic.private_ip
                    interface_info[outsideInterfaceName+"_ip"] = str(ip_response)

                    cidr, netmask = self.get_netmask_from_subnet_cidr(vnic.subnet_id)
                    if netmask != None:
                        interface_info[outsideInterfaceName+"_netmask"] = str(netmask)
                        interface_info[outsideInterfaceName+"_cidr"] = str(cidr)

        except Exception as e:
            logger.error("FTDv: ERROR IN RETRIEVING INTERFACES IP ADDRESS "+repr(e))
            return None
        
        logger.debug("FTDv: Retrieved Interfaces INFO Successfully")
        return interface_info

    def get_management_public_private_ip(self):
        """
        Purpose:    To get Management interface (vnic) public IP. 
        Parameters: Compartment OCID, Instance OCID.
        Returns:    List     Example: [management_public_ip, management_private_ip]
        Raises:
        """
        for i in range(0, self.retries):
            try:
                vnic_attachments = oci.pagination.list_call_get_all_results(
                self.computeClient.list_vnic_attachments,
                compartment_id = self.compartmentId,
                instance_id = self.instanceId,
                ).data        

                vnics = [self.virtualNetworkClient.get_vnic(va.vnic_id).data for va in vnic_attachments]

                for vnic in vnics:
                    if vnic.is_primary:
                        public_ip_response = vnic.public_ip
                        private_ip_response = vnic.private_ip
                        return [public_ip_response, private_ip_response]
                        
            except Exception as e:
                logger.error("FTDv:  ERROR IN RETRIEVING MANAGEMENT PUBLIC IP "+"RETRY COUNT:"+str(i)+"  "+ repr(e))
                continue
        
        return None
                
    def get_netmask_from_subnet_cidr(self, subnetId):
        """
        Purpose:   To calculate Netmask of Subnet.
        Parameters: Subnet OCID
        Returns:    Str
        Raises:
        """
        try:
            subnet_cidr = (self.virtualNetworkClient.get_subnet(subnet_id = subnetId).data).cidr_block
            (addrString, cidrString) = subnet_cidr.split('/')
            cidr = int(cidrString)

            mask = [0, 0, 0, 0]
            for i in range(cidr):
                mask[int(i/8)] = mask[int(i/8)] + (1 << (7 - i % 8))
            
            netmask = ".".join(map(str, mask))
            return [subnet_cidr, netmask]
        except Exception as e:
            logger.error("FTDv:  ERROR IN CALCULATING NETMASK FOR SUBNET ID:{} ERROR:{}".format(subnetId, repr(e)))
            return [None, None]

    def publish_message(self, topicId, msg):
        for i in range(0, self.retries):
            try:
                publish_message_response = self.ons_client.publish_message(
                    topic_id = topicId,
                    message_details=oci.ons.models.MessageDetails(
                        body = json.dumps(msg),
                        title = "Configure_FTDv_Recall")).data

                logger.info("FTDv:  Configure FTDv Function has been recalled successfully")
                return "Configure FTDv Function has been recalled"
            except Exception as e:
                logger.info(e)
                continue
                    
        logger.error("UNABLE TO RE-CALL CONFIGURE FTDv FUNCTION, INSTACE WILL BE TERMINATED")
        terminate_response = self.terminate_instance()
        return "UNABLE TO RE-CALL CONFIGURE FTDv FUNCTION, INSTACE WILL BE TERMINATED"
