import io
import json
import logging

import time

import oci
from fdk import response

from fmc import DerivedFMC
from utility import TokenCaller
import utility as utl
from fdk import response

logging.basicConfig(force=True, level="INFO")
logger = logging.getLogger()

class Teardown:
    def __init__(self):
        auth = self.get_signer()
        self.computeManagementClient = oci.core.ComputeManagementClient(config={}, signer=auth)
        self.retries = 3

    def get_signer(self):
        try:
            auth = oci.auth.signers.get_resource_principals_signer()
            return auth
        except Exception as e:
            logger.error("FTDv TEARDOWN OPERATIONS: ERROR IN OBTAINING SIGNER  "+repr(e))
            return None

    def get_all_instances_in_pool(self, compartmentId, instancePoolId):
        """
        Purpose:   To get ID of all instances in the Instance Pool 
        Parameters: 
        Returns:    List(Instances)
        Raises:
        """
        for i in range(0, self.retries):
            try:
                all_instances_in_instance_pool = self.computeManagementClient.list_instance_pool_instances(
                                            compartment_id = compartmentId,
                                            instance_pool_id = instancePoolId).data
                return all_instances_in_instance_pool

            except Exception as e:
                logger.error("FTDv TEARDOWN OPERATIONS: ERROR IN GETTING INSTANCE LIST FROM INSTANCE POOL, RETRY COUNT:{0}, REASON:{1}".format(str(i+1), repr(e)))
                continue 
        return None


def handler(ctx, data: io.BytesIO = None):
    logger.info("----FTDv Teardown Operation called----")
    try:
        environmentVariables = ctx.Config()
        compartmentId = environmentVariables["compartment_id"]
        
        instancePoolId = environmentVariables["instance_pool_id"]
        compartmentId = environmentVariables["compartment_id"]
        autoScaleGroupPrefix = environmentVariables["autoscale_group_prefix"]

        ftdv_configuration_json_url = environmentVariables["ftdv_configuration_json_url"]
        
        fmc_ip = environmentVariables["fmc_ip"]
        fmc_username = environmentVariables["fmc_username"]

        cryptEndpoint = environmentVariables["cryptographic_endpoint"]
        master_key_id = environmentVariables["master_key_id"]
        #environmentVariables["ftdv_password"] = utl.decrypt_cipher(str(environmentVariables["ftdv_encrypted_password"]), cryptEndpoint, master_key_id)
        environmentVariables["fmc_password"]  = utl.decrypt_cipher(str(environmentVariables["fmc_encrypted_password"]),cryptEndpoint, master_key_id)

        json_var = utl.get_fmc_configuration_input(ftdv_configuration_json_url)
        if json_var == None:
            return "ERROR IN FTDv CONFIGURATION JSON"
        insideInterfaceName = json_var["fmcInsideNicName"]
        outsideInterfaceName = json_var["fmcOutsideNicName"]

    except Exception as e:
        logger.error("FTDv TEARDOWN OPERATIONS: ERROR IN RETRIEVING ENVIRONMENT VARIABLES: "+repr(e))
        return None
#______________________________________________________________________________________________________________________
    try:
        # OBTAINING AUTH TOKEN FOR FMC FROM FTDv TOKEN MANAGER
        appName = autoScaleGroupPrefix + "_application"
        tokenHandler = TokenCaller(compartmentId, appName)    
        endpoint = environmentVariables['token_endpoint_url']
        token = tokenHandler.get_token(endpoint)
    
        if token == None:
            raise Exception("ERROR IN RECEIVING TOKEN")
    except Exception as e:
        logger.info("FTDv TEARDOWN OPERATIONS: NO TOKEN RECEIVED")
        return "FTDv TEARDOWN OPERATIONS: NO TOKEN RECEIVED"
    
    try: 
        e_var = environmentVariables
        j_var = json_var
        
        # FMC class initialization
        fmc = DerivedFMC(e_var["fmc_ip"], e_var["fmc_username"], e_var["fmc_password"], j_var['fmcAccessPolicyName'])
        
        # Gets Auth token & updates self.reachable variable
        fmc.compartmentId = e_var["compartment_id"]
        fmc.appName = e_var["autoscale_group_prefix"]+"_application"
        fmc.tokenEndpoint = e_var['token_endpoint_url']
        fmc.reach_fmc_with_manual_token(token)
    
    except Exception as e:
        logger.error("FTDv TEARDOWN OPERATIONS: ERROR IN CREATING FMC OBJECTS " + repr(e))
        return "FTDv TEARDOWN OPERATIONS: FAILED TO CREATE FMC AND FTD OBJECTS"
#________________________________________________________________________________________________________________________
    try:
        teardownObj = Teardown()
        all_instances_in_pool = teardownObj.get_all_instances_in_pool(compartmentId, instancePoolId)
        if all_instances_in_pool == None:
            return
        currentRunningInstanceList = []
        for instance in all_instances_in_pool:
            if str(instance.state).upper() == "RUNNING":
                currentRunningInstanceList.append(instance)

        for instance in currentRunningInstanceList:
            vm_name = autoScaleGroupPrefix +"_"+ str(instance.id[-12:])
            try:
                fmc.deregister_device(vm_name)
                for i in range(0, 6):
                    status_in_fmc = fmc.check_reg_status_from_fmc(vm_name)
                    if status_in_fmc == 'FAILED':
                        logger.info(f"FTDv TEARDOWN OPERATIONS: FTDv instance {vm_name} got unregistered from FMC successfully")
                        break
                    else:
                        logger.info(f"FTDv TEARDOWN OPERATIONS: FTDv instance {vm_name} waiting to get un-register")
                        time.sleep(10)
            except Exception as e:
                logger.error(f"FTDv TEARDOWN OPERATIONS: ERROR IN DEREGISTERING {vm_name} FROM FMC")
                continue
    except Exception as e:
        logger.error("FTDv TEARDOWN OPERATIONS: ERROR IN UN-REGISTERING DEVICES  "+repr(e))
        return "FTDv TEARDOWN OPERATIONS: ERROR IN UN-REGISTERING DEVICES"

    return response.Response(
        ctx, response_data=json.dumps(
            {"Response": "SUCCESSFULL"}),
        headers={"Content-Type": "application/json"}
    )
