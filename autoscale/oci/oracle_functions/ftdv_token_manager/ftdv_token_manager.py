import io
import json
import logging

from fdk import response
import time
import oci
import utility as utl
from fmc import FirepowerManagementCenter
logger = logging.getLogger()

class Token:
    def __init__(self, fmc_ip, fmc_username, fmc_password, compartment_id, application_name):
        self.fmc = FirepowerManagementCenter(fmc_ip, fmc_username, fmc_password)
        self.signer = auth = oci.auth.signers.get_resource_principals_signer()
        self.functions_client = oci.functions.FunctionsManagementClient(config={}, signer = self.signer)
        self.compartmentId = compartment_id
        self.appName = application_name
        self.functionId = self.get_function_id("ftdv_token_manager")
        self.retry = 3

    def create_new_token(self):
        try:
            for i in range(0, self.retry):
                token_reponse = self.fmc.get_auth_token()
                if token_reponse != None:
                    logger.info("FTDv TOKEN MANAGER: NEW TOKEN GENERATED")
                    self.write_token(json.dumps(dict(token_reponse)))
                    return token_reponse
            return None
        except Exception as e:
            logger.error("FTDv TOKEN MANAGER: ERROR IN RETRIEVING TOKEN "+repr(e))
            return None    

    def write_token(self, token_response):
        try:
            update_function_response = self.functions_client.update_function(
                function_id = self.functionId,
                update_function_details=oci.functions.models.UpdateFunctionDetails(
                    config={'TOKEN': token_response})).data
            logger.debug("TOKEN SAVED SUCCESSFULLY")
            return True
        except Exception as e:
            raise Exception("UNABLE TO SAVE TOKEN  "+repr(e))

    def get_application_id(self):
        try:
            list_applications_response = self.functions_client.list_applications(
                compartment_id = self.compartmentId,
                lifecycle_state = "ACTIVE",
                display_name = self.appName).data
            return list_applications_response[0].id
        except Exception as e:
            raise Exception("ERROR IN RETRIEVING APPLICATION ID  "+repr(e))

    def get_function_id(self, funcName):
        try:
            list_functions_response = self.functions_client.list_functions(
                application_id = self.get_application_id(),
                lifecycle_state = "ACTIVE",
                display_name = funcName).data

            return list_functions_response[0].id
        except Exception as e:
            raise Exception("ERROR IN RETRIEVING FUNCTION ID  "+repr(e))

def handler(ctx, data: io.BytesIO = None):
    try:
        #body = json.loads(data.getvalue())
        logger.info("---TOKEN MANAGER CALLED---")
    except (Exception, ValueError) as ex:
        logger.info('error parsing json payload: ' + str(ex))
        return "FAILED"

    try:
        environmentVariables = ctx.Config()
        compartmentId = environmentVariables["compartment_id"]
        autoScaleGroupPrefix = environmentVariables["autoscale_group_prefix"]
        
        fmc_ip = environmentVariables["fmc_ip"]
        fmc_username = environmentVariables["fmc_username"]
        
        cryptEndpoint = environmentVariables["cryptographic_endpoint"]
        master_key_id = environmentVariables["master_key_id"]
        fmc_password  = utl.decrypt_cipher(str(environmentVariables["fmc_encrypted_password"]),cryptEndpoint, master_key_id)
    except Exception as e:
        logger.error("FTDv CONFIGURE: ERROR IN RETRIEVING ENVIRONMENT VARIABLES"+repr(e))
        return "FAILED"

    try:
        application_name = autoScaleGroupPrefix + "_application"
        tokenManager = Token(fmc_ip, fmc_username, fmc_password, compartmentId, application_name)

        for i in range(0,3):
            token = tokenManager.create_new_token()
            if token != None:
                break
                
        if token == None:
            logger.error("FTDv TOKEN MANAGER: TOKEN COULD NOT BE OBTAINED")

    except Exception as e:
        logger.error("FTDv TOKEN MANAGER: ERROR IN CREATING TOKEN  "+repr(e))
        token = None

    return response.Response(
        ctx, response_data=json.dumps(
            {"TOKEN": "{}".format(token)}),
        headers={"Content-Type": "application/json"})
