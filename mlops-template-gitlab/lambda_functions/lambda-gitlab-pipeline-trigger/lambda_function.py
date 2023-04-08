import gitlab
import os
import boto3
import base64
from botocore.exceptions import ClientError
import cfnresponse

import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())

'''
def get_secret():
    secret_name = os.environ['GitLabTokenSecretName']
    region_name = os.environ['Region']

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            logging.error(e)
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            logging.error(e)
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            logging.error(e)
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            logging.error(e)
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            logging.error(e)
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            
            return secret.split(':')[-1].strip('" "}\n')
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret.split(':')[-1].strip('"}')

    return None
'''

def get_secret(secret):

    secret_name = os.environ[secret]
    region_name = os.environ['Region']
    
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            logging.error(e)
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            logging.error(e)
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            logging.error(e)
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            logging.error(e)
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            logging.error(e)
            raise e
        else:
            logging.error(e)
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return secret.split(':')[-1].strip('" "}\n')
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret
            
    return None

def create_custom_ca_bundle(carootcert, cabundlelocation):
    original_ca_bundle = certifi.where()

    with open(original_ca_bundle, 'rb') as original_file, open(cabundlelocation, 'wb') as custom_file:
        custom_file.write(original_file.read())
        custom_file.write(b'\n')
        custom_file.write(carootcert.encode('utf-8'))
        
    return 

def lambda_handler(event, context):
    ''' '''
    gitlab_project_name = os.environ['DeployProjectName']
    gitlab_server_uri = os.environ['GitLabServer']
    project_id = os.environ['SageMakerProjectId']
    
    #Fetch GitLab Token Secret
    
    #gitlab_private_token = get_secret()  

    #if gitlab_private_token is None:
    #    raise Exception("Failed to retrieve secret from Secrets Manager")
    

    FETCH_GITLAB_TOKEN_SECRET_ERROR_MSG = "GitLab token was not retrieved from Secrets Manager."

    try:
        gitlab_private_token = get_secret('GitLabTokenSecretName') 
        if gitlab_private_token is None:
            raise Exception(FETCH_GITLAB_TOKEN_SECRET_ERROR_MSG)
    except Exception as e:
        logging.error(FETCH_GITLAB_TOKEN_SECRET_ERROR_MSG)
        cfnresponse.send(event, context, cfnresponse.FAILED, response_data)
    
    FETCH_CAROORCERT_SECRET_ERROR_MSG = "CAROOTCERT value was not retrieved from Secrets Manager."
            
    try:
        '''get caroot cert from secrets manager'''
        carootcert = get_secret('CARootCertificateSecretName')
        if carootcert is None:
            raise Exception(FETCH_CAROORCERT_SECRET_ERROR_MSG)
        
        '''REQUESTS_CA_BUNDLE location where combined certificate file would be created'''
        cabundlelocation = os.environ['REQUESTS_CA_BUNDLE']
        
        create_custom_ca_bundle(carootcert,cabundlelocation)
        
    except Exception as e:
        logging.error("Error while creating custom CA bundle file")
        cfnresponse.send(event, context, cfnresponse.FAILED, response_data)
    
    
    
    # Configure SDKs for GitLab and S3
    gl = gitlab.Gitlab(gitlab_server_uri, private_token=gitlab_private_token)
    print(gitlab_server_uri)

    # Create the GitLab Project
    try:
        project = gl.projects.list(search = gitlab_project_name + '-' + project_id)[0]
        logging.info("Project")
        logging.info(project)
        
    except Exception as e:
        logger.error("Unable to find the project for model deploy in GitLab..")
        logger.error(e)
        return {
            'message' : "Failed to find GitLab project.."
        }

    try:
        trigger = project.triggers.create({'description' : gitlab_project_name + '-lambda-generated-token'})
        token = trigger.token
        project.trigger_pipeline('main', token)
        trigger.delete()
    except Exception as e:
        logging.error("Failed to trigger pipeline..")
        logging.error(e)
        return {
            'message' : "Failed to trigger pipeline.."
        }

    return {
            'message' : "Success!"
        }
