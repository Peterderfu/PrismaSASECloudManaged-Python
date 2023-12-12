import sys,os,json
sys.path.append(os.getcwd()) # add current path to system environment
import boto3
from botocore.exceptions import ClientError
from auth import saseAuthentication
from access import prismaAccess,policyObjects,identityServices,configurationManagement


#API connection to Prisma Access setup
def prismaAccessConnect(secret):
    p = saseAuthentication.saseAuthentication()
    p.prismaAccessAuth(secret['tsg_id'],secret['client_id'],secret['client_secret'])
    return prismaAccess.prismaAccess(p.saseToken)

## List all HIP Objects
def ListHipObjects(conn):
    o = policyObjects.policyObjects(conn)
    return o.paHipObjectsListHipObjects()

## List all local users
def ListLocalUsers(conn):
    o = identityServices.identityServices(conn)
    return o.paIdentidyListLocalUsers()

## Lock local users
def LockLocalUsers(conn,payload):
    o = identityServices.identityServices(conn)
    return o.paIdentityLockLocalUsers(payload)
## Push configuration
def PushConfig(conn,payload):
    o = configurationManagement.configurationManagement(conn)
    return o.paConfigPush(payload)
def lambda_handler(event, context):
    secret_name = "Prisma-Access"
    region_name = "us-east-1"

    # Create a Secrets Manager client
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
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e
    # Decrypts secret using the associated KMS key.
    secret = get_secret_value_response['SecretString']
    conn = prismaAccessConnect(secret)
    print(conn)

if __name__ == '__main__':
    tokenPath = 'data/authToken.json'
    conn = prismaAccessConnect(tokenPath)
    
    # # -----------------------------------
    output = ListLocalUsers(conn)
    print(output)