import sys,os,json
sys.path.append(os.getcwd()) # add current path to system environment
import boto3
from botocore.exceptions import ClientError
from auth import saseAuthentication
from access import prismaAccess,policyObjects,identityServices,configurationManagement

PRISMA_ACCESS_RESP_OK = 201

#API connection to Prisma Access setup
# def prismaAccessConnect(tokenPath):
def prismaAccessConnect(secret):
    p = saseAuthentication.saseAuthentication()
    p.prismaAccessAuth(secret['TSG_ID'],secret['Client_ID'],secret['Client_Secret'])
    # p.prismaAccessAuthLoadToken(tokenPath)
    return prismaAccess.prismaAccess(p.saseToken)

## List all HIP Objects
def ListHipObjects(conn):
    o = policyObjects.policyObjects(conn)
    return o.paHipObjectsListHipObjects().paList()

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
def getPrismaAccessConn():
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
    conn = prismaAccessConnect(json.loads(secret))
    return conn
def setHIPObject(registration):
    OS_map = {
        "Windows":"Microsoft",
        "macOS":"Apple",
        "iOS":"Apple",
        "Android":"Google",
        "Chrome":"Google",
        "Linux":"Linux"
    }
    output = json.dumps({
        "name": registration['User'] + " device",
        "host-info": {
            "criteria": {
                "host-id": {
                    "is": registration['ID']
                },
                "os": {
                    "contains": {OS_map[registration['OS']]: "All"}
                }
            }
        },
    })
    return output

def CreateHIPObject(conn,registration):
    
    o = policyObjects.policyObjects(conn)
    # respHipObjectsCreate = o.paHipObjectsCreate(hipObject)
    # if not (respHipObjectsCreate == PRISMA_ACCESS_RESP_OK):
    #     print("Failed to create HIP object")
    #     exit()

    respHipProfilesListHipProfiles = o.paHipProfilesListHipProfiles('Mobile Users')
    if (respHipProfilesListHipProfiles == PRISMA_ACCESS_RESP_OK):
        pass
def RegisterUserDevice(conn,registration):
    try:
        user      = registration['User']
        OS        = registration['OS']
        device_ID = registration['ID']
    except:
        print('Invalid input registration info')
    output = {'status':'','info':''}
    ho = ListHipObjects(conn)
    
    if len(ho['data']) > 0:
        for d in ho['data']:
            try:
                if d['host_info']['criteria']['host_id']['is'] == device_ID:
                    output = {'status':'Device ID existed','info':'Device ID : ' + device_ID}    
                    return output # there is device registry existing in Prisma Access
            except KeyError:
                pass
        
        # there is no device registry existing in Prisma Access and start to do registration
        # step 1: add HIP object
        o = CreateHIPObject(conn,registration)
        # step 2: add HIP profile by adding HIP object
        # step 3: add security policy including HIP profile
        # step 4: push config

    return output        

if __name__ == '__main__':
    conn = getPrismaAccessConn()
    # # -----------------------------------
    output = ListLocalUsers(conn)
    reg = {'User':'peter3','OS':'Windows','ID':'testtetetetsesewwwwwwwww'}

    # output = RegisterUserDevice(conn, reg)
    print(output)