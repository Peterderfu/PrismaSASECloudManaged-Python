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
def ListHipObjects(conn,folder):
    o = policyObjects.policyObjects(conn)
    return o.paHipObjectsListHipObjects(folder)

## List all HIP Profiles
def ListHipProfiles(conn,folder):
    o = policyObjects.policyObjects(conn)
    return o.paHipProfilesListHipProfiles(folder)

## List all Security Policy
def ListSecurityPolicy(conn,folder):
    o = policyObjects.policyObjects(conn)
    return o.paSecurityPolicyListSecurityPolicy(folder)


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
## List candidate configuration
def ListCandidateCondig(conn):
    o = configurationManagement.configurationManagement(conn)
    return o.paCandidateConfigList()

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
def setHIPObject(conn,registration):
    #get a HIP object template pre-defined in Prisma Access portal and modify it for new HIP object 
    output = getHIPObjectGPTemplate(conn)
    OS_map = {
        "Windows":"Microsoft",
        "macOS":"Apple",
        "iOS":"Apple",
        "Android":"Google",
        "Chrome":"Google",
        "Linux":"Linux"
    }
    
    output['name'] = registration['User'] + " device"
    output['host_info']['criteria']['os']['contains'] = {OS_map[registration['OS']]: "All"}
    output['host_info']['criteria']['host_id']['is'] = registration['ID']
    return output

def setHIPProfile(conn,objectName):
    #get a HIP profile template pre-defined in Prisma Access portal and modify it for new HIP profile 
    output = getHIPProfileGPTemplate(conn)
    
    output['name'] = "is-" + objectName
    output['match'] = "'" + objectName + "'"
    return output

def setSecurityPolicy(conn,policy):
    #get a HIP security profile pre-defined in Prisma Access portal and modify it for new security profile
    output = getSecurityPolicyGPTemplate(conn)
    output['name'] = policy['name']
    output['source_user'] = policy['source_user']
    output['source_hip'] = policy['source_hip']
    output['destination'] = policy['destination']
    output['disable'] = False
    return output

def CreateHIPObject(conn,registration):
    output = None
    o = policyObjects.policyObjects(conn)
    hipObject = setHIPObject(conn,registration)
    resp = o.paHipObjectsCreate(hipObject)
    if not (resp == PRISMA_ACCESS_RESP_OK):
        print("Failed to create HIP object")
        exit()
    return hipObject['name']

def CreateHIPProfile(conn,objectName):
    output = None
    o = policyObjects.policyObjects(conn)
    profileObject = setHIPProfile(conn,objectName)

    resp = o.paHipProfilesCreate(profileObject)
    if not (resp == PRISMA_ACCESS_RESP_OK):
        print("Failed to create HIP profile")
        exit()
    return profileObject['name']

def CreateSecurityPolicy(conn,policy):
    o = policyObjects.policyObjects(conn)
    secuirtyPolicy = setSecurityPolicy(conn,policy)
    resp = o.paSecurityPolicyCreate(secuirtyPolicy,"Mobile Users")
    if (resp == PRISMA_ACCESS_RESP_OK):
        pass

def RegisterUserDevice(conn,registration):
    try:
        user            = registration['User']
        OS              = registration['OS']
        device_ID       = registration['ID']
        destination     = registration['Destination']
    except:
        print('Invalid input registration info')
    output = {'status':'','info':''}
    ho = ListHipObjects(conn,"Mobile Users")
    
    if len(ho['data']) > 0:
        for d in ho['data']:  #check device identical to input registration info
            try:
                if d['host_info']['criteria']['host_id']['is'] == device_ID:
                    output = {'status':'Device ID existing','info':'Device ID : ' + device_ID}    
                    return output # there is device registry existing in Prisma Access
            except KeyError:
                pass
        
        # there is no device registry existing in Prisma Access and start to do registration
        # step 1: add HIP object
        objectName = CreateHIPObject(conn,registration)
        # step 2: add HIP profile by adding HIP object
        profileName = CreateHIPProfile(conn,objectName)
        # step 3: add security policy including HIP profile
        policy = {
                "name":"Allow_" + user + "_" + objectName,
                "source_user": user,
                "source_hip": profileName,
                "destination": destination
            }
    
        securityPolicy = CreateSecurityPolicy(conn,policy)
        # step 4: push config
        pass

    return output


def getHIPObjectGPTemplate(conn,objectName="HIP_OBJECT_GP_TEMPLATE"):
    output = None
    ho = ListHipObjects(conn,folder="Mobile Users")
    
    if len(ho['data']) > 0:
        for d in ho['data']:
            if d['name'] == objectName:
                d['name'] = ''
                d['description'] = ''
                del d['id']
                output = d
                break
    return output

def getHIPProfileGPTemplate(conn,objectName="HIP_PROFILE_GP_TEMPLATE"):
    output = None
    ho = ListHipProfiles(conn,folder="Mobile Users")
    
    if len(ho['data']) > 0:
        for d in ho['data']:
            if d['name'] == objectName:
                d['name'] = ''
                d['description'] = ''
                del d['id']
                output = d
                break
    return output

def getSecurityPolicyGPTemplate(conn,objectName="SECURITY_POLICY_GP_TEMPLATE"):                
    output = None
    so = ListSecurityPolicy(conn,folder="Mobile Users")
    if len(so['data']) > 0:
        for d in so['data']:
            if d['name'] == objectName:
                del d['id']
                output = d
                break
    return output
def DeleteHipObject(conn,object):
    output = None
    o = policyObjects.policyObjects(conn)
    output = o.paHipObjectsDelete(object,object['folder'])
    return output

def DeleteHipProfile(conn,object):
    output = None
    o = policyObjects.policyObjects(conn)
    output = o.paHipProfilesDelete(object,object['folder'])
    return output

def  DeleteUserDevice(conn,reg):
    device_ID = reg['ID']
    hipObjectToBeDeleted = None
    hipProfileToBeDeleted = None
    o = ListHipObjects(conn,"Mobile Users")
    
    if len(o['data']) > 0:
        for d in o['data']:  #check device identical to input registration info
            try:
                if d['host_info']['criteria']['host_id']['is'] == device_ID:
                    hipObjectToBeDeleted = d
                    break
            except KeyError:
                pass
    if hipObjectToBeDeleted:
        deletedObjectName = DeleteHipObject(conn,hipObjectToBeDeleted)
        deletedObjectName = '\'' + deletedObjectName + '\''
        o = ListHipProfiles(conn,"Mobile Users")
        if len(o['data']) > 0:
            for d in o['data']:  #check device identical to input registration info
                try:
                    if d['match']== deletedObjectName:
                        hipProfileToBeDeleted = d
                        break
                except KeyError:
                    pass
        deletedProfileName = DeleteHipProfile(conn,hipProfileToBeDeleted)
    else:
        pass
    

if __name__ == '__main__':
    conn = getPrismaAccessConn()
    # # -----------------------------------
    # output = ListLocalUsers(conn)
    
    reg = {
            'User':'peter2223',
            'OS':'Windows',
            'ID':'2537edb1-3a2e-4281-a2b6-bf367f46415c',
            'Destination':{'8.8.8.8'}
           }
    
    DeleteUserDevice(conn,reg)

    output = RegisterUserDevice(conn, reg)
    # print(output)