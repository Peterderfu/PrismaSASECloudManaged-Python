import sys,os,json,time
sys.path.append(os.getcwd()) # add current path to system environment
import boto3
from botocore.exceptions import ClientError
from auth import saseAuthentication
from access import prismaAccess,policyObjects,identityServices,configurationManagement

PRISMA_ACCESS_RESP_OK = [200,201]
MOBILE_USERS = "Mobile Users"

def setResponse(statusCode,msg):
    return {
            "statusCode": statusCode,
            "headers": {"Content-Type": "application/json"},
            "isBase64Encoded": "false",
            "body": {"msg": msg }
            }
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
    
    output['name'] = registration['User'] + "_object"
    output['host_info']['criteria']['os']['contains'] = {OS_map[registration['OS']]: "All"}
    output['host_info']['criteria']['host_id']['is'] = registration['Device']
    return output

def setHIPProfile(conn,objectName):
    #get a HIP profile template pre-defined in Prisma Access portal and modify it for new HIP profile 
    output = getHIPProfileGPTemplate(conn)
    
    output['name'] = getHIPProfileName(objectName)
    output['match'] = "'" + objectName + "'"
    return output

def setSecurityPolicy(conn,policy):
    #get a HIP security profile pre-defined in Prisma Access portal and modify it for new security profile
    output = getSecurityPolicyGPTemplate(conn)
    output['name'] = policy['name']
    output['source_user'] = [policy['source_user']]
    output['source_hip'] = [policy['source_hip']]
    output['destination'] = [policy['destination']]
    output['disabled'] = False
    return output

def CreateHIPObject(conn,registration):
    output = None
    o = policyObjects.policyObjects(conn)
    hipObject = setHIPObject(conn,registration)
    resp = o.paHipObjectsCreate(hipObject)
    if not (resp['code'] in PRISMA_ACCESS_RESP_OK):
        print("Failed to create HIP object")
        return output
    output = hipObject['name']
    return output

def CreateHIPProfile(conn,objectName):
    output = None
    o = policyObjects.policyObjects(conn)
    profileObject = setHIPProfile(conn,objectName)

    resp = o.paHipProfilesCreate(profileObject)
    if not (resp['code'] in PRISMA_ACCESS_RESP_OK):
        print("Failed to create HIP profile")
        return output
    output = profileObject['name']
    return output
def CreateSecurityPolicy(conn,policy):
    output = None
    o = policyObjects.policyObjects(conn)
    secuirtyPolicy = setSecurityPolicy(conn,policy)

    resp = o.paSecurityPolicyCreate(secuirtyPolicy,MOBILE_USERS)
    if (resp['code'] in PRISMA_ACCESS_RESP_OK):
        policies = o.paSecurityPolicyListSecurityPolicy(MOBILE_USERS)
        if len(policies) > 0:
            for d in policies['data']:  
                if d['name'] == secuirtyPolicy['name']: # Move the policy to top
                    o.paSecurityPolicyMoveTop(d['id'],MOBILE_USERS)
                    output = secuirtyPolicy['name']
    return output



def getHIPObjectGPTemplate(conn,objectName="HIP_OBJECT_GP_TEMPLATE"):
    output = None
    ho = ListHipObjects(conn,folder=MOBILE_USERS)
    
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
    ho = ListHipProfiles(conn,folder=MOBILE_USERS)
    
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
    so = ListSecurityPolicy(conn,folder=MOBILE_USERS)
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

def DeleteHipProfile(conn,profile):
    output = None
    o = policyObjects.policyObjects(conn)
    output = o.paHipProfilesDelete(profile,profile['folder'])
    return output
def DeleteSecurityPolicy(conn,policy):
    output = None
    o = policyObjects.policyObjects(conn)
    output = o.paSecurityPolicyDelete(policy,policy['folder'])
    return output
def DeleteUserDevice(conn,reg):
    device_ID = reg['Device']
    hipObjectToBeDeleted = None
    hipProfileToBeDeleted = None
    securityPolicyToBeDeleted = None
    policyName = getSecurityPolicyName(getHIPProfileName(getHIPObjectName(reg['User'])))
    o = ListSecurityPolicy(conn,MOBILE_USERS)
    if len(o['data']) > 0:
        for d in o['data']:  #check device identical to input registration info
            if d['name'] == policyName:
                securityPolicyToBeDeleted = d
                securityPolicyToBeDeleted['folder'] = MOBILE_USERS
                deletedSecurityPolicyName = DeleteSecurityPolicy(conn,securityPolicyToBeDeleted)
                break

    o = ListHipObjects(conn,MOBILE_USERS)
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
        o = ListHipProfiles(conn,MOBILE_USERS)
        if len(o['data']) > 0:
            for d in o['data']:  #check device identical to input registration info
                try:
                    if d['match']== deletedObjectName:
                        hipProfileToBeDeleted = d
                        break
                except KeyError:
                    pass
    if hipProfileToBeDeleted:
        deletedProfileName = DeleteHipProfile(conn,hipProfileToBeDeleted)
    else:
        pass
    
def getHIPObjectName(user):
    return user + "_object"
def getHIPProfileName(objectName):
    return objectName + "_profile"
def getSecurityPolicyName(profileName):
    return "ALLOW_" + profileName

def pushConfig(conn,configBody):
    output = None
    stage_first_OK = False
    stage_second_OK = False
    o = configurationManagement.configurationManagement(conn)
    
    pushJobs = o.paConfigPush(configBody)
    if not (pushJobs["code"] in PRISMA_ACCESS_RESP_OK):
        print("Failed to push config")
        exit()
    job_id = int(pushJobs["resp"]["job_id"])
    while (True):
        print("Pushing configuration stage #1 - validating")
        try:
            jobs = o.paConfigJobsListById(str(job_id),MOBILE_USERS)
            result_str = jobs["data"][0]["result_str"]
        except KeyError:
            continue
            
        match result_str:
            case "PEND":
                time.sleep(3)
            case "OK":
                stage_first_OK = True
                job_id = job_id + 1
                break
            case _:
                break
    if stage_first_OK:
        while (True):
            print("Pushing configuration stage #2 - deployment")
            try:
                jobs = o.paConfigJobsListById(str(job_id),MOBILE_USERS)
                result_str = jobs["data"][0]["result_str"]
            except KeyError:
                continue
            
            match result_str:
                case "PEND":
                    time.sleep(3)
                case "OK":
                    stage_second_OK = True
                    break
                case _:
                    break
    output = stage_first_OK & stage_second_OK
    if output:
        print("Pushing configuration - OK")
        response = setResponse(200,"OK")
    else:
        print("Pushing configuration - FAIL")
        response = setResponse(500,"Failed to push configuration")
    return response

def RegisterUserDevice(registrations):
# Device ID type
#   Windows 
#       —Machine GUID stored in the Windows registry (HKEY_Local_Machine\Software\Microsoft\Cryptography\MachineGuid) 
#   macOS 
#       —MAC address of the first built-in physical network interface 
#   Android 
#       —Android ID 
#   iOS 
#       —UDID 
#   Linux 
#       —Product UUID retrieved from the system DMI table 
#   Chrome 
#       —GlobalProtect-assigned unique alphanumeric string with length of 32 characters 
    response = None
    conn = getPrismaAccessConn()
    for registration in registrations:
        registration['Destination'] = '8.8.8.8'
        DeleteUserDevice(conn,registration)
        try:
            user            = registration['User']
            OS              = registration['OS']
            device_ID       = registration['Device']
            destination     = registration['Destination']
        except:
            msg = 'Invalid input registration info'
            response = setResponse(500,msg)
            print(msg)
            return response
        ho = ListHipObjects(conn,MOBILE_USERS)
        
        if len(ho['data']) > 0:
            for d in ho['data']:  #check device identical to input registration info
                try:
                    if d['host_info']['criteria']['host_id']['is'] == device_ID:
                        msg = 'Device ID (' + device_ID + ') is already existing'
                        response = setResponse(500,msg)
                        return response # there is device registry existing in Prisma Access
                except KeyError:
                    pass
            
            # there is no device registry existing in Prisma Access and start to do registration
            # step 1: add HIP object
            objectName = CreateHIPObject(conn,registration)
            if not objectName:
                response = setResponse(500,"Failed to create HIP object")
            # step 2: add HIP profile by adding HIP object
            profileName = CreateHIPProfile(conn,objectName)
            if not profileName:
                response = setResponse(500,"Failed to create HIP profile")
            # step 3: add security policy including HIP profile
            policy = {
                    "name": getSecurityPolicyName(profileName),
                    "source_user": user,
                    "source_hip": profileName,
                    "destination": destination
                }
            securityPolicy = CreateSecurityPolicy(conn,policy)
            if not securityPolicy:
                response = setResponse(500,"Failed to create security policy")
            
        # step 4: push config
        pushResult = pushConfig(conn,{"description":user,"folders":[MOBILE_USERS]})
        if not pushResult:
            response = setResponse(500,"Failed to push config")

        # User and device creation successfully
        if  (objectName and profileName and securityPolicy and pushResult):
            response = setResponse(200,"OK")       
    return response

def lambda_handler(event, context):
    operation = event['operation']
    operations = {
        'register': RegisterUserDevice,
        'list': ListLocalUsers
    }
    if operation in operations:
        return operations[operation](event.get('payload'))
    else:
        raise ValueError('Unrecognized operation "{}"'.format(operation))
    # conn = getPrismaAccessConn()

    # reg = event['reg']
    # DeleteUserDevice(conn,reg)
    # output = RegisterUserDevice(conn, reg)
    # pushConfig(conn,{"description":reg["User"],"folders":[MOBILE_USERS]})
    # print(output)

if __name__ == '__main__':
    # -----------------------------------
    # output = ListLocalUsers(conn)
    
    reg = [
            {
                "User":"user02",
                "OS":"Windows",
                "ID":"123456",
                "Destination":"8.8.8.8"
            },
            {
                "User":"user03",
                "OS":"Linux",
                "ID":"987654321",
                "Destination":"8.8.8.8"
            }
        ]
    # event = {"reg":reg}
    event = {}
    event['payload'] = reg
    event['operation'] = 'register'
    lambda_handler(event,{})
