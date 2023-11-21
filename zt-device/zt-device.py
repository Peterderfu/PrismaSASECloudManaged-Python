import sys,os,json
sys.path.append(os.getcwd()) # add current path to system environment
from auth import saseAuthentication
from access import prismaAccess,policyObjects,identityServices,configurationManagement


#API connection to Prisma Access setup
def prismaAccessConnect(tokenPath):
    p = saseAuthentication.saseAuthentication()
    p.prismaAccessAuthLoadToken(tokenPath)
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
if __name__ == '__main__':
    tokenPath = 'data/authToken.json'
    conn = prismaAccessConnect(tokenPath)
    
    # # -----------------------------------
    output = ListLocalUsers(conn)
    print(output)

    # # -----------------------------------
    # id = '40979f0e-0afa-4f05-95f3-02439400a2a2'
    # s = '{"disabled": "True","name": "peter","password": "1234"}'
    # payload = json.loads(s)
    # LockLocalUsers(conn,id,payload)

    # -----------------------------------
    # s = '{"description": "disable Peter","folders": ["Mobile Users"]}'
    # payload = json.loads(s)
    # output = PushConfig(conn,payload)
    


    pass

