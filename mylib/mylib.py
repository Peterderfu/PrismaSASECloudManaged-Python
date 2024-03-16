from auth import saseAuthentication
from access import prismaAccess,serviceSetup,configurationManagement
import time

PRISMA_ACCESS_RESP_OK = [200,201]
#API connection to Prisma Access setup
def prismaAccessConnect(tokenPath):
    p = saseAuthentication.saseAuthentication()
    p.prismaAccessAuthLoadToken(tokenPath)
    return prismaAccess.prismaAccess(p.saseToken)

def setResponse(statusCode,msg):
    return {
                "statusCode": statusCode,
                "headers": {"Content-Type": "application/json"},
                "isBase64Encoded": "false",
                "body": {"msg": msg }
            }

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
            jobs = o.paConfigJobsListById(str(job_id),"Remote Networks")
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
            print("Pushing configuration stage #2 - deploying")
            try:
                jobs = o.paConfigJobsListById(str(job_id),"Remote Networks")
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
