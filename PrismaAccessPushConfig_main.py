# from auth import saseAuthentication
from access import serviceSetup
from mylib.mylib import *
import argparse


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--token_file", type = str, help = "File containing Prisma Access token")
    parser.add_argument("-t", "--tunnel_name",type = str, help = "Target tunnel")
    parser.add_argument("-p","--monitor_ip",type=str,  help = "Tunnel monitor IP")
    args = parser.parse_args()
    token_file = args.token_file
    tunnel_name = args.tunnel_name
    monitor_ip = args.monitor_ip
    
    # Get all tunnels info in Remote networks
    conn = prismaAccessConnect(token_file)
    o = serviceSetup.serviceSetup(conn)
    tunnels = o.paIpsecTunnelsListIpsecTunnels("Remote Networks")

    # Get one tunnel with tunnel_name
    tunnelToEdit = dict()
    description = None
    if len(tunnels['data']) > 0 :
        for t in tunnels['data']:
            if t['name'] == tunnel_name:
                tunnelToEdit = t # tunnel name mathced to tunnel_name found
                break
    
    if len(tunnelToEdit) > 0:
        if tunnelToEdit['tunnel_monitor']['enable']: # Start to disable Tunnel monitor
            tunnelToEdit['tunnel_monitor']['enable'] = False
            del tunnelToEdit['tunnel_monitor']['destination_ip']
            description = "Disable tunnel monitor By API"
        else:                                       # Start to enable Tunnel monitor with monitor IP
            tunnelToEdit['tunnel_monitor']['enable'] = True
            tunnelToEdit['tunnel_monitor']['destination_ip'] = monitor_ip
            description = "Enable tunnel monitor By API"
        
        #delete unneccessary fields        
        del tunnelToEdit['id']
        del tunnelToEdit['folder']
        #edit tunnel setting (enable or disable tunnel monitor)
        output = o.paIpsecTunnelsEditIpsecTunnel(tunnelToEdit,"Remote Networks")
        # step 4: push config
        pushResult = pushConfig(conn,{"description":description,"folders":["Remote Networks"]})
        print(pushResult)
        # if not pushResult:
        #     response = setResponse(500,"Failed to push config")

    
