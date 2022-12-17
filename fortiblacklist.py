import json
import os

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import warnings


def getWanIP(session, urlstub, interface, scope):
    response = session.get(urlstub + "/api/v2/monitor/system/interface?scope=" + scope)

    interfaces = json.loads(response.text)
    wanip = interfaces["results"][interface]["ip"]
    return wanip

def processDevice(fwinfo, userName, password):
    warnings.simplefilter('ignore', InsecureRequestWarning)
    headers = {
        "User-Agent": "Mozilla",
        "X-Requested-With": "MrPython",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = "ajax=1&username=" + userName + "&secretkey=" + password
    firewallIP = "192.168.1.1"
    port = "443"
    interface = "wan1"
    scope = "global"

    if "ip" in fwinfo:
        firewallIP = fwinfo["ip"]
    if "port" in fwinfo:
        port = str(fwinfo["port"])
    if "interface" in fwinfo:
        interface = fwinfo["interface"]
    if "scope" in fwinfo:
        scope = fwinfo["scope"]

    session = requests.Session()

    urlstub = "https://" + firewallIP + ":" + port
    response = session.post(url=urlstub + "/logincheck",
                             headers=headers, verify=False, data=data)
    wanip = getWanIP(session, urlstub, interface, scope)
    response3 = session.get(urlstub + "/api/v2/cmdb/firewall/address?scope=" + scope)
    print(f'Begin: {firewallIP}')
    addresses = json.loads(response3.text)
    for addy in addresses["results"]:
        if addy["name"].startswith("ban-"):
            print(addy)
    print(f'processDevice() returned {wanip}')
    print(f'End: {firewallIP}')

def main():
    username = os.getenv("username")
    password = os.getenv("password")
    ips = json.loads(os.getenv("devicelist"))
    for theip in ips:
        processDevice(theip, username, password)

if __name__ == '__main__':
    main()








