import json
import os

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import warnings

def createAddress(session, urlstub, scope, address):
    data = address
    data = {
  "name": "ban-demo2",
  "subnet": "1.1.1.1/32",
  "color": "0"
}
    headers = {"Content-Type": "application/json"}
    cookies = session.cookies
    items = cookies.get_dict()
    response = session.post(urlstub + "/api/v2/cmdb/firewall/address?datasource=1&vdom=" + scope, json=data, cookies=items)
    response = session.post("http://172.27.12.11" + "/api/v2/cmdb/firewall/address?datasource=1&vdom=" + scope, json=data, cookies=items)
    print(response.text)


def getAddresses(session, urlstub, scope):
    response3 = session.get(urlstub + "/api/v2/cmdb/firewall/address?scope=" + scope)
    addresses = json.loads(response3.text)
    for addy in addresses["results"]:
        createAddress(session, urlstub, scope, addy)
    return addresses

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
    print(f'Begin: {firewallIP}')
    addresses = getAddresses(session, urlstub, scope)
    for addy in addresses["results"]:
        if addy["name"].startswith("ban-"):
            print(f'{addy["name"]}: {addy["subnet"]}')
    newaddresses = os.getenv("newaddresses")
    newaddressdict = json.loads(newaddresses)
    print(f'processDevice() returned {wanip}')
    #for address in newaddressdict:
       # createAddress(session, urlstub, scope, address)
    print(f'End: {firewallIP}')

def main():
    username = os.getenv("username")
    password = os.getenv("password")
    ips = json.loads(os.getenv("devicelist"))
    for theip in ips:
        processDevice(theip, username, password)

if __name__ == '__main__':
    main()








