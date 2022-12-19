import json
import os

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import warnings

def createAddress(session, urlstub, scope, address, csrf):
    data = address

    headers = {"Content-Type": "application/json",
               "X-CSRFTOKEN": csrf }

    proxies = {
        'http': 'http://localhost:8080',
        'https': 'http://localhost:8080'
    }
    response = session.post(urlstub + "/api/v2/cmdb/firewall/address?datasource=1&vdom=" + scope, json=data, headers=headers, proxies=proxies, verify=False)
    #response = session.put(urlstub + "/api/v2/cmdb/firewall/address/ban-demo3?datasource=1&vdom=" + scope, json=data, headers=headers, proxies=proxies, verify=False)
    print(response.text)

def getAddresses(session, urlstub, scope, cookies):
    response3 = session.get(urlstub + "/api/v2/cmdb/firewall/address?scope=" + scope, verify=False)
    addresses = json.loads(response3.text)
    return addresses

def getWanIP(session, urlstub, interface, scope):
    response = session.get(urlstub + "/api/v2/monitor/system/interface?scope=" + scope, verify=False)

    interfaces = json.loads(response.text)
    wanip = interfaces["results"][interface]["ip"]
    return wanip

def loadBlacklistAddresses():
    f = open('blacklist.json', "r")
    blacklist = json.loads(f.read())
    print(blacklist)
    return blacklist

def processDevice(fwinfo, userName, password):
    warnings.simplefilter('ignore', InsecureRequestWarning)
    blacklist = loadBlacklistAddresses()
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
    proxies = {
        'http': 'http://localhost:8080',
        'https': 'http://localhost:8080'
    }
    response = session.post(url=urlstub + "/logincheck",
                             headers=headers, verify=False, proxies=proxies, data=data)
    cookies = session.cookies.get_dict()

    csrf = cookies["ccsrftoken"].replace('"', '')

    wanip = getWanIP(session, urlstub, interface, scope)
    print(f'Begin: {firewallIP}')
    addresses = getAddresses(session, urlstub, scope, csrf)
    for addy in addresses["results"]:
        if addy["name"].startswith("ban-"):
            print(f'{addy["name"]}: {addy["subnet"]}')
    newaddresses = os.getenv("newaddresses")
    newaddressdict = json.loads(newaddresses)
    print(f'processDevice() returned {wanip}')
    for address in blacklist:
       createAddress(session, urlstub, scope, address, csrf)
    print(f'End: {firewallIP}')

def main():
    username = os.getenv("username")
    password = os.getenv("password")
    ips = json.loads(os.getenv("devicelist"))
    for theip in ips:
        processDevice(theip, username, password)

if __name__ == '__main__':
    main()








