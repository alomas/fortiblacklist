import json
import os

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import warnings


def doesAddressExist(session, urlstub, scope, address, csrf):
    data = address
    headers = {"Content-Type": "application/json",
               "X-CSRFTOKEN": csrf}

    proxies = {
        # 'http': 'http://localhost:8080',
        # 'https': 'http://localhost:8080'
    }
    response = session.get(urlstub + f'/api/v2/cmdb/firewall/address/{data["name"]}?datasource=1&vdom=' + scope,
                           json=data, headers=headers, proxies=proxies, verify=False)

    responsedict = json.loads(response.text)
    if "status" in responsedict:
        status = responsedict["status"]
        if status == "success":
            return True
    return False


def getAddressObjects(session, urlstub, scope, csrf):
    headers = {"Content-Type": "application/json",
               "X-CSRFTOKEN": csrf}

    proxies = {
        # 'http': 'http://localhost:8080',
        # 'https': 'http://localhost:8080'
    }
    response = session.get(urlstub + f'/api/v2/cmdb/firewall/address?datasource=1&vdom=' + scope, headers=headers,
                           proxies=proxies, verify=False)

    responsedict = json.loads(response.text)
    blacklist = []
    if "status" in responsedict:
        status = responsedict["status"]
        if status == "success":
            results = responsedict["results"]
            for result in results:
                if result["name"].startswith("autoban-"):
                    tempaddr = {
                        "name": result["name"]
                    }
                    blacklist.append(tempaddr)
    print(f'\tBuilt blacklist with {len(blacklist)} items.')
    return blacklist


def doesAddressGroupExist(session, urlstub, scope, addressgroup, csrf):
    data = addressgroup
    headers = {"Content-Type": "application/json",
               "X-CSRFTOKEN": csrf}

    proxies = {
        # 'http': 'http://localhost:8080',
        # 'https': 'http://localhost:8080'
    }
    response = session.get(urlstub + f'/api/v2/cmdb/firewall/addrgrp/{data["name"]}?datasource=1&vdom=' + scope,
                           json=data, headers=headers, proxies=proxies, verify=False)

    responsedict = json.loads(response.text)
    if "status" in responsedict:
        status = responsedict["status"]
        if status == "success":
            return True
    return False


def createAddressGroup(session, urlstub, scope, addressgroup, blacklistnames, csrf):
    data = addressgroup

    headers = {"Content-Type": "application/json",
               "X-CSRFTOKEN": csrf}

    proxies = {
        # 'http': 'http://localhost:8080',
        # 'https': 'http://localhost:8080'
    }
    addressGroupExists = doesAddressGroupExist(session, urlstub, scope, addressgroup, csrf)
    if addressGroupExists:
        print(f'\t{addressgroup["name"]} exists, updating...', end=" ")
        response = session.put(
            urlstub + f'/api/v2/cmdb/firewall/addrgrp/{addressgroup["name"]}?datasource=1&vdom=' + scope, json=data,
            headers=headers, proxies=proxies, verify=False)
    else:
        data = {
            "name": "autoban-group1",
            "member": blacklistnames
        }
        print(f'\t{addressgroup["name"]} does not exist, creating...', end=" ")
        response = session.post(urlstub + "/api/v2/cmdb/firewall/addrgrp?datasource=1&vdom=" + scope, json=data,
                                headers=headers, proxies=proxies, verify=False)

    responsedict = json.loads(response.text)
    status = responsedict["status"]
    print(status)


def createAddress(session, urlstub, scope, address, bannedlist, csrf):
    data = address

    headers = {"Content-Type": "application/json",
               "X-CSRFTOKEN": csrf}

    proxies = {
        # 'http': 'http://localhost:8080',
        # 'https': 'http://localhost:8080'
    }
    addressExists = doesAddressExist(session, urlstub, scope, address, csrf)
    if addressExists:
        print(f'\t{address["subnet"]} exists, updating...', end=" ")
        response = session.put(urlstub + f'/api/v2/cmdb/firewall/address/{address["name"]}?datasource=1&vdom=' + scope,
                               json=data, headers=headers, proxies=proxies, verify=False)
    else:
        print(f'\t{address["subnet"]} does not exist, creating...', end=" ")
        response = session.post(urlstub + "/api/v2/cmdb/firewall/address?datasource=1&vdom=" + scope, json=data,
                                headers=headers, proxies=proxies, verify=False)

    responsedict = json.loads(response.text)
    status = responsedict["status"]
    print(status)
    if status == "success":
        shortaddr = {"name": address["name"]}
        if len(bannedlist) < 600:
            if shortaddr not in bannedlist:
                bannedlist.append(shortaddr)
                print(f'\tAdded {shortaddr["name"]} to blacklist')
    return bannedlist


def getAddressGroup(session, urlstub, scope):
    response3 = session.get(urlstub + "/api/v2/cmdb/firewall/addrgrp?scope=" + scope, verify=False)
    addresses = json.loads(response3.text)
    return addresses


def getAddresses(session, urlstub, scope):
    response3 = session.get(urlstub + "/api/v2/cmdb/firewall/address?scope=" + scope, verify=False)
    addresses = json.loads(response3.text)
    return addresses


def loadBlacklistAddresses():
    f = open('blacklist.json', "r")
    blacklist = json.loads(f.read())
    return blacklist


def makeBlacklist():
    iplist = []
    ipfile = os.getenv("ipfile")
    with open(ipfile) as f:
        lines = f.readlines()
        for line in lines:
            linedict = {"name": "autoban-" + line.replace("\n", ""), "subnet": line.replace("\n", "") + "/32"}
            iplist.append(linedict)
    return iplist


def processDevice(fwinfo, userName, password):
    warnings.simplefilter('ignore', InsecureRequestWarning)
    blacklist = makeBlacklist()

    headers = {
        "User-Agent": "Mozilla",
        "X-Requested-With": "MrPython",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = "ajax=1&username=" + userName + "&secretkey=" + password
    firewallIP = "192.168.1.1"
    port = "443"
    scope = "global"
    if "ip" in fwinfo:
        firewallIP = fwinfo["ip"]
    if "port" in fwinfo:
        port = str(fwinfo["port"])
    if "scope" in fwinfo:
        scope = fwinfo["scope"]

    session = requests.Session()

    urlstub = "https://" + firewallIP + ":" + port
    proxies = {
        # 'http': 'http://localhost:8080',
        # 'https': 'http://localhost:8080'
    }
    # Login to device
    session.post(url=urlstub + "/logincheck",
                 headers=headers, verify=False, proxies=proxies, data=data)
    cookies = session.cookies.get_dict()
    csrf = cookies["ccsrftoken"].replace('"', '')

    print(f'Begin: {firewallIP}')
    blacklistedaddresses = getAddressObjects(session, urlstub, scope, csrf)
    for address in blacklist:
        blacklistedaddresses = createAddress(session, urlstub, scope, address, blacklistedaddresses, csrf)
    addressGroup = {"name": "autoban-group1"}
    addressGroupExists = doesAddressGroupExist(session, urlstub, scope, addressGroup, csrf)
    if addressGroupExists:
        print("\tGroup exists")
        createAddressGroup(session, urlstub, scope, addressGroup, blacklistedaddresses, csrf)

    else:
        print("\tGroup does not exist.")
        createAddressGroup(session, urlstub, scope, addressGroup, blacklistedaddresses, csrf)
    print(f'End: {firewallIP}')


def main():
    username = os.getenv("username")
    password = os.getenv("password")
    ips = json.loads(os.getenv("devicelist"))
    for theip in ips:
        processDevice(theip, username, password)


if __name__ == '__main__':
    main()
