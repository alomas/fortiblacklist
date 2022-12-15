import json
import os

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import warnings

def getlogintoken():
    print("getlogintoken()")

def getWanIP():
    print("printWanIP")

def readProperties():
    print("readProperties()")

def getLoginToken(firewallIP, port, userName, password):
    print("processDevice()")

def processDevice(firewallIP, port, userName, password):
    warnings.simplefilter('ignore', InsecureRequestWarning)
    headers = {
        "User-Agent": "Mozilla",
        "X-Requested-With": "MrPython",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = "ajax=1&username=" + userName + "&secretkey=" + password
    session = requests.Session()
    urlstub = "https://" + firewallIP + ":" + port
    response = session.post(url=urlstub + "/logincheck",
                             headers=headers, verify=False, data=data)
    cookies=session.cookies
    items = cookies.items()
    response2 = session.get(urlstub + "/api/v2/monitor/system/interface/")
    interfaces = json.loads(response2.text)
    wanip = interfaces["results"]["wan1"]["ip"]
    print(f'processDevice() returned {wanip}')
    print(response.text)
def main():
    readProperties()
    ip = os.getenv("ip")
    port = os.getenv("port")
    username = os.getenv("username")
    password = os.getenv("password")

    processDevice(ip, port, username, password)

if __name__ == '__main__':
    main()








