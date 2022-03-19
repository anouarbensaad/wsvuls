import requests
import json
import re
import sys
from regex import CF_PARSE_SUB_AND_DOMAIN,CF_IP
from gen_proxies import proxies_chain
end = '\033[1;0m'
red = '\033[1;91m'
green = '\033[1;92m'
f = open('../db/vulners.json')
DB_LOAD = json.load(f)
URL = DB_LOAD["base"]["cloudFlare"]["url"]+DB_LOAD["base"]["cloudFlare"]["endpoint"]
SCANNER = DB_LOAD["base"]["cloudFlare"]["url"]+DB_LOAD["base"]["cloudFlare"]["scanner"]
def parse_sub_and_domain(data):
    matched = re.findall(CF_PARSE_SUB_AND_DOMAIN,data)
    try:
        return matched
    except Exception as err:
        return None

def wide_scan(target,ip,proxy):
    params = {
        "resource": "hosts",
        "sort": "RELEVANCE",
        "per_page": "25",
        "virtual_hosts":"EXCLUDE",
        "q": target
    }
    res = requests.get(SCANNER+ip,params=params,proxies=proxy)
    return res.text

def parse_ip(data):
    matched = re.findall(CF_IP,data)
    try:
        return matched
    except Exception as err:
        return None

def cloud_grap(url,target):
    success = False
    temp_proxies = []
    ipaddrs = None
    for p in proxies_chain():
        temp_proxies.append(p)
    while success == False:
        for p in temp_proxies:
            proxy = {
                "https": p
            }
            params = {
                "resource":"hosts",
                "sort":"RELEVANCE",
                "per_page":"25",
                "virtual_hosts":"EXCLUDE",
                "q":target
            }
            try:
                res = requests.get(url,params=params,timeout=5,proxies=proxy)
                if parse_ip(res.text) is not None and len(parse_ip(res.text)) > 0:
                    print("%sSUCCESS PARSE:%s"%(green,end))
                    for ipp in parse_ip(res.text):
                        print(ipp)
                    success = True
                    break
            except Exception as error:
                print("%sPROXY FAIL: %s%s"%(red,error,end))
    return ipaddrs

def get_ips_data(ips):
    for ip in ips:
        for proxy in proxies_chain():
            try:
                print(wide_scan(None,ip,proxy))
            except Exception as error:
                print("%sPROXY FAIL: %s%s"%(red,p,end))

cloud_grap(URL,"")