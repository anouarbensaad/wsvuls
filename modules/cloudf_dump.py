import requests
import json
import re
import sys
from regex import CF_PARSE_SUB_AND_DOMAIN,CF_IP
from gen_proxies import proxies_chain
end = '\033[1;0m'
red = '\033[1;91m'

f = open('../db/vulners.json')
DB_LOAD = json.load(f)
URL = DB_LOAD["base"]["cloudFlare"]["url"]+DB_LOAD["base"]["cloudFlare"]["endpoint"]

def parse_sub_and_domain(data):
    matched = re.findall(CF_PARSE_SUB_AND_DOMAIN,data)
    try:
        return matched
    except Exception as err:
        return None

def parse_ip(data):
    matched = re.findall(CF_IP,data)
    try:
        return matched
    except Exception as err:
        return None

def cloud_grap(url,target):
    success = False
    while not success:
        for p in proxies_chain():
            proxy = {
                "https": p
            }
            params = {
                "resource":"hosts",
                "sort":"RELEVANCE",
                "per_page":"25",
                "virtual_hosts":"EXCLUDE",
                "q":url
            }
            try:
                res = requests.get(url,params=params,timeout=4,proxies=proxy)
                if parse_ip(res.text) is not None:
                    print(parse_ip(res.text))
                if parse_sub_and_domain(res.text) is not None:
                    success = True
                    print(parse_sub_and_domain(res.text))
                    break
            except Exception as error:
                print("%sProxy FAIL: %s%s"%(red,p,end))

# cloud_grap(URL,"")