import requests
import re
import json
from regex import PROXY_PARSE

f = open('../db/vulners.json')
DB_LOAD = json.load(f)
URL = DB_LOAD["base"]["proxies"]["url"]

def get_proxies():
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:98.0) Gecko/20100101 Firefox/98.0"
    }
    res = requests.get(URL,headers=headers)
    return res.text

def proxies_chain():
    proxies = []
    matched = re.findall(PROXY_PARSE,get_proxies())
    for m in matched:
        proxies.append(m[0]+":"+m[1])
    return proxies