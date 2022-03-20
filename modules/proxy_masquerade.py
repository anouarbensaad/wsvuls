import requests
import re
import json
import sys

from regex import PROXY_PARSE

if sys.version_info < (3, 0):
    raise Exception("This program requires Python 3.0 or greater")

class ProxyMasquerade:
    def __init__(self,url,headers=None):
        '''
        make a request to get list of proxies

        :url: the free-proxy-list url
        :headers: send specefic request headers. 
        '''
        
        self._url = url
        self._headers = headers

    def _set_headers(headers):
        '''
        set headers request.
        '''
        
        self._headers = headers

    def free_proxy_request(self):
        '''
        make request for free-proxy-list url.
        '''
        
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:98.0) Gecko/20100101 Firefox/98.0",
            "Accept":"*/*",
            "Content-Type":"*/*"
        }
        res = requests.get(self._url,headers=headers)
        return res.text

    def proxies_chain(self):
        '''
        using regular expression get
        IPADDRESS:PORT
        '''

        proxies = []
        matched = re.findall(PROXY_PARSE,self.free_proxy_request())
        for m in matched:
            proxies.append(m[0]+":"+m[1])
        return proxies