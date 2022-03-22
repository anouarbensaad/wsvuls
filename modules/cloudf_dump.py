import requests
import json
import re
import sys
import socket

from modules.regex import CF_PARSE_SUB_AND_DOMAIN,CF_IP

if sys.version_info < (3, 0):
    raise Exception("This program requires Python 3.0 or greater")

end = '\033[1;0m'
red = '\033[1;91m'
green = '\033[1;92m'

class CloudDumpException(Exception):
    '''
    Custom CloudDump exception class
    '''
    def __init__(self, msg="CloudDump exception encountered.", dump=None):
        self.msg = msg
    def __str__(self):
        return self.msg

class CloudDump:
    
    def __init__(self,
                url,proxies=None,
                target=None,
                scanner=None):

        '''
        Executes censys analysis and bypass the rate limit using free proxies
        crawled from free-proxy-list

        :url: censys search url.
        :proxies: list of proxies crawled
        :scanner: url when recieve cloudflare ipaddresses and search for adresses.
        '''

        self._url = url
        self._proxies = proxies
        self._scanner = scanner
        self._target = target

    def _set_scanner_(self, scanner):
        '''
        set scanner property url for a specific target.
        '''
        
        self._scanner = scanner

    def _set_proxies_(self,proxies):
        '''
        set proxies property crawled from free-proxy-list
        '''

        self._proxies = proxies

    def _set_target_(self,target):
        '''
        set proxies property crawled from free-proxy-list
        '''

        self._target = target

    def _graps_(self):
        '''
        This method is used to make a crawling-loadbalance
        
        so we can receive content from censys and get the addresses which 
        can be bypassed the rate-limit
        '''

        success = False
        temp_proxies = []
        ipaddrs = []
        # set proxies to array.
        [temp_proxies.append(proxy) for proxy in self._proxies]
        # repeating requests until getting the data
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
                    "q":self._target
                }
                try:
                    res = requests.get(self._url,params=params,timeout=5,proxies=proxy)
                    # check ip addresses found or not.
                    if self.parse_ip(res.text) is not None and len(self.parse_ip(res.text)) > 0:
                        [ipaddrs.append(ipp) for ipp in self.parse_ip(res.text)]
                        success = True
                        break
        
                except requests.exceptions.HTTPError as errh:
                    print(f"{red}ProxyError{end}: {p} -> a http Error occurred")

                except requests.exceptions.ConnectionError as errc:
                    print(f"{red}ProxyError{end}: {p} -> an error Connecting to the web occurred")
                
                except requests.exceptions.Timeout as errt:
                    print(f"{red}ProxyError{end}: {p} -> a timeout Error occurred")
                
                except requests.exceptions.RequestException as err:
                    print(f"{red}ProxyError{end}: {p} -> an unknown Error occurred")
        
        print(f"\n{green}Found{end} -> {ipaddrs}\n")
        return ipaddrs

    def parse_domains(self,data):
        '''
        parse subdomains from specefic url.
        '''

        matched = re.findall(CF_PARSE_SUB_AND_DOMAIN,data)
        try:
            return matched
        except Exception as err:
            return None

    def wide_scan(self,ipadresses,target):
        '''
        search data from ip.
        :ip: the target ip crawled.
        '''

        ports = []
        comp = {}
        temp_proxies = [] # array proxies.
        [temp_proxies.append(proxy) for proxy in self._proxies]
        for ip in ipadresses:
            success = False
            while success == False:
                for p in temp_proxies:
                    proxy = {
                        "https": p
                    }
                    params = {
                        "resource": "hosts",
                        "sort": "RELEVANCE",
                        "per_page": "25",
                        "virtual_hosts":"EXCLUDE",
                        "q": self._target
                    }
                    try:
                        res = requests.get(self._scanner+ip,params=params,proxies=proxy)
                        print(res)
                        success = True
                        break
                    except Exception as err:
                        print(err)

    def parse_ip(self,data):
        '''
        parse ip addresses, from data content.
        '''

        matched = re.findall(CF_IP,data)
        try:
            return matched
        except Exception as err:
            return None
