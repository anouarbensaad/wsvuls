import requests
import json
import re
import sys
import socket
from modules.proxy_masquerade import ProxyMasquerade
from modules.regex import (CF_PARSE_SUB_AND_DOMAIN,
                        CF_IP,
                        PROVIDER_IP,
                        ROUTING_IP,
                        PROTOCOLS_IP,
                        OS_IP)

if sys.version_info < (3, 0):
    raise Exception("This program requires Python 3.0 or greater")

end = '\033[1;0m'
red = '\033[1;91m'
green = '\033[1;92m'
yellow = '\033[1;93m'  # yellow
blue = '\033[1;94m'

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
        
        print(f"{yellow}Available Proxies:{end} {len(self._proxies)}")
        
        success = False
        temp_proxies = []
        ipaddrs = []
        used_proxy = 0
        # set proxies to array.
        [temp_proxies.append(proxy) for proxy in self._proxies]
        # repeating requests until getting the data
        while success == False:
            if used_proxy == len(self._proxies):
                self._refresh_proxies_()
                print(f"{yellow}Available Proxies:{end} {len(self._proxies)}")
                used_proxy = 0
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
                    res = requests.get(self._url,params=params,timeout=10,proxies=proxy)
                    # check ip addresses found or not.
                    if self.parse_ip(res.text) is not None and len(self.parse_ip(res.text)) > 0:
                        [ipaddrs.append(ipp) for ipp in self.parse_ip(res.text)]
                        success = True
                        break

                except Exception as err:
                    error = str(err)
                    rmatched = re.search(re.compile(r"Caused\s+by\s+.+[\',|,]\s+(?:\')?(?:\w+\(\')?(.+)[\']"),error)
                    print(f"{red}ProxyError{end}: {p}\t\t->\t{rmatched.group(1)}")

        print(f"\n{green}Found{end} -> {ipaddrs}\n")
        return ipaddrs

    def _refresh_proxies_(self):
        print(f"{blue}[*] Refresh Proxies{end}")
        proxy_obj = ProxyMasquerade(url="https://free-proxy-list.net/")
        self._set_proxies_(proxy_obj.proxies_chain())

    def parse_domains(self,data):
        '''
        parse subdomains from specefic url.
        '''

        matched = re.findall(CF_PARSE_SUB_AND_DOMAIN,data)
        try:
            return matched
        except Exception as err:
            return None

    def __get_protocols__(self,data):
        matches = re.findall(PROTOCOLS_IP,data)
        try:
            return matches
        except Exception as err:
            return None

    def __get_os__(self,data):
        matched = re.search(OS_IP,data)
        try:
            return matched.group(1)
        except Exception as err:
            return None

    def __get_routing__(self,data):
        routing = []
        matched = re.search(ROUTING_IP,data)
        try:
            routing.append(matched.group(1),matched.group(2))
            return routing
        except Exception as err:
            return None
    
    def __get_provider__(self,data):
        matched = re.search(PROVIDER_IP,data)
        try:
            return matched.group(1)
        except Exception as err:
            return None

    def wide_scan(self,ipadresses,target):
        '''
        search data from ip.
        :ip: the target ip crawled.
        '''
        
        print(f"{yellow}Available Proxies:{end} {len(self._proxies)}")
        
        ports = []
        comp = {}
        used_proxy = 0
        temp_proxies = [] # array proxies.
        [temp_proxies.append(proxy) for proxy in self._proxies]
        for ip in ipadresses:
            success = False
            while success == False:
                if used_proxy == len(self._proxies):
                    self._refresh_proxies_()
                    print(f"{yellow}Available Proxies:{end} {len(self._proxies)}")
                    used_proxy = 0
                for p in temp_proxies:
                    proxy = {
                        "https": p
                    }
                    try:
                        res = requests.get(self._scanner+ip,proxies=proxy,timeout=10)
                        print("PROTOCOLS:\n")
                        for p in self.__get_protocols__(res.text):
                            print(p)
                        print("OS:\n")
                        print(self.__get_os__(res.text))
                        print("ROUTING:\n")
                        print(f"{self.__get_routing__(res.text)[0]} via {self.__get_routing__(res.text)[1]}")
                        print("PROVIDER:\n")
                        print(self.__get_provider__(res.text))
                        success = True
                        break

                    except Exception as err:
                        error = str(err)
                        rmatched = re.search(re.compile(r"Caused\s+by\s+.+[\',|,]\s+(?:\')?(?:\w+\(\')?(.+)[\']"),error)
                        print(f"{red}ProxyError{end}: {p}\t\t->\t{rmatched.group(1)}")


    def scan_ip(self,ip):
        '''
        search data from ip.
        '''

        print(f"{yellow}Available Proxies:{end} {len(self._proxies)}")
        ports = []
        comp = {}
        temp_proxies = [] # array proxies.
        used_proxy = 0
        [temp_proxies.append(proxy) for proxy in self._proxies]
        success = False
        while success == False:
            if used_proxy == len(self._proxies):
                self._refresh_proxies_()
                print(f"{yellow}Available Proxies:{end} {len(self._proxies)}")
                used_proxy = 0
            for p in temp_proxies:
                used_proxy = used_proxy+1
                proxy = {
                    "https": p
                }
                try:
                    res = requests.get(self._scanner+ip,proxies=proxy,timeout=10)
                    print("PROTOCOLS:\n")
                    for p in self.__get_protocols__(res.text):
                        print(p)
                    print("OS:\n")
                    print(self.__get_os__(res.text))
                    print("ROUTING:\n")
                    print(f"{self.__get_routing__(res.text)[0]} via {self.__get_routing__(res.text)[1]}")
                    print("PROVIDER:\n")
                    print(self.__get_provider__(res.text))
                    success = True
                    break

                except Exception as err:
                    error = str(err)
                    rmatched = re.search(re.compile(r"Caused\s+by\s+.+[\',|,]\s+(?:\')?(?:\w+\(\')?(.+)[\']"),error)
                    print(f"{red}ProxyError{end}: {p}\t\t->\t{rmatched.group(1)}")

    def parse_ip(self,data):
        '''
        parse ip addresses, from data content.
        '''

        matched = re.findall(CF_IP,data)
        try:
            return matched
        except Exception as err:
            return None
