import requests
import re
import sys

from modules.regex import MAPPED_REQUESTS

if sys.version_info < (3, 0):
    raise Exception("This program requires Python 3.0 or greater")

WARN_DEBUG = "WARNING"
REQ_ID  = "REQUEST_ID"
REQ_URL = "REQUEST_URL"
REQ_TYPE = "REQUEST_TYPE"
REQ_START = "REQUEST_START"
REQ_BYTES = "REQUEST_BYTES"
REQ_IP = "REQUEST_IP"

class MapperRequest:
    def __init__(self,data):
        '''
        :_data: get data from stats_analyse.
        '''
        self._data = data
    
    def __mapper__(self):
        '''
        parse all requests and get
        
        :reqUrl: request url
        :reqMime: request time
        :reqStart: time when start.
        :reqDNS: dns time-consumed
        :reqSocket: socket time-consumed
        :reqSSL: ssl handshake time-consumed
        :reqBytes: size of request.
        :reqIP: request ip address.
        '''
        
        requsets = re.findall(MAPPED_REQUESTS,self._data)
        return requsets

    def __parser__(self,content,debug):
        reqs = []
        for REQUEST in content:
            dbglen = len(REQUEST[0].split(" "))
            if (dbglen == 2):
                if( REQUEST[0].split(" ")[0] == "warning" ):
                    reqs.append([
                        (REQ_ID,REQUEST[1],WARN_DEBUG),
                        (REQ_URL,REQUEST[2],WARN_DEBUG),
                        (REQ_TYPE,REQUEST[3],WARN_DEBUG),
                        (REQ_START,REQUEST[4],WARN_DEBUG),
                        (REQ_BYTES,REQUEST[10],WARN_DEBUG),
                        (REQ_IP,REQUEST[13],WARN_DEBUG)
                    ])
            reqs.append([
                (REQ_ID,REQUEST[1]),
                (REQ_URL,REQUEST[2]),
                (REQ_TYPE,REQUEST[3]),
                (REQ_START,REQUEST[4]),
                (REQ_BYTES,REQUEST[10]),
                (REQ_IP,REQUEST[13])	
            ])
        return reqs