import requests
import re
import sys
import argparse
import hashlib
import uuid
import json

# get regular expressions compiles.
from modules.regex import (
	GETBYTEIN,
	COUNT_REQUESTS,
	FULLY_LOADED,
	BYTEINDOC,
	REQUEST_DOC,
	DOC_COMPLETE,
	TBLOCKTIME,
	CUMULATIVE_LAYOUT_SHIFT,
	LARGEST_CONTENT_FULPAINT,
	SPEED_INDEX,
	FIRST_CONTENT_FULPAINT,
	START_RENDER,
	TTFB)

if sys.version_info < (3, 0):
    raise Exception("This program requires Python 3.0 or greater")

class Stats:
    def __init__(self,url,scanner,target=None):
        '''
        this class to get info of requests

        :url: the sync url and endpoint
        :scanner: the scan-endpoint recieved.
        :target: url target. 
        '''

        self._url = url
        self._scanner = scanner
        self._target = target
    
    def _set_target_(self,target):
        '''
        setter method to set the target url.
        '''
        self._target = target
    
    def generate_phpsession(self):
        '''
        generate a php session to set it into cookie.
        '''
        nosalted="anouarbensaad"
        result = hashlib.md5(nosalted.encode())
        return str("b"+result.hexdigest())

    def __load__(self):
        '''
        this method to get html data to extract token from it.
        '''
        return requests.get(self._url,headers={
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:97.0) Gecko/20100101 Firefox/97.0"
            }).text

    def getnonce(self,data):
        '''
        using regular expression to get nonce_token from html.
        '''
        regexp=re.compile(r'\"nonce\":\"(.+)\"')
        matched=re.search(regexp,data)
        return matched.group(1)

    def post_wvscan(self,nonce):
        '''
        set target to the scanner url.
        '''

        sess_id = uuid.uuid1()
        data={
            "action":"web_scanner",
            "url":self._target,
            "nonce_code":nonce
        }
        anonumous_session="\""+str(sess_id)+"\""
        cookies= {
            "ajs_anonymous_id": anonumous_session,
            "PHPSESSID": self.generate_phpsession(),
            "vid": str(sess_id)
        }
        headers={
            "X-Requested-With": "XMLHttpRequest",
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:97.0) Gecko/20100101 Firefox/97.0",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Accept": "*/*",
            "Referer": self._url,
            "Connection": "keep-alive"
        }
        posted=requests.post(self._scanner,headers=headers,data=data,cookies=cookies)
        return posted.json()

    def _get_averages_(self,res):
        text="...."
        analysed=False
        response=None
        print("AnalyseID: %s " % (res["data"]["testId"]))
        analyseURL = res["data"]["jsonUrl"]
        print("\n[ Start Scanning For %s]\n" % (self._target))
        while not analysed:
            res_analyse = requests.get(analyseURL)
            try:
                estimation = res_analyse.json()["statusText"]
                for x in text:
                    sys.stdout.write(x)
                    sys.stdout.write("")
                    sys.stdout.flush() 
                if estimation == "Test Complete":
                    analysed=True
                    return res_analyse.json()["data"]["runs"]["1"]["firstView"]["pages"]["details"]
            except KeyError as err:
                analysed=True
                return res_analyse.json()["data"]["runs"]["1"]["firstView"]["pages"]["details"]

    def netspeed(self,url):
        print("\n")
        response = requests.get(url)
        return response.text

    def _get_ttfb_(self,data):
        matched=re.search(TTFB,data)
        try:
            ttfb_value = matched.group(1)
            return ttfb_value
        except Exception as err:
            return None

    def _get_start_render_(self,data):
        matched=re.search(START_RENDER,data)
        try:
            start_render = matched.group(1)
            return start_render
        except Exception as err:
            return None

    def _get_first_content_fulpaint_(self,data):
        matched=re.search(FIRST_CONTENT_FULPAINT,data)
        try:
            getfirstContentfulPaint = matched.group(1)
            return getfirstContentfulPaint
        except Exception as error:
            return None

    def _get_speed_index_(self,data):
        matched=re.search(SPEED_INDEX,data)
        try:
            SpeedIndex = matched.group(1)
            return SpeedIndex
        except Exception as error:
            return None

    def _get_largest_content_fulpaint_(self,data):
        matched=re.search(LARGEST_CONTENT_FULPAINT,data)
        try:
            LCP = matched.group(1)
            return LCP
        except Exception as error:
            return None

    def _get_cumulative_layout_shift_(self,data):
        matched=re.search(CUMULATIVE_LAYOUT_SHIFT,data)
        try:
            LCP = matched.group(1)
            return LCP
        except Exception as error:
            return None

    def _get_total_block_time_(self,data):
        matched=re.search(TBLOCKTIME,data)
        try:
            TBT = matched.group(1)
            return TBT
        except Exception as error:
            return None

    def _get_doc_complete_(self,data):
        matched=re.search(DOC_COMPLETE,data)
        try:
            DC = matched.group(1)
            return DC
        except Exception as error:
            return None

    def _get_request_doc_(self,data):
        matched=re.search(REQUEST_DOC,data)
        try:
            RD = matched.group(1)
            return RD
        except Exception as error:
            return None

    def _get_byte_indoc_(self,data):
        matched=re.search(BYTEINDOC,data)
        try:
            BID = matched.group(1)
            return BID
        except Exception as error:
            return None

    def _get_fully_loaded_(self,data):
        matched=re.search(FULLY_LOADED,data)
        try:
            FL = matched.group(1)
            return FL
        except Exception as err:
            return None

    def _get_request_count_(self,data):
        matched=re.search(COUNT_REQUESTS,data)
        try:
            RC = matched.group(1)
            return RC
        except Exception as err:
            return None

    def _get_byte_in_(self,data):
        matched=re.search(GETBYTEIN,data)
        try:
            BI = matched.group(1)
            return BI
        except Exception as err:
            return None