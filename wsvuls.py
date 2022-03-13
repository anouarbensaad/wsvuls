
# author: anouarbensaad

from __future__ import print_function

import requests
import re
import sys
import argparse
import hashlib
import uuid
import json

# get regular expressions compiles.
from modules.regex import (
	MAPPED_REQUESTS,
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

from modules.constants import (
	WARN_DEBUG,
	REQ_ID,
	REQ_URL,
	REQ_TYPE,
	REQ_START,
	REQ_BYTES,
	REQ_IP)

# import endpoint and url.
f = open('./db/vulners.json')
loaded = json.load(f)

# colors.
end = '\033[1;0m'
R = '\033[1;91m'
G = '\033[1;92m'

URL = loaded["base"]["url"]+loaded["base"]["endpoint"]
sync = loaded["base"]["url"]+loaded["base"]["scanner"]

def generate_phpsession():
	nosalted="anouarbensaad"
	result = hashlib.md5(nosalted.encode())
	return str("b"+result.hexdigest())

def parser_error(errmsg):
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print(R + "Error: " + errmsg + W)
    sys.exit()

def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython3 ' + sys.argv[0] + " -u google.com")
    parser.error = parser_error
    parser._optionals.title = "\nOPTIONS"
    parser.add_argument('-u', '--url', help="url target to scan")
    parser.add_argument('-m', '--mapper', help="map all requests details...", dest='mapper',action="store_true")
    return parser.parse_args()

args = parse_args()
URL_ARG = args.url
MAPPER_ARG = args.mapper


def getnonce(data):
	regexp=re.compile(r'\"nonce\":\"(.+)\"')
	matched=re.search(regexp,data)
	print("retrieve token",matched.group(1))
	return matched.group(1)

def postwvscan(nonce):
	sess_id = uuid.uuid1()
	data={
	"action":"web_scanner",
	"url":URL_ARG,
	"nonce_code":nonce
	}
	anonumous_session="\""+str(sess_id)+"\""
	cookies= {
	"ajs_anonymous_id": anonumous_session,
	"PHPSESSID": generate_phpsession(),
	"vid": str(sess_id)
	}
	headers={
	"X-Requested-With": "XMLHttpRequest",
	"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:97.0) Gecko/20100101 Firefox/97.0",
	"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
	"Accept": "*/*",
	"Host": "snyk.io",
	"Referer": URL,
	"Connection": "keep-alive"
	}
	posted=requests.post(sync,headers=headers,data=data,cookies=cookies)
	return posted.json()

HEADERS={
"Content-Type": "*/*",
"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:97.0) Gecko/20100101 Firefox/97.0",
"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
}
res = requests.get(URL,headers=HEADERS);

def getAverages(res):
	text="...."
	analysed=False
	response=None
	print("AnalyseID: %s " % (res["data"]["testId"]))
	analyseURL = res["data"]["jsonUrl"]
	print("\n[ Start Scanning For %s]\n" % (URL_ARG))
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

def netspeed(url):
	print("\n")
	response = requests.get(url)
	return response.text

def getTTFB(data):
	matched=re.search(TTFB,data)
	try:
		ttfb_value = matched.group(1)
		return ttfb_value
	except Exception as err:
		return None

def getStartRender(data):
	matched=re.search(START_RENDER,data)
	try:
		start_render = matched.group(1)
		return start_render
	except Exception as err:
		return None

def getfirstContentfulPaint(data):
	matched=re.search(FIRST_CONTENT_FULPAINT,data)
	try:
		getfirstContentfulPaint = matched.group(1)
		return getfirstContentfulPaint
	except Exception as error:
		return None

def getSpeedIndex(data):
	matched=re.search(SPEED_INDEX,data)
	try:
		SpeedIndex = matched.group(1)
		return SpeedIndex
	except Exception as error:
		return None

def getLargestContentfulPaint(data):
	matched=re.search(LARGEST_CONTENT_FULPAINT,data)
	try:
		LCP = matched.group(1)
		return LCP
	except Exception as error:
		return None

def getCumulativeLayoutShift(data):
	matched=re.search(CUMULATIVE_LAYOUT_SHIFT,data)
	try:
		LCP = matched.group(1)
		return LCP
	except Exception as error:
		return None

def getTotalBlockingTime(data):
	matched=re.search(TBLOCKTIME,data)
	try:
		TBT = matched.group(1)
		return TBT
	except Exception as error:
		return None

def getDocComplete(data):
	matched=re.search(DOC_COMPLETE,data)
	try:
		DC = matched.group(1)
		return DC
	except Exception as error:
		return None

def getRequestDoc(data):
	matched=re.search(REQUEST_DOC,data)
	try:
		RD = matched.group(1)
		return RD
	except Exception as error:
		return None

def getBytesInDoc(data):
	matched=re.search(BYTEINDOC,data)
	try:
		BID = matched.group(1)
		return BID
	except Exception as error:
		return None

def getFullyLoaded(data):
	matched=re.search(FULLY_LOADED,data)
	try:
		FL = matched.group(1)
		return FL
	except Exception as err:
		return None

def getRequestsCount(data):
	matched=re.search(COUNT_REQUESTS,data)
	try:
		RC = matched.group(1)
		return RC
	except Exception as err:
		return None

def getByteIn(data):
	matched=re.search(GETBYTEIN,data)
	try:
		BI = matched.group(1)
		return BI
	except Exception as err:
		return None

def requestsMapper(data):
	find_requests = re.findall(MAPPED_REQUESTS,data)
	return find_requests

def parse_requests(content,debug):
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

process_load = getAverages(postwvscan(getnonce(res.text)))
data_content = netspeed(process_load)
# print(data_content)
if getTTFB(data_content) is not None:
	print(f"First Byte : {getTTFB(data_content)} Seconds")
if getStartRender(data_content) is not None:
	print(f"Start Render : {getStartRender(data_content)} Seconds")
if getfirstContentfulPaint(data_content) is not None:
	print(f"FCP : {getfirstContentfulPaint(data_content)} Seconds")
if getSpeedIndex(data_content) is not None:
	print(f"Speed Index : {getSpeedIndex(data_content)} Seconds")
if getLargestContentfulPaint(data_content) is not None:
	print(f"LCP : {getLargestContentfulPaint(data_content)} Seconds")
if getCumulativeLayoutShift(data_content) is not None:
	print(f"CLS : {getCumulativeLayoutShift(data_content)}")
if getTotalBlockingTime(data_content) is not None:
	print(f"TBT : {getTotalBlockingTime(data_content)} Seconds")
if getDocComplete(data_content) is not None:
	print(f"DC Time : {getDocComplete(data_content)} Seconds")
if getRequestDoc(data_content) is not None:
	print(f"DC Requests : {getRequestDoc(data_content)}")
if getBytesInDoc(data_content) is not None:
	print(f"DC Bytes : {getBytesInDoc(data_content)} KiloBytes")
if getFullyLoaded(data_content) is not None:
	print(f"Time : {getFullyLoaded(data_content)} Seconds")
if getRequestsCount(data_content) is not None:
	print(f"Requests : {getRequestsCount(data_content)}")
if getByteIn(data_content) is not None:
	print(f"Total Bytes : {getByteIn(data_content)} KiloBytes")
if (MAPPER_ARG):
	print("\n[ Request Details ]")
	for maps in parse_requests(requestsMapper(data_content),""):
		print(f"{maps[0]}: {maps[1]}")
		print("−−−−−−−−−−−−−−")