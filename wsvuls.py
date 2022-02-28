import requests
import re
import sys
import argparse
import hashlib
import uuid
import json

f = open('./db/vulners.json')
loaded = json.load(f)

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
	regexp = r'<td id=\"TTFB\" valign=\"middle\">(.+)<span class=\"units\">(.+)</span></td>'
	rempiled = re.compile(regexp)
	matched=re.search(rempiled,data)
	ttfb_value = matched.group(1)
	return ttfb_value

def getStartRender(data):
	regexp = r'<td id=\"StartRender\" valign=\"middle\">(.+)<span class=\"units\">(.+)</span></td>'
	rempiled = re.compile(regexp)
	matched=re.search(rempiled,data)
	start_render = matched.group(1)
	return start_render

def getfirstContentfulPaint(data):
	regexp = r'<td id=\"firstContentfulPaint\" valign=\"middle\">(.+)<span class=\"units\">(.+)</span></td>'
	rempiled = re.compile(regexp)
	matched=re.search(rempiled,data)
	getfirstContentfulPaint = matched.group(1)
	return getfirstContentfulPaint

def getSpeedIndex(data):
	regexp = r'<td id=\"SpeedIndex\" valign=\"middle\">(.+)<span class=\"units\">(.+)</span></td>'
	rempiled = re.compile(regexp)
	matched=re.search(rempiled,data)
	SpeedIndex = matched.group(1)
	return SpeedIndex

def getLargestContentfulPaint(data):
	regexp = r'<td id="chromeUserTiming.LargestContentfulPaint" class=".+" valign="middle">(.+)<span class="units">S</span></td>'
	rempiled = re.compile(regexp)
	matched=re.search(rempiled,data)
	LCP = matched.group(1)
	return LCP

def getCumulativeLayoutShift(data):
	regexp = r'<td id="chromeUserTiming.CumulativeLayoutShift" class=".+" valign="middle">(.+)</td>'
	rempiled = re.compile(regexp)
	matched=re.search(rempiled,data)
	LCP = matched.group(1)
	return LCP
def getTotalBlockingTime(data):
	regexp = r'<td id="TotalBlockingTime" class=".+" valign="middle"><span class="units comparator">.+</span>(.+)<span class="units">S</span></td>'
	rempiled = re.compile(regexp)
	matched=re.search(rempiled,data)
	TBT = matched.group(1)
	return TBT

def getDocComplete(data):
	regexp = r'<td id="DocComplete" class="border" valign="middle">(.+)<span class="units">S</span></td>'
	rempiled = re.compile(regexp)
	matched=re.search(rempiled,data)
	DC = matched.group(1)
	return DC

def getRequestDoc(data):
	regexp = r'<td id="RequestsDoc" valign="middle">(.+)</td>'
	rempiled = re.compile(regexp)
	matched=re.search(rempiled,data)
	RD = matched.group(1)
	return RD

def getBytesInDoc(data):
	regexp = r'<td id="BytesInDoc" valign="middle">(.+)<span class="units">KB</span></td>'
	rempiled = re.compile(regexp)
	matched=re.search(rempiled,data)
	BID = matched.group(1)
	return BID

def getFullyLoaded(data):
	regexp = r'<td id="FullyLoaded" class="border" valign="middle">(.+)<span class="units">S</span></td>'
	rempiled = re.compile(regexp)
	matched=re.search(rempiled,data)
	FL = matched.group(1)
	return FL

def getRequestsCount(data):
	regexp = r'<td id="Requests" valign="middle">(.+)</td>'
	rempiled = re.compile(regexp)
	matched=re.search(rempiled,data)
	RC = matched.group(1)
	return RC

def getByteIn(data):
	regexp = r'<td id="BytesIn" valign="middle">(.+)<span class="units">KB</span></td>'
	rempiled = re.compile(regexp)
	matched=re.search(rempiled,data)
	BI = matched.group(1)
	return BI

def requestsMapper(data):
	regx_reqid = r'<th class="reqNum oddRender"><a href=".+">(.+)</a></th>'
	regx_requests = r'<td class="reqUrl evenRender"><a rel="nofollow" href="(.+)">.+</a></td>'
	regx_startime = r'<td class="reqStart oddRender">(.+)</td>'
	regx_type = r'<td class="reqMime oddRender">(.+)</td>'
	regx_dns = r'<td class="reqDNS oddRender">(.+)</td>'
	regx_ssl = r'<td class="reqSSL oddRender">(.+)</td>'
	regx_code = r'<td class="reqResult oddRender">(.+)</td>'
	reg0_compile = re.compile(regx_reqid)
	reg1_compile = re.compile(regx_requests)
	reg2_compile = re.compile(regx_startime)
	reg3_compile = re.compile(regx_type)
	reg4_compile = re.compile(regx_dns)
	reg5_compile = re.compile(regx_ssl)
	reg6_compile = re.compile(regx_code)
	req_id=re.findall(reg0_compile,data)
	urls=re.findall(reg1_compile,data)
	times=re.findall(reg2_compile,data)
	types=re.findall(reg3_compile,data)
	dns_time=re.findall(reg4_compile,data)
	ssl_time=re.findall(reg5_compile,data)
	code_status=re.findall(reg6_compile,data)
	for i in range(len(urls)):
		print("\n------------------------------------------")
		print("RequestID: %s" % (req_id[i]))
		print("Resource: %s" % (urls[i]))
		print("Request Start: %s" % (times[i]))
		print("Content Type: %s" % (types[i]))
		print("DNS Lookup: %s" % (dns_time[i]))
		print("SSL Negotiation: %s" % (ssl_time[i]))
		print("Error/Status Code: %s" % (code_status[i]))

process_load = getAverages(postwvscan(getnonce(res.text)))
data_content = netspeed(process_load)
# print(data_content)
print("First Byte : {0} Seconds".format(getTTFB(data_content)))
print("Start Render : {0} Seconds".format(getStartRender(data_content)))
print("FCP : {0} Seconds".format(getfirstContentfulPaint(data_content)))
print("Speed Index : {0} Seconds".format(getSpeedIndex(data_content)))
print("LCP : {0} Seconds".format(getLargestContentfulPaint(data_content)))
print("CLS : {0}".format(getCumulativeLayoutShift(data_content)))
print("TBT : {0} Seconds".format(getTotalBlockingTime(data_content)))
print("DC Time : {0} Seconds".format(getDocComplete(data_content)))
print("DC Requests : {0}".format(getRequestDoc(data_content)))
print("DC Bytes : {0} KiloBytes".format(getBytesInDoc(data_content)))
print("Time : {0} Seconds".format(getFullyLoaded(data_content)))
print("Requests : {0}".format(getRequestsCount(data_content)))
print("Total Bytes : {0} KiloBytes".format(getByteIn(data_content)))
if (MAPPER_ARG):
	print("\n[ Request Details ]")
	print(requestsMapper(data_content))