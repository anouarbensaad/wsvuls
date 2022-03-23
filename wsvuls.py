
# author: anouarbensaad

from __future__ import print_function

import requests
import re
import sys
import argparse
import hashlib
import uuid
import json

from common.colors import end,red

from modules.stats import Stats
from modules.mapper import MapperRequest as Mapper
from modules.proxy_masquerade import ProxyMasquerade
from modules.cloudf_dump  import CloudDump

# get constants variables.
from modules.constants import (
	SEPARATOR,
	FIRST_B,
	S_RENDER,
	FCP,
	SPEED_I,
	LCP,
	CLS,
	TBT,
	DCTIME,
	DCREQS,
	DCBYTES,
	TTIME,
	REQSS,
	TOTBYTES,
	KB,
	S
	)

# get commons functions.
from common.printer import logger_p

# import endpoint and url.
f = open('./db/vulners.json')
DB_LOAD = json.load(f)

stat_map_url = DB_LOAD["base"]["statMapper"]["url"]+DB_LOAD["base"]["statMapper"]["endpoint"]
stat_map_scanner = DB_LOAD["base"]["statMapper"]["url"]+DB_LOAD["base"]["statMapper"]["scanner"]
cloud_dump_url = DB_LOAD["base"]["cloudFlare"]["url"]+DB_LOAD["base"]["cloudFlare"]["endpoint"]
cloud_dump_scanner = DB_LOAD["base"]["cloudFlare"]["url"]+DB_LOAD["base"]["cloudFlare"]["scanner"]
proxy_url = DB_LOAD["base"]["proxies"]["url"]

def parser_error(errmsg):
	print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
	print(f"Error: {red}{errmsg}{end}.")
	sys.exit()

def parse_args():
	parser = argparse.ArgumentParser(epilog='\tExample: \r\npython3 ' + sys.argv[0] + " -u google.com")
	subparser = parser.add_subparsers(dest="command") 
	parser.error = parser_error
	# cloud arguments.
	cloud_parser = subparser.add_parser("cloud", help="get data from cloudflare",aliases=['cloud'])
	cloud_parser.add_argument('-d', '--domain',
			help="domain target to scan",
			dest="domain",
			nargs=1)
	cloud_parser.add_argument('-w', '--wide',
			help="wide scan to get all data from cloudflare",
			dest="wide",
			action="store_true")
	cloud_parser.add_argument('--use-proxy',
			help="use proxy when requesting",
			dest="useproxy",
			default=True,
			action="store_true")
	
	# stat arguments
	stat_parser = subparser.add_parser("stats", help="get statistics of target website",aliases=['stats'])
	stat_parser.add_argument('-u', '--url',
			help="url target to scan",
			dest="url",
			nargs=1)
	stat_parser.add_argument('-m', '--mapper',
			help="mapping all requests from target",
			dest="mapper",
			action="store_true")

	parser._optionals.title = "\nOPTIONS"
	return parser.parse_args()

args = parse_args()
if args.command == 'stats':
	if(args.url):
		stat = Stats(url=stat_map_url,scanner=stat_map_scanner)
		stat._set_target_(args.url[0])
		_noncetoken = stat.getnonce(stat.__load__())
		_testurl = stat.post_wvscan(_noncetoken)
		_details = stat._get_averages_(_testurl)
		_content = stat.netspeed(_details)
		if stat._get_ttfb_(_content) is not None:
			logger_p(FIRST_B,stat._get_ttfb_(_content),S)

		if stat._get_start_render_(_content) is not None:	
			logger_p(S_RENDER,stat._get_start_render_(_content),S)

		if stat._get_first_content_fulpaint_(_content) is not None:
			logger_p(FCP,stat._get_first_content_fulpaint_(_content),S)

		if stat._get_speed_index_(_content) is not None:
			logger_p(SPEED_I,stat._get_speed_index_(_content),S)

		if stat._get_largest_content_fulpaint_(_content) is not None:
			logger_p(LCP,stat._get_largest_content_fulpaint_(_content),S)

		if stat._get_cumulative_layout_shift_(_content) is not None:
			logger_p(CLS,stat._get_cumulative_layout_shift_(_content))

		if stat._get_total_block_time_(_content) is not None:
			logger_p(TBT,stat._get_total_block_time_(_content),S)

		if stat._get_doc_complete_(_content) is not None:
			logger_p(DCTIME,stat._get_doc_complete_(_content))

		if stat._get_request_doc_(_content) is not None:
			logger_p(DCREQS,stat._get_request_doc_(_content))

		if stat._get_byte_indoc_(_content) is not None:
			logger_p(DCBYTES,stat._get_byte_indoc_(_content),KB)

		if stat._get_fully_loaded_(_content) is not None:
			logger_p(TTIME,stat._get_fully_loaded_(_content),S)

		if stat._get_request_count_(_content) is not None:
			logger_p(REQSS,stat._get_request_count_(_content))

		if stat._get_byte_in_(_content) is not None:
			logger_p(TOTBYTES,stat._get_byte_in_(_content),KB)
	else:
		parser_error("You need target url use (-u or --url)")
	if args.mapper == True:
		mapper = Mapper(data=_content)
		print("\n[ Requests details ]")
		for MAP in mapper.__parser__(mapper.__mapper__(),""):
			print(f"{MAP[3][0]}:{MAP[3][1]}\n{MAP[4][0]}:{MAP[4][1]}\n{MAP[2][0]}:{MAP[2][1]}\n{MAP[1][0]}:{MAP[1][1]}\n{SEPARATOR}")

elif args.command == 'cloud':
	if args.domain:
		proxy_obj = ProxyMasquerade(url=proxy_url)
		cloud_obj = CloudDump(cloud_dump_url)
		cloud_obj._set_proxies_(proxy_obj.proxies_chain())
		cloud_obj._set_target_(args.domain[0])
		cloud_ips = cloud_obj._graps_()
	else:
		parser_error("You need to specify the target url use (-d or --domain)")
	if args.wide == True:
		cloud_obj._set_scanner_(cloud_dump_scanner)
		cloud_obj.wide_scan(cloud_ips,args.domain[0])
else:
	parser_error("argument command: invalid choice: (choose from 'cloud', 'stats').")
