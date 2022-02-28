<h1 align="center">
  <br>
  <a href="https://github.com/anouarbensaad/wsvuls"><img src="https://i.ibb.co/mBBymCT/WSV.png" alt="WSVuls"></a>
  <br>
  WSVuls
  <br>
</h1>

<h4 align="center">Website vulnerability scanner detect issues [ outdated server software and insecure HTTP headers.]</h4>
 
### What's WSVuls?

WSVuls is a simple and powerful command line tool for Linux, Windows and macOS. It's designed for developers/testers and for those workers in IT who want to test vulnerabilities and analyses website from a single command.
It detects issues outdated software version, insecures HTTP headers, the long and useless requests

### Why WSVuls ?
WSVuls uses a crawl process to parse data from target website.

with WSVuls we can extract: 
- First Byte
- Start Render
- FCP
- Speed Index
- LCP 
- CLS
- TBT
- DC Time
- DC Requests
- DC Bytes
- Time
- Requests
- Total Bytes

in `mapper` feature we can extract :
- Resource
- Request Start
- Content Type
- DNS Lookup
- SSL Negotiation
- Error/Status Code

### Usage

```text
Usage:
  wsvuls [options]

Examples:

To scan target url:
$ wsvuls -u facebook.com

You can map all requests from url:
$ wsvuls -u facebook.com --mapper

Flags:
  -u, --url       set target website
  -m, --mapper    to mapp requests from website
  -h, --help      help for wsvuls
  -v, --version   version for wsvuls

Use "wsvuls --help" for more information about a command.
```

### Screenshot
<div align="center">
<img src="https://user-images.githubusercontent.com/23563528/155910876-cc6f1f4c-7f64-4646-bbef-d95aeb91a928.png" />
</div>
