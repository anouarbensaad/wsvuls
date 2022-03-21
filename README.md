<h1 align="center">
  <br>
  <a href="https://github.com/anouarbensaad/wsvuls"><img src="https://i.ibb.co/mBBymCT/WSV.png" alt="WSVuls"></a>
  <br>
  WSVuls
  <br>
</h1>

<h4 align="center">Website vulnerability scanner detect issues [ outdated server software and insecure HTTP headers.]</h4>

<p align="center">
  <a href="https://github.com/anouarbensaad/wsvuls/issues">
    <img src="https://img.shields.io/github/issues/anouarbensaad/wsvuls"
         alt="issues">
  </a>
  <a href="https://github.com/anouarbensaad/wsvuls/blob/main/LICENSE">
      <img src="https://img.shields.io/github/license/anouarbensaad/wsvuls">
  </a>
</p>


### What's WSVuls?

WSVuls is a simple and powerful command line tool for Linux, Windows and macOS. It's designed for developers/testers and for those workers in IT who want to test vulnerabilities and analyses website from a single command.
It detects issues outdated software version, insecures HTTP headers, the long and useless requests

### Why WSVuls ?

WSVuls can extract the following data while crawling: 
##### Cloudflare :
- IP Address
- Ports
- Hex Headers
- Protocol Version
##### Stats :
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

##### Mapper :
- Resource
- Request Start
- Content Type
- DNS Lookup
- SSL Negotiation
- Error/Status Code

### Docker
WSVuls can be launched using docker

##### Build Image
```BASH
$ git clone https://github.com/anouarbensaad/wsvuls
$ cd wsvuls
$ docker build -t wsvuls:latest .
```
##### Run a WSVuls container with interactive mode
```BASH
$ docker run -it --name wsvuls wsvuls:latest -u facebook.com
```

### Usage

```text
Scan, Detect and get stats for a specific url

Examples:

To get stats from target url:
$ wsvuls stats -u facebook.com

To get map all requests:
$ wsvuls stats -u facebook.com --mapper

To detect a right ip address from cloudflare firewall:
$ wsvuls cloud -d facebook.com

by default use-proxy to bypass the limit rate.

Available Commands: 
  stats      Get statistics of target website.
  cloud      Get the right data from cloudflare.
  
Flags:
  -h, --help      help for wsvuls
```

### Screenshot
<div align="center">
<img src="https://user-images.githubusercontent.com/23563528/155910876-cc6f1f4c-7f64-4646-bbef-d95aeb91a928.png" />
</div>
