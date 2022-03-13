import re

# Mapping request from url.
MAPPED_REQUESTS = re.compile(r"""
    <\w+>
    <\w+\s+\w+=\"reqNum(.+)\">
    <\w+\ \w+\=\".+\">([0-9]+)</\w+></\w+>\s+ # scrab the request number
    <\w+\s+\w+=\"reqUrl\s.+\"><\w+\s+rel=\"\w+\"\s+\w+=\"(.+)\">.+</\w+></\w+>\s+ # URL of request
    <\w+\s+\w+=\"reqMime.+\">(.+)</\w+>\s+ # type of request [text|js|css]
    <\w+\s+\w+=\"reqStart\s+.+\">(.+)(?:\s+\w+)?</\w+>\s+
    <\w+\s+\w+=\"reqDNS.+>(.+)</\w+>\s+ # elapsed time of dns request.
    <\w+\s+\w+=\"reqSocket.+>(.+)</\w+>\s+ # elapsed time of socket.
    <\w+\s+\w+=\"reqSSL.+\">(.+)\</\w+>\s+ # elapsed time of handshake ssl.
    <\w+\s+\w+=\"reqTTFB.+\">(.+)</\w+>\s+<\w+\s+\w+=\"reqDownload.+\">(.+)</\w+>\s+
    <\w+\s+\w+=\"reqBytes.+\">(.+)</\w+>\s+ # request size.
    <\w+\s+\w+=\"cpuTime.+\">(.+)</\w+>\s+
    <\w+\s+class=\"reqResult\s+.+\">(.+)</\w+>\s+ # HTTP CODE [200,404,400,502,301,401...]
    <\w+\s+class=\"reqIP.+\">(.+)</\w+>\s+ # IP Address.
    </\w+>
""", re.IGNORECASE | re.VERBOSE)

# Get size of all requests
GETBYTEIN = re.compile(r"""
    <\w+\s+
    \w+=\"BytesIn"\s+\w+=\"middle\">
    (.+)<\w+\s+\w+=\".+\">\w+
    </\w+></\w+>
""", re.VERBOSE)

# Count all requests
COUNT_REQUESTS = re.compile(r"""
    <\w+\s+
    \w+=\"Requests\"\s+\w+=\"middle\">
    (.+)</\w+>
""", re.VERBOSE)

FULLY_LOADED = re.compile(r"""
    <\w+\s+
    \w+=\"FullyLoaded\"\s+
    \w+=\".+\"\s+
    \w+=\".+\">(.+)
    <\w+\s+
    \w+=\".+\">
    \w+</\w+>
    </\w+>
""", re.IGNORECASE | re.VERBOSE)

BYTEINDOC = re.compile(r"""
    <\w+\s+
    \w+="BytesInDoc"\s+
    \w+=\"middle\">(.+)
    <\w+\s+\w+="units">\w+</\w+>
    </\w+>
""", re.VERBOSE)

REQUEST_DOC = re.compile(r"""
    <\w+\s+
    \w+=\"RequestsDoc\"\s+
    \w+=\"middle\">(.+)
    </\w+>
""", re.VERBOSE)

DOC_COMPLETE = re.compile(r"""
    <\w+\s+
      \w+=\"DocComplete\"\s+
      \w+=\"border"\s+\w+=\"middle\">
      (.+)<\w+\s+
      \w+=\"units\">
      \w+</\w+>
    </\w+>
""", re.VERBOSE)

# Get total blocking time from all requests.
TBLOCKTIME = re.compile(r"""
    <\w+\s+
      \w+=\"TotalBlockingTime\"\s+
      \w+=\".+\"\s+
      .+=\".+\"><\w+\s+
      \w+=\".+\"\s+
      .+">.+</\w+>(.+)<\w+\s+
      \w+=\".+\">
      \w+</\w+>
    </\w+>
""", re.IGNORECASE | re.VERBOSE)

CUMULATIVE_LAYOUT_SHIFT = re.compile(r"""
    <\w+\s+
      \w+="chromeUserTiming.CumulativeLayoutShift"\s+
      \w+=".+"\s+\w+="middle">(.+)
    </\w+>
""", re.VERBOSE)

LARGEST_CONTENT_FULPAINT = re.compile(r"""
    <\w+\s+
      \w+="chromeUserTiming.LargestContentfulPaint"\s+
      \w+=".+"\s+\w+=\"middle\">(.+)<\w+\s+
      \w+=\"units\">\w+</\w+>
    </\w+>
""",  re.VERBOSE)

SPEED_INDEX = re.compile(r"""
    <\w+\s+
      \w+=\"SpeedIndex\"\s+
      \w+=\".+\">(.+)<\w+\s+
      \w+=\".+\">(.+)</\w+>
    </\w+>
""",  re.VERBOSE)

FIRST_CONTENT_FULPAINT = re.compile(r"""
    <\w+\s+
      \w+=\"firstContentfulPaint\"\s+
      \w+=\".+\">(.+)<\w+\s+
      \w+=\".+\">(.+)</\w+>
    </\w+>
""", re.VERBOSE)

START_RENDER = re.compile(r"""
    <\w+\s+
      \w+=\"StartRender\"\s+
      \w+=\"middle\">(.+)<\w+\s+
      \w+=\"units\">(.+)</\w+>
    </\w+>
""", re.VERBOSE)

TTFB = re.compile(r"""
    <\w+\s+\w+=\"TTFB\"\s+\w+=\".+\">
    (.+)<\w+\s+\w+=\".+\">(.+)</\w+></\w+>
""", re.VERBOSE)