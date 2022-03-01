FROM python:3-alpine

LABEL name WSVuls
LABEL src "https://github.com/anouarbensaad/wsvuls"
LABEL creator anouarbensaad
LABEL desc "website vulnerability scanner detect issues [ outdated server software and insecure HTTP headers.]"

RUN apk add git && git clone https://github.com/anouarbensaad/wsvuls.git WSVuls
WORKDIR WSVuls
RUN pip install -r requirements.txt

VOLUME [ "/WSVuls" ]
ENTRYPOINT [ "python", "wsvuls.py" ]
CMD ["--help"]