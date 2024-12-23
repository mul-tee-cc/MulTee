ARG REPO=""
FROM ${REPO}docker.io/library/python:2.7.18-slim

#RUN pip install --upgrade pip
RUN pip --trusted-host=pypi.python.org install PyKMIP==0.10.0

RUN apt-get update && apt-get install -y --force-yes zip unzip sqlite
RUN apt-get install -y --force-yes vim curl

COPY overlay /

RUN mkdir /etc/pykmip/state && /perform.sh init

EXPOSE 5696/tcp
ENTRYPOINT ["/perform.sh","start"]
