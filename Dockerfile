FROM ubuntu:16.04
MAINTAINER George Nikolopoulos "t_giorgosn@citrix.com"
RUN apt-get update -y
RUN apt-get install -y wget iputils-ping
RUN apt-get install -y python python-pip
RUN apt-get install -y net-tools
RUN pip install prometheus_client requests
COPY exporter.py /
COPY metrics.json /

ENTRYPOINT ["python", "/exporter.py" ]

