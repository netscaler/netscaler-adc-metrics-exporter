FROM alpine:latest
RUN apk update
RUN apk add python py-pip
RUN apk add curl
RUN pip install prometheus_client requests
COPY exporter.py /
COPY metrics.json /

ENTRYPOINT ["python", "/exporter.py" ]
