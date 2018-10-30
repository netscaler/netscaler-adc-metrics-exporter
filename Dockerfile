FROM alpine:latest
RUN apk update
RUN apk add python py-pip
RUN apk add curl
RUN pip install prometheus_client requests
COPY version/VERSION /exporter/
COPY exporter.py /exporter/
COPY metrics.json /exporter/


ENTRYPOINT ["python", "/exporter/exporter.py" ]
