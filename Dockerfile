FROM alpine:latest
RUN apk update
RUN apk add python py-pip
RUN apk add curl
RUN pip install prometheus_client requests pyyaml
COPY version/VERSION /exporter/
COPY exporter.py /exporter/
COPY metrics.json /exporter/
RUN touch /exporter/exporter.log
RUN ln -sf /dev/stdout /exporter/exporter.log
USER nobody


ENTRYPOINT ["python", "/exporter/exporter.py" ]
