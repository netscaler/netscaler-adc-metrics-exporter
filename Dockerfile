FROM alpine:3.11
RUN apk update
RUN apk add python3
RUN apk add curl iputils
COPY pip_requirements.txt .
RUN pip3 install -r pip_requirements.txt
COPY version/VERSION /exporter/
COPY exporter.py /exporter/
COPY metrics.json /exporter/
RUN touch /exporter/exporter.log
RUN ln -sf /dev/stdout /exporter/exporter.log
USER nobody


ENTRYPOINT ["python3", "/exporter/exporter.py" ]
