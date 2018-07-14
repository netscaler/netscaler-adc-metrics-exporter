FROM python:3
MAINTAINER George Nikolopoulos "t_giorgosn@citrix.com"
COPY exporter.py /
COPY metrics.json /
RUN pip install prometheus_client requests

ENTRYPOINT ["python", "/exporter.py"]
