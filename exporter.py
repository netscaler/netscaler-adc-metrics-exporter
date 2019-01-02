import os
import sys
import yaml
import json
import time
import signal
import logging
import requests
import argparse
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily, REGISTRY
from requests.packages.urllib3.exceptions import InsecureRequestWarning

def parseConfig(args):
    try:
        nse = {}
        with open(args.config_file, 'r') as stream:
            config = yaml.load(stream)
            for key, value in vars(args).items():
                cfgkey = key.replace('_', '-')
                nse[key]=config[cfgkey] if cfgkey in config else value

    except Exception as e:
        print(e)
        sys.exit()

    return nse


# Function to fire nitro commands and collect data from NS
def collect_data(nsip, entity, username, password, secure, nitro_timeout):

    #Login credentials
    headers = {'X-NITRO-USER': username, 'X-NITRO-PASS': password}
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    if secure == 'yes':
        protocol = 'https'
    else:
        protocol = 'http'

    # nitro call for all entities except 'services' (ie. servicegroups)
    if (entity != 'services'):
        url = '%s://%s/nitro/v1/stat/%s' % (protocol, nsip, entity)
        r = requests.get(url, headers=headers, verify=False, timeout=nitro_timeout)
        data = r.json()
        if data['errorcode'] == 0:
            return data[entity]
    # nitro call for 'services' entity (ie. servicegroups)
    else:
        url = '%s://%s/nitro/v1/stat/servicegroup?statbindings=yes'%(protocol, nsip)
        r = requests.get(url, headers=headers, verify=False, timeout=nitro_timeout) # get dict with all servicegroups
        servicegroup_list_ds = r.json()
        if servicegroup_list_ds['errorcode'] == 0:
            servicegroup_data = []
            for servicegroups_ds in servicegroup_list_ds['servicegroup']:
                _manual_servicegroup_name = servicegroups_ds['servicegroupname']
                url = '%s://%s/nitro/v1/stat/servicegroup/%s?statbindings=yes'%(protocol, nsip, _manual_servicegroup_name)
                r = requests.get(url, headers=headers, verify=False, timeout=nitro_timeout) # get dict with stats of all services bound to a particular servicegroup
                data_tmp = r.json()
                if data_tmp['errorcode'] == 0:
                    for individual_servicebinding_data in data_tmp['servicegroup'][0]['servicegroupmember']: # create a list with stats of all services bound to NS of all servicegroups
                        individual_servicebinding_data['_manual_servicegroup_name'] = _manual_servicegroup_name # manually adding key:value '_manual_servicegroup_name':_manual_servicegroup_name to stats of a particular service
                        servicegroup_data.append(individual_servicebinding_data)
        return servicegroup_data

class NetscalerCollector(object):

    def __init__(self, nsips, metrics, username, password, secure, nitro_timeout):
        self.nsips = nsips
        self.metrics = metrics
        self.username = username
        self.password = password
        self.secure = secure
        self.nitro_timeout = nitro_timeout

    # Collect metrics from NetScalers
    def collect(self):
        data = {}
        for nsip in self.nsips:
            data[nsip] = {}
            for entity in self.metrics.keys():
                logger.info('Collecting metric %s for %s' % (entity, nsip))
                try:
                    data[nsip][entity] = collect_data(nsip, entity, self.username, self.password, self.secure, self.nitro_timeout)
                except Exception as e:
                    logger.warning('Could not collect metric: ' + str(e))

        # Add labels to metrics and provide to Prometheus
        for entity_name, entity in self.metrics.items():
            if('labels' in entity.keys()):
                label_names = [v[1] for v in entity['labels']]
                label_names.append('nsip')
            else:
                label_names = []
                label_names.append('nsip')

            # Provide collected metric to Prometheus as a counter
            for ns_metric_name, prom_metric_name in entity.get('counters', []):
                c = CounterMetricFamily(prom_metric_name, ns_metric_name, labels=label_names)
                for nsip in self.nsips:
                    entity_stats = data[nsip].get(entity_name, [])
                    if( type(entity_stats) is not list):
                        entity_stats = [entity_stats]

                    for data_item in entity_stats:
                        if('labels' in entity.keys()):
                            label_values = [data_item[key] for key in [v[0] for v in entity['labels']]]
                            label_values.append(nsip)
                        else:
                            label_values = [nsip]
                        try:
                            c.add_metric(label_values, float(data_item[ns_metric_name]))
                        except Exception as e:
                            logger.error('Caught exception while adding counter %s to %s: %s' %(ns_metric_name, entity_name, str(e)))
                yield c

            # Provide collected metric to Prometheus as a gauge
            for ns_metric_name, prom_metric_name in entity.get('gauges', []):
                g = GaugeMetricFamily(prom_metric_name, ns_metric_name, labels=label_names)
                for nsip in self.nsips:
                    entity_stats = data[nsip].get(entity_name, [])
                    if(type(entity_stats) is not list):
                        entity_stats = [entity_stats]

                    for data_item in entity_stats:
                        if('labels' in entity.keys()):
                            label_values = [data_item[key] for key in [v[0] for v in entity['labels']]]
                            label_values.append(nsip)
                        else:
                            label_values = [nsip]
                        try:
                            g.add_metric(label_values, float(data_item[ns_metric_name]))
                        except Exception as e:
                            logger.error('Caught exception while adding gauge %s to %s: %s' %(ns_metric_name, entity_name, str(e)))
                yield g

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--target-nsip', required=True, action='append', help='The IP of the Netscaler to gather metrics from. Required')
    parser.add_argument('--start-delay', default=10, type=float, help='Start the exporter running after a delay to allow other containers to start. Default: 10s')
    parser.add_argument('--port', required=True, type=int, help='The port for the exporter to listen on. Required')
    parser.add_argument('--metric', required=False, action='append', type=str, help='Collect only the metrics specified here, may be used multiple times.')
    parser.add_argument('--username', default='nsroot', type=str, help='The username used to access the Netscaler or NS_USER env var. Default: nsroot')
    parser.add_argument('--password', default='nsroot', type=str, help='The password used to access the Netscaler or NS_PASSWORD env var. Default: nsroot')
    parser.add_argument('--secure', default='no', type=str, help='yes: Use HTTPS, no: Use HTTP. Default: no', choices=['yes', 'no'])
    parser.add_argument('--timeout', default=15, type=float, help='Timeout for Nitro calls.')
    parser.add_argument('--metrics-file', required=False, default='/exporter/metrics.json', type=str, help='Location of metrics.json file. Default: /exporter/metrics.json')
    parser.add_argument('--log-file', required=False, default='/exporter/exporter.log', type=str, help='Location of exporter.log file. Default: /exporter/exporter.log')
    parser.add_argument('--log-level', required=False, default='ERROR', type=str, choices=['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL', 'debug', 'info', 'warn', 'error', 'critical'])
    parser.add_argument('--config-file', required=False, default='./config.yaml', type=str)
    args = parser.parse_args()

    if args.config_file:
        args = parseConfig(args)

    try:
        logging.basicConfig(
            filename=args.log_file,
            format='%(asctime)s %(levelname)-8s %(message)s',
            datefmt='%FT%T%z',
            level= {
                'DEBUG': logging.DEBUG,
                'INFO': logging.INFO,
                'WARN': logging.WARN,
                'ERROR': logging.ERROR,
                'CRITICAL': logging.CRITICAL,
            }[args.log_level.upper()])
    except Exception as e:
        print('Error while setting logger configs::%s', e)

    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logger = logging.getLogger('netscaler_metrics_exporter')

    # Wait for other containers to start.
    logger.info('Sleeping for %s seconds.' % args.start_delay)
    time.sleep(args.start_delay)

    # Start the server to expose the metrics.
    logger.info('Starting the exporter on port %s.' % args.port)
    try:
        start_http_server(args.port)
    except Exception as e:
        logger.error('Error while opening port::%s', e)
        print(e)
        sys.exit()

    # Get username and password of NetScalers.
    ns_user = os.environ.get("NS_USER")
    if ns_user == None:
        ns_user = args.username
    ns_password = os.environ.get("NS_PASSWORD")
    if ns_password == None:
        ns_password = args.password
    else:
      logger.warning('Using NS_PASSWORD Environment variable is insecure. Consider using config.yaml file and --config-file option to define password')

    # Load the metrics file specifying stats to be collected
    try:
        f = open(args.metrics_file, 'r')
        # collect selected metrics only
        if args.metric:
            metrics_data = json.load(f)
            metrics_json = {d:metrics_data[d] for d in metrics_data.keys() if d in args.metric}
        # collect all default metrics
        else:
            metrics_json = json.load(f)
    except Exception as e:
        logger.error('Error while loading metrics::%s', e)

    # Register the exporter as a stat collector
    logger.info('Registering collector for %s' % args.target_nsip)
    try:
        REGISTRY.register(NetscalerCollector(nsips=args.target_nsip, metrics=metrics_json, username=ns_user, password=ns_password, secure=args.secure.lower(), nitro_timeout=args.timeout))
    except Exception as e:
        logger.error('Could not register collector for %s::%s', (args.target_nsip, e))

    # Forever
    while True:
        signal.pause()
