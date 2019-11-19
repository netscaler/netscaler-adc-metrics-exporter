#!/usr/bin/env python
import os
import yaml
import json
import time
import signal
import logging
import requests
import argparse
import sys
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily, REGISTRY
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.auth import HTTPBasicAuth


def parseConfig(args):
    '''Parses the config file for specified metrics.'''

    try:
        with open(args.config_file, 'r') as stream:
            config = yaml.load(stream)
            for key in config.keys():
                args.__setattr__(key.replace('-', '_'), config[key])
    except Exception as e:
        logger.error('Error while reading config file::%s', e)
        print(e)
    return args


def get_metrics_file_data(metrics_file, metric):
    '''Loads stat types from metrics file or any specific metric.'''

    try:
        f = open(metrics_file, 'r')
        # collect selected metrics only
        if args.metric:
            metrics_data = json.load(f)
            metrics_json = {d: metrics_data[d] for d in metrics_data.keys() if d in metric}
        # collect all default metrics
        else:
            metrics_json = json.load(f)
    except Exception as e:
        logger.error('Error while loading metrics::%s', e)
    return metrics_json


def set_logging_args(log_file, log_level):
    '''Sets logging file and level as per the arguments.'''

    try:
        logging.basicConfig(
            filename=log_file,
            format='%(asctime)s %(levelname)-8s %(message)s',
            datefmt='%FT%T%z',
            level={
                'DEBUG': logging.DEBUG,
                'INFO': logging.INFO,
                'WARN': logging.WARN,
                'ERROR': logging.ERROR,
                'CRITICAL': logging.CRITICAL,
            }[log_level.upper()])
    except Exception as e:
        print('Error while setting logger configs::%s', e)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logger = logging.getLogger('citrix_adc_metrics_exporter')
    return logger


def start_exporter_server(port):
    ''' Sets an http server for prometheus client requests.'''

    logger.info('Starting the exporter on port %s.' % port)
    try:
        start_http_server(port)
        print("Exporter is running...")
    except Exception as e:
        logger.critical('Error while opening port::%s', e)
        print(e)


def check_nitro_access(protocol, nsip, username, password):
    '''Validates if exporter is able access ADC.'''

    url = '%s://%s/nitro/v1/config/' % (protocol, nsip)
    try:
        response = requests.get(url, verify=False, auth=HTTPBasicAuth(username, password))
        if (response.status_code == requests.status_codes.codes.unauthorized):
            logger.error('Invalid username or password for Citrix Adc!, Unaurthorized Err : {}'.format(response.status_code))
            return False
    except requests.exceptions.RequestException as err:
        logger.error('{}'.format(err))
        return False
    return True


def get_sslcertkey_stats(protocol, nsip, username, password, nitro_timeout):
    '''Validates if exporter is able fetch stats access from ADC when it's fully configured.'''

    headers = {'X-NITRO-USER': username, 'X-NITRO-PASS': password}
    url = '%s://%s/nitro/v1/config/sslcertkey' % (protocol, nsip)
    try:
        r = requests.get(url, headers=headers, verify=False, timeout=nitro_timeout)
        data = r.json()
        if data['sslcertkey'] is None:
            return False
        else:
            return True
    except Exception as e:
        logger.warning("Unable to access stats, ADC still not fully configured")
        return False
    return True


def verify_ns_session_access(nsip, ns_protocol, ns_user, ns_password):
    '''Validates if exporter is able to establish session with ADC and fetch stats.'''

    ns_access_success = False
    logger.info('Attempting to connect to citrix adc with ip {}'.format(nsip))
    while not ns_access_success:
        ns_access_success = check_nitro_access(ns_protocol, nsip, ns_user, ns_password)
        if ns_access_success is False:
            logger.info('Retrying to connect to citrix adc with ip {}'.format(nsip))
        time.sleep(1)
    logger.info('Exporter connected to citrix adc {}'.format(nsip))


def verify_ns_stats_access(nsip, ns_protocol, ns_user, ns_password, timeout):
    '''Validates if exporter is able to fetch stats from ADC.'''

    ns_stat_access = False
    logger.info('Verifing stat acces for citrix adc with ip {}'.format(nsip))
    while not ns_stat_access:
        ns_stat_access = get_sslcertkey_stats(ns_protocol, nsip, ns_user, ns_password, timeout)
        if ns_stat_access is False:
            logger.info('Retrying to verify stat access for citrix adc with ip {}'.format(nsip))
        time.sleep(4)
    logger.info('Exporter able to acces stats for citrix adc {}'.format(nsip))


# Function to fire nitro commands and collect data from NS
def collect_data(nsip, entity, username, password, protocol, nitro_timeout):
    '''Fetches stats from ADC using nitro call for different entity types.'''

    # Login credentials
    headers = {'X-NITRO-USER': username, 'X-NITRO-PASS': password}

    # nitro call for all entities lbvserver bindings
    if (entity == 'lbvserver_binding'):
        url_lbvserver = '%s://%s/nitro/v1/config/lbvserver' % (protocol, nsip)

        responselbvserver = requests.get(url_lbvserver, headers=headers, verify=False, timeout=nitro_timeout)
        rlbvserver = responselbvserver.json()

        lbvserver_binding_status_up = {'lbvserver_binding': []}

        for lbvserver in rlbvserver['lbvserver']:
            url = '%s://%s/nitro/v1/config/lbvserver_binding/%s' % (protocol, nsip, lbvserver['name'])
            r = requests.get(url, headers=headers, verify=False, timeout=nitro_timeout)
            values = r.json()
            total = 0
            total_down = 0
            total_up = 0
            for lbvserver_binding in values['lbvserver_binding']:
                if ('lbvserver_servicegroupmember_binding' in lbvserver_binding):
                    for lbvserver_binding_servers in lbvserver_binding['lbvserver_servicegroupmember_binding']:
                        total += 1
                        if lbvserver_binding_servers['curstate'] == "UP":
                            total_up += 1
                        else:
                            total_down += 1
                if total != 0:
                    percentup = (total_up/float(total)) * 100
                else:
                    percentup = 0

                lbvserver_binding_status_up['lbvserver_binding'].append(({'name': lbvserver['name'], 'percentup': percentup}))

        teste = json.dumps(lbvserver_binding_status_up)
        data = json.loads(teste)
        return data['lbvserver_binding']

    # this is to fetch lb status for ingress/services in k8s enviroment
    if(entity == 'k8s_ingress_lbvs'):
        entity = 'lbvserver'

    # nitro call for all entities except 'services' (ie. servicegroups)
    if (entity != 'services'):
        if(entity != 'nscapacity' and entity != 'sslcertkey'):
            url = '%s://%s/nitro/v1/stat/%s' % (protocol, nsip, entity)
        else:
            url = '%s://%s/nitro/v1/config/%s' % (protocol, nsip, entity)
        r = requests.get(url, headers=headers, verify=False, timeout=nitro_timeout)
        data = r.json()
        if data['errorcode'] == 0:
            return data[entity]
    # nitro call for 'services' entity (ie. servicegroups)

    else:
        url = '%s://%s/nitro/v1/stat/servicegroup?statbindings=yes' % (protocol, nsip)
        # get dict with all servicegroups
        r = requests.get(url, headers=headers, verify=False, timeout=nitro_timeout)
        servicegroup_list_ds = r.json()
        if servicegroup_list_ds['errorcode'] == 0:
            servicegroup_data = []
            for servicegroups_ds in servicegroup_list_ds['servicegroup']:
                _manual_servicegroup_name = servicegroups_ds['servicegroupname']
                url = '%s://%s/nitro/v1/stat/servicegroup/%s?statbindings=yes' % (protocol, nsip, _manual_servicegroup_name)
                # get dict with stats of all services bound to a particular servicegroup
                r = requests.get(url, headers=headers, verify=False, timeout=nitro_timeout)
                data_tmp = r.json()
                if data_tmp['errorcode'] == 0:
                    # create a list with stats of all services bound to NS of all servicegroups
                    for individual_servicebinding_data in data_tmp['servicegroup'][0]['servicegroupmember']:
                        # manually adding key:value '_manual_servicegroup_name':_manual_servicegroup_name to stats of a particular service
                        individual_servicebinding_data['_manual_servicegroup_name'] = _manual_servicegroup_name
                        servicegroup_data.append(individual_servicebinding_data)
            return servicegroup_data


def update_lbvs_label(k8s_cic_prefix, label_values, ns_metric_name, log_prefix_match):
    '''Updates lbvserver lables for ingress and services for k8s_cic_ingress_service_stat dashboard.'''

    try:
        # If lbvs name ends with expected _svc, then label values are updated with ingress/service info.
        if (str(label_values).find("_svc") != -1):
            cur_prefix = str(label_values[0].split("_")[0].split("-", 1)[0])
            # update lables only if prefix provided is same as CIC prefix used
            if cur_prefix == k8s_cic_prefix:
                # return if ingress name as a service
                if label_values[0].split("_")[3] == 'svc':
                    if log_prefix_match:
                        logger.info('k8s_ingress_service_stat Ingress dashboard cannot be used without ingress')
                    return False
                # update label "citrixadc_k8s_ing_lb_ingress_name" with ingress name
                label_values[0] = label_values[0].split("_")[0].split("-", 1)[1]
                # update label "citrixadc_k8s_ing_lb_ingress_port" with ingress port
                label_values[1] = label_values[1].split("_")[2]
                # update label "citrixadc_k8s_ing_lb_service_name" with service name
                label_values[2] = label_values[2].split("_")[3].split("-", 1)[1]
                # update label "citrixadc_k8s_ing_lb_ingress_port" with service port
                label_values[3] = label_values[3].split("_")[5]
                return True
            else:
                if log_prefix_match:
                    logger.info('k8s_cic_ingress_service_stat Ingress dashboard cannot be used for CIC prefix "%s"', cur_prefix)
                return False
        else:
            if log_prefix_match:
                logger.info('k8s_cic_ingress_service_stat Ingress dashboard cannot be used for non-CIC(or < CIC 1.2) ingress/lb"',)
            return False
    except Exception as e:
        logger.error('Unable to update k8s label: (%s)', e)
        return False


class CitrixAdcCollector(object):
    ''' Add/Update labels for metrics using prometheus apis.'''

    def __init__(self, nsip, metrics, username, password, protocol, nitro_timeout, k8s_cic_prefix):
        self.nsip = nsip
        self.metrics = metrics
        self.username = username
        self.password = password
        self.protocol = protocol
        self.nitro_timeout = nitro_timeout
        self.k8s_cic_prefix = k8s_cic_prefix

    # Collect metrics from Citrix ADCs
    def collect(self):
        nsip = self.nsip
        data = {}
        for entity in self.metrics.keys():
            logger.info('Collecting metric %s for %s' % (entity, nsip))
            try:
                data[entity] = collect_data(nsip, entity, self.username, self.password, self.protocol, self.nitro_timeout)
            except Exception as e:
                logger.warning('Could not collect metric: ' + str(e))

        # Add labels to metrics and provide to Prometheus
        log_prefix_match = True

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
                entity_stats = data.get(entity_name, [])
                if(type(entity_stats) is not list):
                    entity_stats = [entity_stats]

                for data_item in entity_stats:
                    if not data_item:
                        continue

                    if ns_metric_name not in data_item.keys():
                        logger.warning('Counter stats for %s not enabled in adc  %s, so could not add to %s' % (ns_metric_name, nsip, entity_name))
                        break

                    if('labels' in entity.keys()):
                        label_values = [data_item[key] for key in [v[0] for v in entity['labels']]]

                        # populate and update k8s_ingress_lbvs metrics if in k8s-CIC enviroment
                        if entity_name == "k8s_ingress_lbvs":
                            if os.environ.get('KUBERNETES_SERVICE_HOST') is not None:
                                prefix_match = update_lbvs_label(self.k8s_cic_prefix, label_values, ns_metric_name, log_prefix_match)
                                if not prefix_match:
                                    log_prefix_match = False
                                    continue
                            else:
                                continue
                        label_values.append(nsip)
                    else:
                        label_values = [nsip]
                    try:
                        c.add_metric(label_values, float(data_item[ns_metric_name]))
                    except Exception as e:
                        logger.error('Caught exception while adding counter %s to %s: %s' % (ns_metric_name, entity_name, str(e)))

                yield c

            # Provide collected metric to Prometheus as a gauge
            for ns_metric_name, prom_metric_name in entity.get('gauges', []):
                g = GaugeMetricFamily(prom_metric_name, ns_metric_name, labels=label_names)
                entity_stats = data.get(entity_name, [])
                if(type(entity_stats) is not list):
                    entity_stats = [entity_stats]

                for data_item in entity_stats:
                    if not data_item:
                        continue

                    if ns_metric_name not in data_item.keys():
                        logger.warning('Gauge stats for %s not enabled in adc  %s, so could not add to %s' % (ns_metric_name, nsip, entity_name))
                        break

                    if('labels' in entity.keys()):
                        label_values = [data_item[key] for key in [v[0] for v in entity['labels']]]

                        # populate and update k8s_ingress_lbvs metrics if in k8s-CIC enviroment
                        if entity_name == "k8s_ingress_lbvs":
                            if os.environ.get('KUBERNETES_SERVICE_HOST') is not None:
                                prefix_match = update_lbvs_label(self.k8s_cic_prefix, label_values, ns_metric_name, log_prefix_match)
                                if not prefix_match:
                                    log_prefix_match = False
                                    continue
                            else:
                                continue

                        label_values.append(nsip)
                    else:
                        label_values = [nsip]
                    try:
                        g.add_metric(label_values, float(data_item[ns_metric_name]))
                    except Exception as e:
                        logger.error('Caught exception while adding counter %s to %s: %s' % (ns_metric_name, entity_name, str(e)))

                yield g


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--target-nsip', required=True, type=str, help='The IP of the Citrix ADC to gather metrics from. Required')
    parser.add_argument('--start-delay', default=10, type=float, help='Start the exporter running after a delay to allow other containers to start. Default: 10s')
    parser.add_argument('--port', required=True, type=int, help='The port for the exporter to listen on. Required')
    parser.add_argument('--metric', required=False, action='append', type=str, help='Collect only the metrics specified here, may be used multiple times.')
    parser.add_argument('--username', default='nsroot', type=str, help='The username used to access the Citrix ADC or NS_USER env var. Default: nsroot')
    parser.add_argument('--password', default='nsroot', type=str, help='The password used to access the Citrix ADC or NS_PASSWORD env var. Default: nsroot')
    parser.add_argument('--secure', default='no', type=str, help='yes: Use HTTPS, no: Use HTTP. Default: no')
    parser.add_argument('--timeout', default=15, type=float, help='Timeout for Nitro calls.')
    parser.add_argument('--metrics-file', required=False, default='/exporter/metrics.json', type=str, help='Location of metrics.json file. Default: /exporter/metrics.json')
    parser.add_argument('--log-file', required=False, default='/exporter/exporter.log', type=str, help='Location of exporter.log file. Default: /exporter/exporter.log')
    parser.add_argument('--log-level', required=False, default='DEBUG', type=str, choices=['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL', 'debug', 'info', 'warn', 'error', 'critical'])
    parser.add_argument('--config-file', required=False, type=str)
    parser.add_argument('--k8sCICprefix', required=False, default='k8s', type=str, help='Prefix for CIC configured k8s entities')

    # parse arguments provided
    args = parser.parse_args()

    # set logging credentials
    logger = set_logging_args(args.log_file, args.log_level)

    # parse config file if provided as an argument
    if args.config_file:
        args = parseConfig(args)

    # Wait for other containers to start.
    logger.info('Sleeping for %s seconds.' % args.start_delay)
    time.sleep(args.start_delay)

    # Get username and password of CItrix ADCs
    ns_user = os.environ.get("NS_USER")
    if ns_user is None:
        ns_user = args.username
    ns_password = os.environ.get("NS_PASSWORD")
    if ns_password is None:
        ns_password = args.password
    else:
        logger.warning('Using NS_PASSWORD Environment variable is insecure. Consider using config.yaml file and --config-file option to define password')

    # Load the metrics file specifying stats to be collected
    metrics_json = get_metrics_file_data(args.metrics_file, args.metric)

    # set ADC proticol access type
    secure = args.secure.lower()
    if secure == 'yes':
        ns_protocol = 'https'
    else:
        ns_protocol = 'http'

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # Verify ADC session access
    verify_ns_session_access(args.target_nsip, ns_protocol, ns_user, ns_password)

    # Verify ADC stats access
    verify_ns_stats_access(args.target_nsip, ns_protocol, ns_user, ns_password, args.timeout)

    # Start the server to expose the metrics.
    start_exporter_server(args.port)

    if not args.k8sCICprefix.isalnum():
        logger.error('Invalid k8sCICprefix : non-alphanumeric not accepted')

    # Register the exporter as a stat collector
    logger.info('Registering collector for %s' % args.target_nsip)

    try:
        REGISTRY.register(CitrixAdcCollector(nsip=args.target_nsip, metrics=metrics_json, username=ns_user,
                                             password=ns_password, protocol=ns_protocol, nitro_timeout=args.timeout, k8s_cic_prefix=args.k8sCICprefix))
    except Exception as e:
        logger.error('Invalid arguments! could not register collector for {}::{}'.format(args.target_nsip, e))

    # Forever
    while True:
        signal.pause()
