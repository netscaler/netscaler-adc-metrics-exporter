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
from requests.packages.urllib3.exceptions import SubjectAltNameWarning
from requests.auth import HTTPBasicAuth
from retrying  import RetryError
from retrying import retry

NS_USERNAME_FILE = '/mnt/nslogin/username'
NS_PASSWORD_FILE = '/mnt/nslogin/password'
DEPLOYMENT_WITH_CPX = 'sidecar'
CPX_CRED_DIR = '/var/deviceinfo'
CPX_CRED_FILE = '/var/deviceinfo/random_id'
 
def parseConfig(args):
    '''Parses the config file for specified metrics.'''

    try:
        with open(args.config_file, 'r') as stream:
            config = yaml.load(stream, Loader=yaml.FullLoader)
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
            filemode='w',
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
        logger.critical('Error while opening port: {}', format(e))
        print(e)


def check_nitro_access(protocol, nsip, username, password, ns_cert):
    '''Validates if exporter is able access ADC.'''

    url = '%s://%s/nitro/v1/config/' % (protocol, nsip)
    try:
        response = requests.get(url, verify=ns_cert, auth=HTTPBasicAuth(username, password))
        if (response.status_code == requests.status_codes.codes.unauthorized):
            logger.error('Invalid username or password for Citrix Adc!, Unaurthorized Err : {}'.format(response.status_code))
            return False
    except requests.exceptions.RequestException as err:
        logger.error('Nitroc Access Error {}'.format(err))
        return False
    except Exception as e: 
        logger.error("Unable to authenticated ADC nitro credentials {}".format(e))
        return False
    return True


def get_sslcertkey_stats(protocol, nsip, username, password, nitro_timeout, ns_cert):
    '''Validates if exporter is able fetch stats access from ADC when it's fully configured.'''

    headers = {'X-NITRO-USER': username, 'X-NITRO-PASS': password}
    url = '%s://%s/nitro/v1/config/sslcertkey' % (protocol, nsip)
    try:
        r = requests.get(url, headers=headers, verify=ns_cert, timeout=nitro_timeout)
        data = r.json()
        if data['sslcertkey'] is None:
            return False
        else:
            return True
    except Exception as e:
        logger.warning("Unable to access stats, ADC still not fully configured")
        return False
    return True


def verify_ns_session_access(nsip, ns_protocol, ns_user, ns_password, ns_cert):
    '''Validates if exporter is able to establish session with ADC and fetch stats.'''

    ns_access_success = False
    logger.info('Attempting to connect to citrix adc with ip {}'.format(nsip))
    while not ns_access_success:
        ns_access_success = check_nitro_access(ns_protocol, nsip, ns_user, ns_password, ns_cert)
        if ns_access_success is False:
            logger.info('Retrying to connect to citrix adc with ip {}'.format(nsip))
        time.sleep(1)
    logger.info('Exporter connected to citrix adc {}'.format(nsip))


def verify_ns_stats_access(nsip, ns_protocol, ns_user, ns_password, timeout, ns_cert):
    '''Validates if exporter is able to fetch stats from ADC.'''

    ns_stat_access = False
    logger.info('Verifying stat acces for citrix adc with ip {}'.format(nsip))
    while not ns_stat_access:
        ns_stat_access = get_sslcertkey_stats(ns_protocol, nsip, ns_user, ns_password, timeout, ns_cert)
        if ns_stat_access is False:
            logger.info('Retrying to verify stat access for citrix adc with ip {}'.format(nsip))
        time.sleep(4)
    logger.info('Exporter able to acces stats for citrix adc {}'.format(nsip))


def retry_cpx_password_read(ns_password):
    if ns_password is not None:
        return False
    return True

# Generally in the side car mode, credentials should be immediately available.
# Credential file availability cannot take more than a minute in SIDECAR mode even when nodes are highly engaged.
# Wait for credentials max upto 120 seconds.
# There is no need to wait indefinetely even if credentials are not available after two minutes.
@retry(stop_max_attempt_number=120, wait_fixed=1000, retry_on_result=retry_cpx_password_read)
def read_cpx_credentials(ns_password):
    if os.path.isdir(CPX_CRED_DIR):
        if os.path.isfile(CPX_CRED_FILE) and os.path.getsize(CPX_CRED_FILE):
            try:
                with open(CPX_CRED_FILE, 'r') as fr:
                    ns_password = fr.read()
                    if ns_password is not None:
                        logger.info("SIDECAR Mode: Successfully read crendetials for CPX")
                    else:
                        logger.debug("SIDECAR Mode: None password while reading CPX crednetials from file")
            except IOError as e:
                logger.debug("SIDECAR Mode: IOError {}, while reading CPX crednetials from file".format(e))
    return ns_password


def get_cpx_credentials(ns_user, ns_password):
    'Get ns credenttials when CPX mode'

    logger.info("SIDECAR Mode: Trying to get credentials for CPX")
    try:
        ns_password = read_cpx_credentials(ns_password)
    except RetryError:
        logger.error("SIDECAR Mode: Unable to fetch CPX credentials")

    if ns_password is not None:
        ns_user = 'nsroot'
    return ns_user, ns_password

# Priority order for credentials follows the order config.yaml input > env variables
# First env values are populated which can then be overwritten by config values if present.
def get_login_credentials(args):
    '''Gets the login credentials i.e ADC username and passoword'''

    ns_user = os.environ.get("NS_USER")
    ns_password = os.environ.get("NS_PASSWORD")

    deployment_mode = os.environ.get("NS_DEPLOYMENT_MODE", "")
    if deployment_mode.lower() == 'sidecar':
        logger.info('ADC is running as sidecar')
    else:
        logger.info('ADC is running as standalone')   

    if os.environ.get('KUBERNETES_SERVICE_HOST') is not None:
        if os.path.isfile(NS_USERNAME_FILE):
            try:
                with open(NS_USERNAME_FILE, 'r') as f:
                    ns_user = f.read().rstrip()
            except Exception as e:
                logger.error('Error while reading secret. Verify if secret is property mounted::%s', e)
                
        if os.path.isfile(NS_PASSWORD_FILE):
            try:
                with open(NS_PASSWORD_FILE, 'r') as f:
                    ns_password = f.read().rstrip()
            except Exception as e:
                logger.error('Error while reading secret. Verify if secret is property mounted::%s', e)

        if ns_user is None and ns_password is None:
            if deployment_mode.lower() == DEPLOYMENT_WITH_CPX:
                ns_user, ns_password = get_cpx_credentials(ns_user, ns_password)
         
    else:
        if hasattr(args, 'username'):
            ns_user = args.username

        if hasattr(args, 'password'):
            ns_password = args.password
         
    return ns_user, ns_password


def get_ns_session_protocol(args):
    'Get ns session protocol to access ADC'
    secure = args.secure.lower()
    if secure == 'yes':
        ns_protocol = 'https'
    else:
        ns_protocol = 'http'
    return ns_protocol


def get_ns_cert_path(args):
    'Get ns cert path if protocol is secure option is set' 
    if args.cacert_path:
        ns_cacert_path = args.cacert_path
    else:
        ns_cacert_path = os.environ.get("NS_CACERT_PATH", None)

    if not ns_cacert_path:
        logger.error('EXITING : Certificate Validation enabled but cert path not provided')
        sys.exit()

    if not os.path.isfile(ns_cacert_path):
        logger.error('EXITING: ADC Cert validation enabled but CA cert does not exist {}'.format(ns_cacert_path))
        sys.exit()
         
    logger.info('CA certificate path found for validation')
    return ns_cacert_path

def get_cert_validation_args(args, ns_protocol):
    'Get ns validation args, if validation set, then fetch cert path'
    if args.validate_cert:
        ns_cert_validation = args.validate_cert.lower()
    else:
        ns_cert_validation = os.environ.get("NS_VALIDATE_CERT", 'no').lower()

    if ns_cert_validation == 'yes':
        if ns_protocol == 'https':
            logger.info('Cert Validation Enabled')
            ns_cert = get_ns_cert_path(args)
        else:
            logger.error('EXITING: Cert validation enabled on insecure session')
            sys.exit()
    else:
        ns_cert = False # Set ns_sert as False for no cert validation
    return ns_cert

class CitrixAdcCollector(object):
    ''' Add/Update labels for metrics using prometheus apis.'''

    def __init__(self, nsip, metrics, username, password, protocol, 
                 nitro_timeout, k8s_cic_prefix, ns_cert):
        self.nsip = nsip
        self.metrics = metrics
        self.username = username
        self.password = password
        self.protocol = protocol
        self.nitro_timeout = nitro_timeout
        self.k8s_cic_prefix = k8s_cic_prefix
        self.ns_cert = ns_cert
        self.ns_session = requests.Session()
        
    # Collect metrics from Citrix ADC
    def collect(self):
        nsip = self.nsip
        data = {}
        self.ns_session_login()

        for entity in self.metrics.keys():
            logger.info('Collecting metric %s for %s' % (entity, nsip))
            try:
                data[entity] = self.collect_data(entity)
            except Exception as e:
                logger.warning('Could not collect metric: ' + str(e))

        self.ns_session_logout()
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
                                prefix_match = self.update_lbvs_label(label_values, ns_metric_name, log_prefix_match)
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
                                prefix_match = self.update_lbvs_label(label_values, ns_metric_name, log_prefix_match)
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

    # Function to fire nitro commands and collect data from NS
    def collect_data(self, entity):
        '''Fetches stats from ADC using nitro call for different entity types.'''

        # nitro call for all entities lbvserver bindings
        if (entity == 'lbvserver_binding'):
            return self.get_lbvs_bindings_status()

        # this is to fetch lb status for ingress/services in k8s enviroment
        if(entity == 'k8s_ingress_lbvs'):
            entity = 'lbvserver'

        # nitro call for all entities except 'services' (ie. servicegroups)
        if (entity != 'services'):
            if(entity != 'nscapacity' and entity != 'sslcertkey'):
                url = '%s://%s/nitro/v1/stat/%s' % (self.protocol, self.nsip, entity)
            else:
                url = '%s://%s/nitro/v1/config/%s' % (self.protocol, self.nsip, entity)
            data = self.get_entity_stat(url)
            return data[entity]
        else:
            # nitro call for 'services' entity (ie. servicegroups)
            return self.get_svc_grp_services_stats()

    def get_svc_grp_services_stats(self):
        '''Fetches stats for services'''

        url = '%s://%s/nitro/v1/stat/servicegroup' % (self.protocol, self.nsip)
        # get dict with all servicegroups
        servicegroup_list_ds = self.get_entity_stat(url)
        if servicegroup_list_ds:
            servicegroup_data = []
            for servicegroups_ds in servicegroup_list_ds['servicegroup']:
                _manual_servicegroup_name = servicegroups_ds['servicegroupname']
                url = '%s://%s/nitro/v1/stat/servicegroup/%s?statbindings=yes' % (self.protocol, self.nsip, _manual_servicegroup_name)
                data_tmp = self.get_entity_stat(url)
                if data_tmp:
                    if 'servicegroupmember' in data_tmp['servicegroup'][0]:
                    # create a list with stats of all services bound to NS of all servicegroups
                        for individual_svc_binding_data in data_tmp['servicegroup'][0]['servicegroupmember']:
                            # manually adding stats of a particular service
                            individual_svc_binding_data['_manual_servicegroup_name'] = _manual_servicegroup_name
                            servicegroup_data.append(individual_svc_binding_data)
            return servicegroup_data

    def get_lbvs_bindings_status(self):
        '''Fetches percentage of lbvs bindings up status'''

        url_lbvserver = '%s://%s/nitro/v1/stat/lbvserver' % (self.protocol, self.nsip)
        rlbvserver = self.get_entity_stat(url_lbvserver)

        lbvserver_binding_status_up = {'lbvserver_binding': []}
        for lbvserver in rlbvserver['lbvserver']:
            total_up = int(lbvserver['actsvcs'])
            total_down = int(lbvserver['inactsvcs'])
            total = total_up + total_down
            if total != 0:
                percentup = (total_up/float(total)) * 100
            else:
                percentup = 0

            lbvserver_binding_status_up['lbvserver_binding'].append(({'name': lbvserver['name'], 'percentup': percentup}))

        teste = json.dumps(lbvserver_binding_status_up)
        data = json.loads(teste)
        return data['lbvserver_binding']

    def get_entity_stat(self, url):
        '''Fetches stats from ADC using nitro using for a particular entity.'''

        try:
            r = self.ns_session.get(url, verify=self.ns_cert, timeout=self.nitro_timeout)
            data = r.json()
            if data['errorcode'] == 0:
                return data
        except requests.exceptions.RequestException as err:
            logger.error('Stat Access Error {}'.format(err))
        except Exception as e: 
            logger.error("Unable to access stats from ADC {}".format(e))


    def update_lbvs_label(self, label_values, ns_metric_name, log_prefix_match):
        '''Updates lbvserver lables for ingress and services for k8s_cic_ingress_service_stat dashboard.'''

        try:
            # If lbvs name ends with expected _svc, then label values are updated with ingress/service info.
            if (str(label_values).find("_svc") != -1):
                cur_prefix = str(label_values[0].split("_")[0].split("-", 1)[0])
                # update lables only if prefix provided is same as CIC prefix used
                if cur_prefix == self.k8s_cic_prefix:
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
                    logger.info('k8s_cic_ingress_service_stat dashboard cannot be used for non-CIC ingress/lb')
                return False
        except Exception as e:
            logger.error('Unable to update k8s label: (%s)', e)
            return False

    def ns_session_login(self):
        ''' Login to ADC and get a session id for stat access'''

        payload={"login": {'username': self.username, 'password': self.password}}
        url = '%s://%s/nitro/v1/config/login' % (self.protocol, self.nsip)
        ns_login = False
        while not ns_login:
            try:
                response = self.ns_session.post(url, json=payload, verify=ns_cert)
                data = response.json() 
                if data['errorcode'] == 0 :
                    logger.info("ADC Session Login Successful")
                    ns_login = True
                else:
                    logger.error("ADC Session Login Failed")
            except requests.exceptions.RequestException as err:
                logger.error('Session Login Error {}'.format(err))
            except Exception as e:
                logger.error("Login Session Try Failed{}".format(e))
            if ns_login is False:
                logger.info('Retrying to Login to citrix adc')
                time.sleep(1)

    def ns_session_logout(self):
        ''' Logout of ADC session'''

        payload={"logout": {}}
        url = '%s://%s/nitro/v1/config/logout' % (self.protocol, self.nsip)
        ns_logout = False
        while not ns_logout:
            try:
                response = self.ns_session.post(url, json=payload, verify=ns_cert)
                if response.status_code == 201 or response.status_code == 200:
                     ns_logout = True
                     self.ns_session.close()
                     logger.info("ADC Session Logout Successful")
                     break
                else:
                    logger.error("ADC Session Logout Failed")
            except requests.exceptions.RequestException as err:
                logger.error('Session Logout Error {}'.format(err))
            except Exception as e:
                logger.error("Logout Session Try Failed{}".format(e))
            if ns_logout is False:
                logger.info('Retrying to Logout of citrix adc')
                time.sleep(1)
 
 
if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--target-nsip', required=True, type=str, help='The IP of the Citrix ADC to gather metrics from. Required')
    parser.add_argument('--start-delay', default=10, type=float, help='Start the exporter running after a delay to allow other containers to start. Default: 10s')
    parser.add_argument('--port', required=True, type=int, help='The port for the exporter to listen on. Required')
    parser.add_argument('--metric', required=False, action='append', type=str, help='Collect only the metrics specified here, may be used multiple times.')
    parser.add_argument('--secure', default='yes', type=str, help='yes: Use HTTPS, no: Use HTTP. Default: no')
    parser.add_argument('--validate-cert', required=False, type=str, help='yes: Validate Cert, no: Do not validate cert. Default: no')
    parser.add_argument('--cacert-path', required=False, type=str, help='Certificate path for secure validation')
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

    # Get username and password of Citrix ADC
    ns_user, ns_password = get_login_credentials(args)

    # Wait for other containers to start.
    logger.info('Sleeping for %s seconds.' % args.start_delay)
    time.sleep(args.start_delay)

    # Load the metrics file specifying stats to be collected
    metrics_json = get_metrics_file_data(args.metrics_file, args.metric)

    # Get protocol type to access ADC
    ns_protocol = get_ns_session_protocol(args) 

    # Get cert validation args provided 
    ns_cert = get_cert_validation_args(args, ns_protocol) 
       
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)

    # Verify ADC session access
    verify_ns_session_access(args.target_nsip, ns_protocol, ns_user, ns_password, ns_cert)

    # Verify ADC stats access
    verify_ns_stats_access(args.target_nsip, ns_protocol, ns_user, ns_password, args.timeout, ns_cert)

    # Start the server to expose the metrics.
    start_exporter_server(args.port)

    if not args.k8sCICprefix.isalnum():
        logger.error('Invalid k8sCICprefix : non-alphanumeric not accepted')

    # Register the exporter as a stat collector
    logger.info('Registering collector for %s' % args.target_nsip)

    try:
        REGISTRY.register(CitrixAdcCollector(nsip=args.target_nsip, metrics=metrics_json, username=ns_user,
                                             password=ns_password, protocol=ns_protocol, 
                                             nitro_timeout=args.timeout, k8s_cic_prefix=args.k8sCICprefix,                                                          ns_cert=ns_cert))
    except Exception as e:
        logger.error('Invalid arguments! could not register collector for {}::{}'.format(args.target_nsip, e))

    # Forever
    while True:
        signal.pause()
