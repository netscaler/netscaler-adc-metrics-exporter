from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily, REGISTRY
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import time
import requests
import argparse
import json
import os

def collect_data(nsip, entity, username, password, secure):
    # Function to fire nitro commands and collect data from NS

    #Login credentials
    headers = {
        'X-NITRO-USER': username,
        'X-NITRO-PASS': password,
    }
   
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    if secure == 'yes':
        protocol = 'https'
    else:
        protocol = 'http' 

    
    if (entity != 'services'):  # nitro command to fire for all entities except 'services' (ie. servicegroups)
        url = '%s://%s/nitro/v1/stat/%s' % (protocol, nsip, entity)
        r = requests.get(url, headers=headers, verify=False, timeout=5)
        data = r.json()
        if data['errorcode'] == 0:
            return data[entity]
    
    else:                       # nitro command to fire for 'services' entity (ie. servicegroups)
        url = '%s://%s/nitro/v1/stat/servicegroup?statbindings=yes'%(protocol, nsip)
        r = requests.get(url, headers=headers, verify=False, timeout=5) # get dict with all servicegroups
        servicegroup_list_ds = r.json()
        if servicegroup_list_ds['errorcode'] == 0:
            servicegroup_data = []
            for servicegroups_ds in servicegroup_list_ds['servicegroup']:
                _manual_servicegroup_name = servicegroups_ds['servicegroupname']
                url = '%s://%s/nitro/v1/stat/servicegroup/%s?statbindings=yes'%(protocol, nsip, _manual_servicegroup_name)
                r = requests.get(url, headers=headers, verify=False, timeout=5) # get dict with stats of all services bound to a particular servicegroup 
                data_tmp = r.json()
                if data_tmp['errorcode'] == 0:
                    for individual_servicebinding_data in data_tmp['servicegroup'][0]['servicegroupmember']: # create a list with stats of all services bound to NS of all servicegroups (to generalize code-flow which comes later on)
                        individual_servicebinding_data['_manual_servicegroup_name'] = _manual_servicegroup_name # manually add a key:value '_manual_servicegroup_name':_manual_servicegroup_name to stats of a particular service (to generalize code-flow which comes later on)
                        servicegroup_data.append(individual_servicebinding_data)
        return servicegroup_data


class NetscalerCollector(object):

    def __init__(self, nsips, metrics, username, password, secure):
        self.nsips = nsips
        self.metrics = metrics
        self.username = username
        self.password = password
        self.secure = secure

    def collect(self):
        
        # Collect metrics from NetScalers
        data = {}
        for nsip in self.nsips:
            data[nsip] = {}    
            for entity in self.metrics.keys():  # cycle through metrics json to get required entities whose stats need to be collected
                print('>>> Collecting stats for: %s::%s' % (nsip, entity))
                try:
                    data[nsip][entity] = collect_data(nsip, entity, self.username, self.password, self.secure)
                except Exception as e:
                    print('>>> Caught exception while collecting data: ' + str(e))

        # Provide collected stats to Prometheus as a counter/guage with desired labels
        for entity_name, entity in self.metrics.items():
            if('labels' in entity.keys()):
                label_names = [v[1] for v in entity['labels']]
                label_names.append('nsip')
            else:
                label_names = []
                label_names.append('nsip')
            
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
                            print('>>> Caught exception while adding counter %s to %s: %s' %(ns_metric_name, entity_name, str(e)))
                yield c

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
                            print('>>> Caught exception while adding guage %s to %s: %s' %(ns_metric_name, entity_name, str(e)) )
                yield g
        

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--target-nsip', required=True, action='append')
    parser.add_argument('--start-delay', default=10, type=float)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--username', default='nsroot', type=str)
    parser.add_argument('--password', default='nsroot', type=str)
    parser.add_argument('--secure', default='no', type=str)
    args = parser.parse_args()

    # Wait for other containers to start.
    print('>>> Sleeping for: %s seconds ...' % args.start_delay)
    time.sleep(args.start_delay)

    # Start the server to expose the metrics.
    print('>>> Starting the exporter on port: %s' % args.port)
    start_http_server(args.port)
    
    # Get username and password of NetScalers.
    ns_user = os.environ.get("NS_USER")
    ns_password = os.environ.get("NS_PASSWORD")
    if ns_user == None:
        ns_user = args.username
    if ns_password == None:
        ns_password = args.password
    
    # Load the metrics file specifying stats to be collected
    f = open('metrics.json', 'r')
    metrics_json = json.load(f)

    # Register the exporter as a stat collector.
    print('>>> Registering collector for: %s' % (args.target_nsip))
    REGISTRY.register(NetscalerCollector(nsips=args.target_nsip, metrics=metrics_json, username=ns_user, password=ns_password, secure=args.secure.lower()))

    # Forever
    while True:
        time.sleep(1)
