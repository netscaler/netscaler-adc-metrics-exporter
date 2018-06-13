Exporter for NetScaler Stats
===

Description:
---

This is a simple server that scrapes Citrix NetScaler (NS) stats and exports them via HTTP to Prometheus. Prometheus can then be added as a data source to Grafana to view the netscaler stats graphically.

![exporter_diagram](https://user-images.githubusercontent.com/40210995/41329824-84c214fe-6eed-11e8-899c-3b9c73b52718.png)

   In the above diagram, blue boxes represent physical machines or VMs and grey boxes represent containers. 
There are two physical/virual NetScaler instances present with IPs 10.0.0.1 and 10.0.0.2 and a NetScaler CPX (containerized NetScaler) with an IP 172.17.0.2.
To monitor stats and counters of these NetScaler instances, an exporter (172.17.0.3) is being run as a container. 
The exporter is able to get NetScaler stats such as http request rates, ssl encryption-decryption rate, total hits to a vserver, etc from the three NetScaler instances and send them to the Prometheus containter 172.17.0.4.
The Prometheus container then sends the stats acquired to Graphana which can plot them, set alarms, create heat maps, generate tables, etc as needed to analyse the NetScaler stats. 

   Details about setting up and working of the exporter is given below. 

Usage:
---
The exporter can be run as a standalone python script or built into a container.

### Usage as a Python Script:
To use the exporter as a python script, the following command can be fired
```
python ns-exporter:v1 [flags]
```
where the flags are:

flag             |    Description
-----------------|--------------------
--target-nsip    |Used to specify the &lt;IP:port&gt; of the Netscalers to be monitored
--port	         |Used to specify which port to bind the exporter to. Agents like Prometheus will need to scrape this port of the container to access stats being exported
-h               |Provides helper docs related to the exporter

The exporter can be setup as given in the diagram using;
```
python exporter.py --target-nsip=10.0.0.1:80 --target-nsip=10.0.0.2:80 --target-nsip=172.17.0.2:80 --port 8888
```
This directs the exporter container to scrape the 10.0.0.1, 10.0.0.2, and 172.17.0.2, IPs on port 80, and the expose the stats it collects on port 8888. 
The user can then access the exported metrics directly thorugh port 8888 on the machine where the exporter is running, or Prometheus and Graphana can be setup to view the exported metrics though their GUI.

### Usage as a Container:
In order to use the exporter as a container, it needs to be built into a container. This can be done as follows; 
```
docker build -f Dockerfile -t ns-exporter:v1 ./
```
Once built, the general structure of the command to run the exporter is very similar to what was used while running it as a script:
```
docker run -dt -p [host-port:container-port] --name netscaler-exporter ns-exporter:v1 [flags]
```
To setup the exporter as given in the diagram, the following command can be used:
```
docker run -dt -p 8888:8888 --name netscaler-exporter ns-exporter:v1 --target-nsip=10.0.0.1:80 --target-nsip=10.0.0.2:80 --target-nsip=172.17.0.2:80 --port 8888
```
This directs the exporter container to scrape the 10.0.0.1, 10.0.0.2, and 172.17.0.2, IPs on port 80, and the expose the stats it collects on port 8888. 
The user can then access the exported metrics directly thorugh port 8888 on the machine where the exporter is running, or Prometheus and Graphana can be setup to view the exported metrics though their GUI.
  
Stats Exported by Default:
---

The exporter is configured to export some of the most commonly used stats for a Netscaler device. They are mentioned in the ```metrics.json``` file and summarized in the table below:

Sl. No. |     STATS 				| NS nitro name
--------|---------------------------|--------------
1       | LB vserver stats          | "lbvserver"
2	    | CS vserver stats          | "csvserver"
3	    | HTTP stats                | "protocolhttp"
4	    | TCP stats                 | "protocoltcp"
5	    | IP stats	                | "protocolip"
6	    | SSL stats                 | "ssl"
7	    | Interface stats	        | "Interface" (capital 'i')
8	    | Service stats	            | "service"
9		| Service group stats		| "services"


Exporting Stats not Included by Default:
---

In this document, the term 'entity' has been used to refer to NetScaler entities such as HTTP, Interfaces, LB, etc. The term 'metrics' has been used to refer to the stats collected for these entities. For example,
the entity ```lbvserver``` has metrics such as ```totalpktsent```, ```tothits```, ```requestsrate```, etc. These metrics are classified by Prometheus into two categories -- ```counters``` and ```guages``` as per this [link](https://prometheus.io/docs/concepts/metric_types/)
Metrics whose value can only increase with time are called counters and those which can increase or decrease are called guages. For the example of ```lbvserver```, ```totalpktsent``` and ```tothits``` are counters, while ```requestsrate``` is a guage. 
Accordingly, entities and their metrics have been provided in the ```metrics.json``` file. By modifying ```metrics.json```, new entities and their metrics which are not exported by default can be included. 
For example, to  export ```aaa``` stats, the lines given between ```-.-.-.-``` can be added as follows:


```
{
    "system": {
        "counters": [
            ["numcpus", "netscaler_cpu_number"]
        ],

        "gauges": [
            ["cpuusagepcnt", "netscaler_cpu_usage_percent"],
            ["mgmtcpuusagepcnt", "netscaler_cpu_management_cpu_usage_percent"],
            ["pktcpuusagepcnt", "netscaler_cpu_packet_cpu_usage_percent"],
            ["rescpuusagepcnt", "netscaler_cpu_res_cpu_usage_percent"]
        ]
    },

-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.
    "aaa": {
            "counters": [
                ["aaatotsessions", "netscaler_aaa_tot_sessions"],
                ["aaatotsessiontimeout", "netscaler_aaa_tot_session_timeout"]
            ],
            "gauges": [
                ["aaasessionsrate', 'netscaler_aaa_sessions_rate"],
                ["aaasessiontimeoutrate ', 'netscaler_aaa_session_timeout_rate"]
            ]
      },
-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.

    "protocolhttp": {
        "counters": [
            ["httptotrequests", "netscaler_http_tot_requests"],
            ["httptotresponses", "netscaler_http_tot_responses"],
            ["httptotposts", "netscaler_http_tot_posts"],
            ["httptotgets", "netscaler_http_tot_gets"],
            ...
            ...
            ["httptotchunkedrequests", "netscaler_http_tot_chunked_requests"]
        ],

        "gauges": [
            ["httprequestsrate", "netscaler_http_requests_rate"],
            ["spdystreamsrate", "netscaler_http_spdy_streams_rate"],
            ...
            ...
            ["http11responsesrate", "netscaler_http_11_responses_rate"]
        ]
    },

    "lbvserver": {
        "counters": [
            ["totalpktssent", "netscaler_lb_vserver_packets_sent_total"],
            ["tothits", "netscaler_lb_vserver_hits_total"],
            ["totalrequestbytes", "netscaler_lb_vserver_request_bytes_total"],
            ...
            ... 
            ["totalresponsebytes", "netscaler_lb_vserver_response_bytes_received_total"]
        ],

        "gauges": [
            ["requestbytesrate", "netscaler_lb_vserver_request_rate_bytes"],
            ["requestsrate", "netscaler_lb_vserver_request_rate"],
            ...
            ...
            ["inactsvcs", "netscaler_lb_vserver_inactive_services_count"]
        ],

        "labels": [
            ["name", "lb_vserver_name"],
            ["type", "lb_vserver_type"]
        ]
    },

...
...
...
}

```

On a given NetScaler, some entities such as lbvserver, csvserver, interfaces, etc can have multiple instances of that entity configured, each having its own name. Such entities have an additional structure in ```metrics.json``` called ```label```.
A label is used for such entities to differenciate stats among different instances of that entity based on name, ip, type, or any other suitable characteristic of that entitiy. 
Other entities such as http, tcp, ssl are present as a single global parameter for the NetScaler, and thus do not have a ```label``` section in ```metrics.json```.

Verification of Exporter Functionality
---
To verify if the exporter is scraping and exporting stats from NetScaler instances, the following url can be opened on a web browser or curl command can be fired from CLI:
```
http://<hostIP>:<port>
curl http://<hostIP>:<port>
```
where hostIP is the IP of the host on which the python script or container is running, and port is the value of the ```--port``` flag which had been provided (```8888``` as per the example).

