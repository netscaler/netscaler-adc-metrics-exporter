Description:
===

This is a simple server that scrapes Citrix NetScaler (NS) stats and exports them via HTTP to Prometheus. Prometheus can then be added as a data source to Grafana to view the netscaler stats graphically.

![exporter_diagram](https://user-images.githubusercontent.com/40210995/41329824-84c214fe-6eed-11e8-899c-3b9c73b52718.png)

   In the above diagram, blue boxes represent physical machines or VMs and grey boxes represent containers. 
There are two physical/virual NetScaler instances present with IPs 10.0.0.1 and 10.0.0.2 and a NetScaler CPX (containerized NetScaler) with an IP 172.17.0.2.
To monitor stats and counters of these NS instances, an exporter (172.17.0.3) is being run as a container. 
The exporter is able to get NS stats such as http request rates, ssl encryption-decryption rate, total hits to a vserver, etc from the three NS instances and send them to the Prometheus containter 172.17.0.4.
The Prometheus container then sends the stats acquired to Graphana which can plot them, set alarms, create heat maps, generate tables, etc as needed to analyse the NS stats. 

   Details about setting up and working of the exporter is given below. 

Usage:
===
The exporter can be run as container once built from the Dockerfile. The container can be build using ;
```
docker build -f Dockerfile -t ns-exporter:v1 ./
```


Once built, the general structure of the command to run the exporter is:
```
docker run -dt -p [host-port:container-port] --name NS-exporter ns-exporter:v1 [flags]
```
where the following flags can be supplied:

flag             |    Description
-----------------|--------------------
--target-nsip    |Used to specify the &lt;IP:port&gt; of the Netscalers to be monitored
--port	         |Used to specify which port to bind the exporter to. Agents like Prometheus will need to scrape this port of the container to access stats being exported
-h               |Provides helper docs related to the exporter


To setup the exporter as given in the diagram, the following command can be used:

```
docker run -dt -p 8888:8888 --name NS-exporter ns-exporter:v1 --target-nsip=10.0.0.1:80 --target-nsip=10.0.0.2:80 --target-nsip=172.17.0.2:80 --port 8888
```
This directs the exporter container to scrape the 10.0.0.1, 10.0.0.2, and 172.17.0.2, IPs on port 80, and the expose the stats it collects on port 8888.
  

GIVE PROM AND GRAPH setup steps also??
 


Stats Exported by Default:
===

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

In this document, the term 'entity' has been used to refer to NetScaler entities such as HTTP, Interfaces, LB, etc. The term 'metrics' has been used to refer to the stats collected for these entities. For example,
the entity ```lbvserver``` has metrics such as ```totalpktsent```, ```tothits```, ```requestsrate```, etc. These metrics are classified by Prometheus into two categories -- ```counters``` and ```guages``` as per this [link](https://prometheus.io/docs/concepts/metric_types/)
Metrics whose value can only increase are counters and those which can increase or decrease are called guages. For the example of ```lbvserver```, ```totalpktsent``` and ```tothits``` are counters, while ```requestsrate``` is a guage. 
Accordingly, entities and their metrics have been provided in the ```metrics.json``` file. By modifying ```metrics.json```, new entities and their metrics which are not exported by default can be included. 
For example, adding the lines given between the ```-.-.-.-``` lines below, directs the exporter to also export ```aaa``` stats.


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

On a single NS, some entities such as lbvserver, csvserver, interfaces, etc can have multiple entities each having its own name. Such entities have an additional section structure in ```metrics.json``` called ```label```.
A lable can be used along with such entities to differenciate stats based on name, ip, type as needed. Other entities such as http, tcp, ssl are present as a single global parameter for the NS, in which case the ```label```
datastrcuture is not needed.
