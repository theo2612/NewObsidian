[Training]([[https]]://securityonionsolutions.com/training/)

# 3 Workflows
- Workflow 1 
	- Alert, Triage, Case creation
	- Login, look at alert, decide if legit, create case
- Workflow 2
	- Ad Hoc hunting
	- start with a question/hypothesis, look through data, answer questions
- Workflow 3
	- Detection Engineering
	- develop detection strategies

# Security Onion Platform - Bottom up

- Analyst Tools
	- SOC - Security Onion Console - Web interface that allow access to the Analyst tools
	- Alerts -
	- Hunt - 
	- Elastic Kibana - visualize data using dashboards
	- Cases - inside SOC - escalates alerts/events, create case inside SOC/component and allows tracking to completion
	- CyberChef - Web app for encryption, encoding, compression, and data analysis
	- Playbook - create detection play based on sigma signature/rules
	- Fleet DM - part of OS Query- run live or scheduled queries against endpoints
	- Navigator - MITRE app for analyzing framework across our enterprise
- Network & Host data
	- Wazuh - Host tool - Host intrustion detection system - allows shipping logs from endpoint and generate alerts based on data seen 
	- Osquery - Host tool - endpoint agent that focuses on allowing you to run queries against either live or scheduled and allows you to write them in sql syntax
	- Beats - Host tool - Allows you to ship logs from endpoints
	- Steno - network tool - Google Stenographer used for full packet capture
	- Suricata - network tool - Generates alerts based on the network data it's seen
	- Zeek - network tool - gives us connection logs, generate metadata about the network data that it is seeing. and extracts files form network data 
	- Strelka - network tool - runs file analysis on extracted files from Zeek. uses yara for signature matching. 
- Infrastructure
	- Salt - allows us to manage docker containers and check  config every 15 min
	- Docker - 
	- Elasticsearch - storing data
	- Redis - queueing
	- Logstash - shipping and parsing logs
	- Filebeat - shipping and parsing logs
	- Grafana - Vizualization performance aspects
- Opertating System
	- CentOS
	- Ubuntu

# Use Cases and Deployment modes
- Not for live mode
	- Forensic Analysis
		- Import node analyzing pcap, logs, packet captures
	- Analyst workstation 
		- Analyst - [[wireshark]]
- For live mode
	- Testing - For evaluation mode
	- Production
		- Standalone
		- Distributed

# Where to get help
- securityonion.net/help
- docs.securityonion.net FAQ
- Community Support Forum (GitHub)
- Paid Support 


