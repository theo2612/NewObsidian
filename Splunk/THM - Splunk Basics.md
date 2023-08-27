# Splunk has 3 major components
- Forwarder, Indexer, Search Head

# Splunk Forwarder
- lightweight agent installed on the endpoint intended to be monitored
- mainly tasked to collectthe data and send to Splunk instance
- takes very few resources to process so it does not affect the endpoints performance
- Key data sources
	- web server generating traffic
	- Windows machine generating Windows event logs, Powershell, and Sysmon data 
	- Linux host generating host-centric logs 
	- Database generating DB connection requests, responses, and errors

# Splunk indexer
- main role to process data it receives from the forwarders 
- takes data, normalizes it into field-value pairs, determines it's datatype, and stores them as events.
- processed data is easy to search and analyze

# Search Head
- place within Search & Reporting app where users search indexed logs
- user searches for term or uses Splunk Search Processing Language, then request is sent to the indexer and relevant events are returned in the form of field-value pairs.
- Search head can transform results into presentable tables, pie-chart, column-chart

# Navigating splunk
- Messages - system level messages
- Settings - Configure the splunk instance
- Activitiy - review the progress of jobs
- Help - miscellaneous information, tutorials
- Find - search
# Apps panel
- Apps installed for this splunk instance
- Default app for every splunk installation is in search and reporting
# Explore Splunk
- contains quick links
- Add Data to the splunk instance
- Add new apps
- Access the splunk documentation
# Splunk Dashboard
- By default no dashboards are displayed
- choose from a range of dashboards available in your splunk instance
- Select a dashboard from the dropdown menu or by the dashboards listing page
# Adding data
- Splunk can ingest any data
- When data is added to splunk, the data is processed and transformed into a series of individual events
- The data sources can be event logs, website logs, firewall logs, etc
- Data sources are grouped into catagories. 
	- Files and Directories
	- Network Events
	- IT Operations
	- Cloud Services 
	- Database Services
	- Security Services 
	- Virtualization Services
	- Application Services
	- Windows sources
	- Other  sources
	











