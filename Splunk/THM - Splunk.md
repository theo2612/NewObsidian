* *Splunk queries always begin with this command implicity unless otherwise specified*
	* When performing additional queries to refine received data this command must be added at the start
	```splunk
	search
	```

*  *When searching for values...*
* What command do you use to include uncommon events?
```splunk
rare
```
* What command do you used to include common security events?
```splunk
top
```
* When we import data into splunk...
* *What is it stored under?*
```splunk
index
```
* *Views that allow us to consistently pull up the same search repeatidly*
	* Dashboard

* *What command is used to remove multiple copies of the same data?*
	* dedup

* *What command is used to search how long even pairs take?*
	* transactions

* *What character is used to 'pipe' search results into further commands*
	* |

* *What command is used to track occurrances of events over time*
	* timechart 

* *What command is used to gather general statistical infomation about a search*
	* stats

* *Data imported into Splunk is catagorized into columns called what?*
	* fields

* *When data are imported into Splunk, what are it's point of origin called?*
	* host

* *When data are impoted into Splunk, what are it's point of origin from within a system called*
	* 









	![[splunk-quick-reference-guide.pdf]]