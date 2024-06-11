# Tools
[Simple Email Reputation - https://emailrep.io/ ]( `https://emailrep.io/`)
- Open Source Intelligence (OSINT) toos to check email reputation and enrich the findings. 
- Given site to do a reputation check on the sender address and the address found in the return path.

# emlAnalyzer 
```bash
~$ emlAnalyzer -i Urgent\:.eml --header --html -u --text --extract-all
```
- -i
	- File to analyze, -i/path-to-file/filename or navigate to the required folder
- -header
	- show header
- -u 
	- show URL's
- --text
	- show cleartext data
- --extract-all
	- Extract all attachments

# More Tools
|**Tool**|**Purpose**|
|---|---|
|**VirusTotal**  |A service that provides a cloud-based detection toolset and sandbox environment.|
|**InQuest**  |A service provides network and file analysis by using threat analytics.|
|**IPinfo.io**  |A service that provides detailed information about an IP address by focusing on geolocation data and service provider.|
|**Talos Reputation**  |An IP reputation check service is provided by Cisco Talos.|
|**Urlscan.io**  |A service that analyses websites by simulating regular user behaviour.|
|**Browserling**  |A browser sandbox is used to test suspicious/malicious links.|
|**Wannabrowser**  |A browser sandbox is used to test suspicious/malicious links.|
