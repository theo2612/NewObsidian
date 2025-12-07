- ping machine
	- `ping ###.###.###.###`
- [[nmap]] for open ports
	- `nmap -p- -T4 --open -vvv -Pn 10.10.10.51 -oN solidstate.txt`
	- 22 [[ssh]]
	- 25 [[smtp]]
	- 80 [[http]]
	- 110 [[pop3]]
	- 119 nntp
	- 4555 rsip
```bash
┌──(kali㉿kali)-[~]
└─$ nmap -p- -T4 --open -vvv -Pn 10.10.10.51 -oN solidstate.txt               
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-27 06:30 EST
Initiating Parallel DNS resolution of 1 host. at 06:30
Completed Parallel DNS resolution of 1 host. at 06:30, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 06:30
Scanning 10.10.10.51 [65535 ports]
Discovered open port 110/tcp on 10.10.10.51
Discovered open port 22/tcp on 10.10.10.51
Discovered open port 25/tcp on 10.10.10.51
Discovered open port 80/tcp on 10.10.10.51
Discovered open port 4555/tcp on 10.10.10.51
Discovered open port 119/tcp on 10.10.10.51
Completed SYN Stealth Scan at 06:30, 17.70s elapsed (65535 total ports)
Nmap scan report for 10.10.10.51
Host is up, received user-set (0.059s latency).
Scanned at 2024-11-27 06:30:30 EST for 18s
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
25/tcp   open  smtp    syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
110/tcp  open  pop3    syn-ack ttl 63
119/tcp  open  nntp    syn-ack ttl 63
4555/tcp open  rsip    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 17.87 seconds
           Raw packets sent: 65619 (2.887MB) | Rcvd: 65547 (2.622MB)
```
- nmap for services and versions running on open ports
	- `nmap -p port#, port#, port# -sC -sV ###.###.###.###`
	- 22 ssh OpenSSH 7.4p1
	- 25 smtp smptd 2.3.2
	- 80 http Apache httpd 2.4.25
	- 110 pop3 pop3d 2.3.2
	- 119 nntp nntpd (posting ok?)
	- 4555 rsip 
```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p 22,25,80,110,119,4555 -sC -sV -vvv 10.10.10.51 -oN solidstate.txt
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-27 06:35 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 06:35
Completed NSE at 06:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 06:35
Completed NSE at 06:35, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 06:35
Completed NSE at 06:35, 0.00s elapsed
Initiating Ping Scan at 06:35
Scanning 10.10.10.51 [4 ports]
Completed Ping Scan at 06:35, 0.09s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 06:35
Completed Parallel DNS resolution of 1 host. at 06:35, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 06:35
Scanning 10.10.10.51 [6 ports]
Discovered open port 25/tcp on 10.10.10.51
Discovered open port 80/tcp on 10.10.10.51
Discovered open port 110/tcp on 10.10.10.51
Discovered open port 22/tcp on 10.10.10.51
Discovered open port 119/tcp on 10.10.10.51
Discovered open port 4555/tcp on 10.10.10.51
Completed SYN Stealth Scan at 06:35, 0.08s elapsed (6 total ports)
Initiating Service scan at 06:35
Scanning 6 services on 10.10.10.51
Completed Service scan at 06:38, 157.78s elapsed (6 services on 1 host)
NSE: Script scanning 10.10.10.51.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 06:38
Completed NSE at 06:38, 21.59s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 06:38
NSE Timing: About 85.42% done; ETC: 06:39 (0:00:05 remaining)
NSE Timing: About 95.83% done; ETC: 06:39 (0:00:03 remaining)
Completed NSE at 06:40, 82.22s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 06:40
Completed NSE at 06:40, 0.00s elapsed
Nmap scan report for 10.10.10.51
Host is up, received reset ttl 63 (0.057s latency).
Scanned at 2024-11-27 06:35:39 EST for 261s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCp5WdwlckuF4slNUO29xOk/Yl/cnXT/p6qwezI0ye+4iRSyor8lhyAEku/yz8KJXtA+ALhL7HwYbD3hDUxDkFw90V1Omdedbk7SxUVBPK2CiDpvXq1+r5fVw26WpTCdawGKkaOMYoSWvliBsbwMLJEUwVbZ/GZ1SUEswpYkyZeiSC1qk72L6CiZ9/5za4MTZw8Cq0akT7G+mX7Qgc+5eOEGcqZt3cBtWzKjHyOZJAEUtwXAHly29KtrPUddXEIF0qJUxKXArEDvsp7OkuQ0fktXXkZuyN/GRFeu3im7uQVuDgiXFKbEfmoQAsvLrR8YiKFUG6QBdI9awwmTkLFbS1Z
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBISyhm1hXZNQl3cslogs5LKqgWEozfjs3S3aPy4k3riFb6UYu6Q1QsxIEOGBSPAWEkevVz1msTrRRyvHPiUQ+eE=
|   256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMKbFbK3MJqjMh9oEw/2OVe0isA7e3ruHz5fhUP4cVgY
25/tcp   open  smtp    syn-ack ttl 63 JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.10 [10.10.14.10])
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3    syn-ack ttl 63 JAMES pop3d 2.3.2
119/tcp  open  nntp    syn-ack ttl 63 JAMES nntpd (posting ok)
4555/tcp open  rsip?   syn-ack ttl 63
| fingerprint-strings: 
|   GenericLines: 
|     JAMES Remote Administration Tool 2.3.2
|     Please enter your login and password
|     Login id:
|     Password:
|     Login failed for 
|_    Login id:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4555-TCP:V=7.94SVN%I=7%D=11/27%Time=67470416%P=x86_64-pc-linux-gnu%
SF:r(GenericLines,7C,"JAMES\x20Remote\x20Administration\x20Tool\x202\.3\.2
SF:\nPlease\x20enter\x20your\x20login\x20and\x20password\nLogin\x20id:\nPa
SF:ssword:\nLogin\x20failed\x20for\x20\nLogin\x20id:\n");
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 06:40
Completed NSE at 06:40, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 06:40
Completed NSE at 06:40, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 06:40
Completed NSE at 06:40, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 262.28 seconds
           Raw packets sent: 10 (416B) | Rcvd: 7 (304B)
```
- search for exploits, RCEs, etc on service's versions running on those open ports
	- 4555 JAMES Remote Administration Tool 2.3.2
		- [[https]]://www.[[exploit-db]].com/exploits/50347
		- has default creds root:root
		- listusers 
			- james, thomas, [[john]], mindy, mailadmin
			- setpassword password on all users
		- login to pop with changed passwords
			- telnet 10.10.10.51 110
			- user james
			- pass password
			- list
			- retr \#
			- [[john]] and mindy have message
			- mindy has a message from [[john]] with her creds in it
			- username: mindy
			- pass: P@55W0rd1!2@
- Mindy has a restricted shell
	- can only use cat, ls, env commands
	- gtfo bins has an env section that can be used to escape restricted shell
		- [[https]]://gtfobins.github.io/gtfobins/env/
- Priv Esc
	- 










