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
	- Then we need to run poc on it to generate the 
		- 
	- I used keepass-dumper-masterkey to 

- Gobuster to enumerate website if machine has 80 or 443
	- `gobuster dir -u http://precious.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -o nameGobuster.txt -t 10`
- -or-
- ffuf to enumerate website if machine has 80 or 443
	- ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.10.10/FUZZ
- 

- search for exploits, RCEs, etc on service's versions running on those open ports
	- SearchSploit
	- Metaspolit
	- document

- Foothold
	- sudo -l




