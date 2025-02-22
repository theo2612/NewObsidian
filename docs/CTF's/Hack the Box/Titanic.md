- ping machine
	- `ping ###.###.###.###`
```bash
 kali@kali  ~/htb/titanic  ping 10.10.11.55
PING 10.10.11.55 (10.10.11.55) 56(84) bytes of data.
64 bytes from 10.10.11.55: icmp_seq=1 ttl=63 time=55.9 ms
64 bytes from 10.10.11.55: icmp_seq=2 ttl=63 time=54.0 ms
64 bytes from 10.10.11.55: icmp_seq=3 ttl=63 time=56.9 ms
64 bytes from 10.10.11.55: icmp_seq=4 ttl=63 time=53.7 ms
^C
--- 10.10.11.55 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 53.685/55.114/56.927/1.346 ms

```
- nmap for open ports
	- `nmap -p- -T4 --open -Pn -vvv ###.###.###.### -oN nameNmap.txt`
	- or ''
```bash
 ✘ kali@kali  ~/htb/titanic  nmap -p- -T4 --open -Pn -vvv 10.10.11.55 -oN titanicNmap.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-15 14:29 EST
Initiating Parallel DNS resolution of 1 host. at 14:29
Completed Parallel DNS resolution of 1 host. at 14:29, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 14:29
Scanning 10.10.11.55 [65535 ports]
Discovered open port 80/tcp on 10.10.11.55
Discovered open port 22/tcp on 10.10.11.55
Completed SYN Stealth Scan at 14:30, 17.75s elapsed (65535 total ports)
Nmap scan report for 10.10.11.55
Host is up, received user-set (0.15s latency).
Scanned at 2025-02-15 14:29:58 EST for 17s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 17.91 seconds
           Raw packets sent: 66060 (2.907MB) | Rcvd: 65543 (2.622MB)

```

- nmap for services and versions running on open ports
	- `nmap -p port#, port#, port# -sC -sV ###.###.###.### -oN nameServicesVersionsNmap.txt` 
		- werkzeug/3.0.3
		- Python/3.10.12
		- 
	```bash
 kali@kali  ~/htb/titanic  nmap -p 22,80 -sC -sV 10.10.11.55 -oN titanicServicesVersionsNmap.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-15 15:00 EST
Nmap scan report for titanic.htb (10.10.11.55)
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
|_  256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
| http-server-header: 
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/3.0.3 Python/3.10.12
|_http-title: Titanic - Book Your Ship Trip
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.64 seconds


```

- Gobuster to enumerate website if machine has 80 or 443
	- `gobuster dir -u http://precious.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -o nameGobuster.txt -t 10`
```bash

```
- -or-
- ffuf to enumerate website if machine has 80 or 443
	- ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.10.10/FUZZ -e .php,.txt -t 10
	- ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.10.10/FUZZ
	- wordlist 3 millipon
```bash

```
- -or-
- `dirsearch -u http://titanic.htb`


- search for exploits, RCEs, etc on service's versions running on those open ports
	- SearchSploit
	- Metaspolit
	- document

- Foothold - Look around and check things out for a second
	- search local directory
	- search root directory
	- sudo -l
	- look for exploitable binary'
		- `$ find / -perm /4000 2>/dev/null'


> [!question] How is your Mom?
> - Fine Thank you for asking


