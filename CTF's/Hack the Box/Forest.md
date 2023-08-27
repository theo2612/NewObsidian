nmap of the ip reveals the 
- following services running on ports
	- 88 Kerberos
	- 389 3268 LDAP
- Service info 
	- Host: Forest 
	- OS: Windows
- 
```bash
┌──(kali㉿kali)-[~]
└─$ nmap -p 53,88,135,139,389,445,464,593,636,3268,3269 -sV -sC -Pn 10.10.10.161
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-19 03:56 EDT
Nmap scan report for 10.10.10.161
Host is up (0.067s latency).

PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2023-08-19 12:50:14Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  �P�U       Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-08-19T12:50:19
|_  start_date: 2023-08-19T12:16:25
|_clock-skew: mean: 7h13m49s, deviation: 4h02m31s, median: 4h53m48s
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2023-08-19T05:50:21-07:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.23 seconds
```

- Longer nmap scan
```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- -T4 -vv -O --min-rate 20000 -Pn 10.10.10.161
[sudo] password for kali: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-19 03:33 EDT
Initiating Parallel DNS resolution of 1 host. at 03:33
Completed Parallel DNS resolution of 1 host. at 03:33, 0.01s elapsed
Initiating SYN Stealth Scan at 03:33
Scanning 10.10.10.161 [65535 ports]
Discovered open port 139/tcp on 10.10.10.161
Discovered open port 445/tcp on 10.10.10.161
Discovered open port 135/tcp on 10.10.10.161
Discovered open port 53/tcp on 10.10.10.161
Increasing send delay for 10.10.10.161 from 0 to 5 due to 1714 out of 4284 dropped probes since last increase.
Discovered open port 49684/tcp on 10.10.10.161
Increasing send delay for 10.10.10.161 from 5 to 10 due to max_successful_tryno increase to 5
Warning: 10.10.10.161 giving up on port because retransmission cap hit (6).
Discovered open port 636/tcp on 10.10.10.161
Discovered open port 49677/tcp on 10.10.10.161
Discovered open port 49676/tcp on 10.10.10.161
Discovered open port 49664/tcp on 10.10.10.161
Discovered open port 389/tcp on 10.10.10.161
Discovered open port 3269/tcp on 10.10.10.161
Discovered open port 5985/tcp on 10.10.10.161
Discovered open port 47001/tcp on 10.10.10.161
Discovered open port 49666/tcp on 10.10.10.161
Discovered open port 9389/tcp on 10.10.10.161
Discovered open port 49667/tcp on 10.10.10.161
Discovered open port 49671/tcp on 10.10.10.161
Discovered open port 464/tcp on 10.10.10.161
Discovered open port 49703/tcp on 10.10.10.161
Discovered open port 49945/tcp on 10.10.10.161
Discovered open port 593/tcp on 10.10.10.161
Discovered open port 3268/tcp on 10.10.10.161
Discovered open port 49665/tcp on 10.10.10.161
Discovered open port 88/tcp on 10.10.10.161
Completed SYN Stealth Scan at 03:33, 13.30s elapsed (65535 total ports)
Initiating OS detection (try #1) against 10.10.10.161
Retrying OS detection (try #2) against 10.10.10.161
Retrying OS detection (try #3) against 10.10.10.161
Retrying OS detection (try #4) against 10.10.10.161
Retrying OS detection (try #5) against 10.10.10.161
Nmap scan report for 10.10.10.161
Host is up, received user-set (0.069s latency).
Scanned at 2023-08-19 03:33:38 EDT for 24s
Not shown: 60448 closed tcp ports (reset), 5063 filtered tcp ports (no-response)
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49671/tcp open  unknown          syn-ack ttl 127
49676/tcp open  unknown          syn-ack ttl 127
49677/tcp open  unknown          syn-ack ttl 127
49684/tcp open  unknown          syn-ack ttl 127
49703/tcp open  unknown          syn-ack ttl 127
49945/tcp open  unknown          syn-ack ttl 127
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=8/19%OT=53%CT=1%CU=32231%PV=Y%DS=2%DC=I%G=Y%TM=64E0706
OS:A%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10C%TI=I%CI=I%II=I%SS=S%TS=
OS:A)SEQ(SP=101%GCD=1%ISR=10C%TI=I%CI=RD%II=I%SS=S%TS=A)OPS(O1=M53ANW8ST11%
OS:O2=M53ANW8ST11%O3=M53ANW8NNT11%O4=M53ANW8ST11%O5=M53ANW8ST11%O6=M53AST11
OS:)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W
OS:=2000%O=M53ANW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y
OS:%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR
OS:%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80
OS:%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q
OS:=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%
OS:A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Uptime guess: 0.008 days (since Sat Aug 19 03:22:18 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: Incremental

Read data files from: /usr/bin/../share/nmap
OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.61 seconds
           Raw packets sent: 255919 (11.264MB) | Rcvd: 80188 (3.211MB)
```

From LDAP we can try Using anonymous bind you can enumerate LDAP and get a list of valid usernames
- namingContexts reveals the domain name "DC=htb,DC=local"
```bash
┌──(kali㉿kali)-[~/htb/forest]
└─$ ldapsearch -H ldap://10.10.10.161 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingContexts: DC=htb,DC=local
namingContexts: CN=Configuration,DC=htb,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=htb,DC=local
namingContexts: DC=DomainDnsZones,DC=htb,DC=local
namingContexts: DC=ForestDnsZones,DC=htb,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

- **Following command fully queries LDAP and sends output to file ldap-anonymous.out**
```bash
┌──(kali㉿kali)-[~/htb/forest]
└─$ ldapsearch -H ldap://10.10.10.161 -x -b "DC=htb,DC=local" > ldap-anonymous.out
```

- **Following command to search for users reveals**
	- sebastian@htb.local
	- santi@htb.local
	- lucinda@htb.local
	- andy@htb.local
	- mark@htb.local
```bash
┌──(kali㉿kali)-[~/htb/forest]
└─$ less ldap-anonymous.out | grep "user"    
description: Default container for upgraded user accounts
objectClass: user
userAccountControl: 546
userPrincipalName: Exchange_Online-ApplicationAccount@htb.local
...
userAccountControl: 66048
userPrincipalName: sebastien@htb.local
objectClass: user
userAccountControl: 66048
userPrincipalName: santi@htb.local
objectClass: user
userAccountControl: 66048
userPrincipalName: lucinda@htb.local
objectClass: user
userAccountControl: 66048
userPrincipalName: andy@htb.local
objectClass: user
userAccountControl: 66048
userPrincipalName: mark@htb.local
```

