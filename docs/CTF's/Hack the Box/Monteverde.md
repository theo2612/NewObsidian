- nmap scan for open ports
	- seeing **88 (Kerberos), 389 (LDAP), 445 (SMB), 5985 (WinRM), and 3389 (RDP)** immediately tells us this is an **Active Directory Domain Controller**
```bash
$ sudo -p- --min-rate=3000 -Pn -oN monteverdeNmapOpenPorts.txt 10.10.10.172
Nmap scan report for 10.10.10.172
Host is up (0.030s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49676/tcp open  unknown
49696/tcp open  unknown
49750/tcp open  unknown

# Nmap done at Sat Aug  2 13:20:43 2025 -- 1 IP address (1 host up) scanned in 44.09 seconds
```

- nmap for services and versions running on open ports
	- domain is MEGABANK.LOCAL
	- when you see `Microsoft HTTPAPI httpd 2.0` on **5985**, that’s almost always WinRM.
```bash
$ sudo -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49676,49696,49750 -sSCV --min-rate=2000 -Pn -oN monteverdeNmapServicesVersions.txt 10.10.10.172
Nmap scan report for 10.10.10.172
Host is up (0.031s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-02 17:39:37Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
49750/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-08-02T17:40:26
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug  2 13:41:06 2025 -- 1 IP address (1 host up) scanned in 96.14 seconds
```

- starting with ldap enumeration
	- 
```bash
┌──(kali㉿kali)-[~/htb/monteverde]
└─$ nxc ldap 10.10.10.172 -u '' -p '' --users                         
LDAP        10.10.10.172    389    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL)
LDAP        10.10.10.172    389    MONTEVERDE       [+] MEGABANK.LOCAL\: 
LDAP        10.10.10.172    389    MONTEVERDE       [*] Enumerated 10 domain users: MEGABANK.LOCAL
LDAP        10.10.10.172    389    MONTEVERDE       -Username-                    -Last PW Set-       -BadPW-  -Description-
LDAP        10.10.10.172    389    MONTEVERDE       Guest                         <never>             0        Built-in account for guest access to the computer/domain
LDAP        10.10.10.172    389    MONTEVERDE       AAD_987d7f2f57d2              2020-01-02 17:53:24 0        Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
LDAP        10.10.10.172    389    MONTEVERDE       mhope                         2020-01-02 18:40:05 0    
LDAP        10.10.10.172    389    MONTEVERDE       SABatchJobs                   2020-01-03 07:48:46 0    
LDAP        10.10.10.172    389    MONTEVERDE       svc-ata                       2020-01-03 07:58:31 0    
LDAP        10.10.10.172    389    MONTEVERDE       svc-bexec                     2020-01-03 07:59:55 0    
LDAP        10.10.10.172    389    MONTEVERDE       svc-netapp                    2020-01-03 08:01:42 0    
LDAP        10.10.10.172    389    MONTEVERDE       dgalanos                      2020-01-03 08:06:10 0    
LDAP        10.10.10.172    389    MONTEVERDE       roleary                       2020-01-03 08:08:05 0    
LDAP        10.10.10.172    389    MONTEVERDE       smorgan                       2020-01-03 08:09:21 0  
```