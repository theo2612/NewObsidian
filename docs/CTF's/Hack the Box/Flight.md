### nmap open ports
- 53 DNS
- 80 HTTP
- 88 kerberos
- 135 rpc
- 139,445 smb
- 
```bash
nmap -p- --min-rate=3000 10.10.11.187 -Pn -oN 10.10.11.187_nmapOpenPorts.txt                        
                                                                                                       
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-11 13:29 EDT                                        
Nmap scan report for 10.10.11.187                                                                      
Host is up (0.030s latency).                                                                           
Not shown: 65517 filtered tcp ports (no-response)                                                      
PORT      STATE SERVICE                                                                                
53/tcp    open  domain                                                                                 
80/tcp    open  http                                                                                   
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
9389/tcp  open  adws                                                                                   
49667/tcp open  unknown                                                                                
49673/tcp open  unknown                                                                                
49674/tcp open  unknown                                                                                
49694/tcp open  unknown                                                                                
49719/tcp open  unknown                                                                                
                          
```
### nmap services
```bash
nmap -p$ports -sSCV --min-rate=2000 10.10.11.187 -Pn -oN 10.10.11.187_nmapServicesVersions.txt      
                                                                                                       
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-11 13:39 EDT                                        
Nmap scan report for 10.10.11.187                                                                      
Host is up (0.031s latency).                                                                           
                                                                                                       
PORT      STATE SERVICE       VERSION                                                                  
53/tcp    open  domain        Simple DNS Plus                                                          
80/tcp    open  http          Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)                   
|_http-title: g0 Aviation                                                                              
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1                                   
| http-methods:                                                                                        
|_  Potentially risky methods: TRACE                                                                   
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-12 00:39:53Z)           
135/tcp   open  msrpc         Microsoft Windows RPC                                                    
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn                                            
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Defa
ult-First-Site-Name)                                                                                   
445/tcp   open  microsoft-ds?                                                                          
464/tcp   open  kpasswd5?                                                                              
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0                                      
636/tcp   open  tcpwrapped                                                                             
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Defa
ult-First-Site-Name)                                                                                   
3269/tcp  open  tcpwrapped                                                                             
9389/tcp  open  mc-nmf        .NET Message Framing                                                     
49667/tcp open  msrpc         Microsoft Windows RPC                                                    
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0                                      
49674/tcp open  msrpc         Microsoft Windows RPC                                                    
49694/tcp open  msrpc         Microsoft Windows RPC                                                    
49719/tcp open  msrpc         Microsoft Windows RPC                                                    
Service Info: Host: G0; OS: Windows; CPE: cpe:/o:microsoft:windows                                     
                                                                                                       
Host script results:                                                                                   | smb2-time:                                       
|   date: 2025-10-12T00:40:42                      
|_  start_date: N/A                                                                                    
|_clock-skew: 6h59m59s                                                                                 
| smb2-security-mode:                                                                                  
|   3:1:1:                                                                                             
|_    Message signing enabled and required                                                             
                                                                                                       
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .         
Nmap done: 1 IP address (1 host up) scanned in 95.48 seconds 
```






```bash

```






```bash

```





```bash

```