nmap open ports and services
```
┌──(kali㉿kali)-[~/htb/timelapse]                                                                   
└─$ nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49667,49673,49674,49693,49719 -sC 
-sV 10.10.11.152 -oN 10.10.11.152_OpenPorts                                                         
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-27 12:35 EDT                                     
Nmap scan report for 10.10.11.152                                                                   
Host is up (0.073s latency).                                                                        
                                                                                                    
PORT      STATE SERVICE           VERSION                                                           
53/tcp    open  domain            Simple DNS Plus                                                   
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-09-28 00:35:26Z)    
135/tcp   open  msrpc             Microsoft Windows RPC                                             
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn                                     
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., 
Site: Default-First-Site-Name)                                                                      
445/tcp   open  microsoft-ds?                                                                       
464/tcp   open  kpasswd5?                                                                           
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0                               
636/tcp   open  ldapssl?                                                                            
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., 
Site: Default-First-Site-Name)                                                                      
3269/tcp  open  globalcatLDAPssl?                                                                   
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                           
|_ssl-date: 2025-09-28T00:36:56+00:00; +7h59m59s from scanner time.                                 
|_http-server-header: Microsoft-HTTPAPI/2.0                                                         
| ssl-cert: Subject: commonName=dc01.timelapse.htb                                                  
| Not valid before: 2021-10-25T14:05:29                                                             
|_Not valid after:  2022-10-25T14:25:29                                                             
| tls-alpn:                                                                                         
|_  http/1.1                                                                                        
|_http-title: Not Found                                                                             
9389/tcp  open  mc-nmf            .NET Message Framing                                              
49667/tcp open  msrpc             Microsoft Windows RPC                                             
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0                               
49674/tcp open  msrpc             Microsoft Windows RPC                                             
49693/tcp open  msrpc             Microsoft Windows RPC                                             
49719/tcp open  msrpc             Microsoft Windows RPC                                             
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows                                
                                                                                                    
Host script results:                                                                                
| smb2-time:                                                                                        
|   date: 2025-09-28T00:36:16                                                                       
|_  start_date: N/A                                                                                 
|_clock-skew: mean: 7h59m58s, deviation: 0s, median: 7h59m58s                                       
| smb2-security-mode:                                                                               
|   3:1:1:                                                                                          
|_    Message signing enabled and required                                                          
                                                                                                    
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .      
Nmap done: 1 IP address (1 host up) scanned in 101.04 seconds        
```

- rpcdump
```
┌──(kali㉿kali)-[~/htb/timelapse]
└─$ impacket-rpcdump 10.10.1.152                  
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Retrieving endpoint list from 10.10.1.152

```
