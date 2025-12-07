Scan the ip for open ports
- 22,80,111,2049,38321,43569,44239,44563,59549
```bash
┌──(kali㉿kali)-[~]
└─$ nmap -p- --min-rate=1000 10.10.11.232                                    
Starting Nmap 7.93 ( https://nmap.org ) at 2024-02-04 09:32 EST
Nmap scan report for clicker.htb (10.10.11.232)
Host is up (0.085s latency).
Not shown: 65526 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
38321/tcp open  unknown
43569/tcp open  unknown
44239/tcp open  unknown
44563/tcp open  unknown
59549/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 11.42 seconds
```

Scan open ports for Services and versions

┌──([[kali]]㉿[[kali]])-[~]                                                                          
└─$ [[nmap]] -p 22,80,111,2049,37261,39993,40417,52313,60655 -sC -sV 10.10.11.232                            
Starting [[Nmap]] 7.93 ( [[https]]://[[nmap]].org ) at 2024-02-04 10:19 EST                                          
[[Nmap]] scan report for clicker.[[htb]] (10.10.11.232)                                                          
Host is up (0.077s latency).   
PORT      STATE  SERVICE VERSION                                                                         
22/tcp    open   [[ssh]]     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu [[Linux]]; protocol 2.0)                    
| [[ssh]]-hostkey:                                                                                           
|   256 89d7393458a0eaa1dbc13d14ec5d5a92 (ECDSA)                                                         
|_  256 b4da8daf659cbbf071d51350edd81130 (ED25519)                                                       
80/tcp    open   [[http]]    Apache httpd 2.4.52 ((Ubuntu))                                                  
| [[http]]-cookie-flags:                                                                                     
|   /:                                                                                                   
|     PHPSESSID:                                                                                         
|_      httponly flag not set                                                                            
|_http-server-header: Apache/2.4.52 (Ubuntu)                                                             
|_http-title: Clicker - The Game                                                                         
111/tcp   open   rpcbind 2-4 (RPC #100000)                                                               
| rpcinfo:                                                                                               
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      41679/tcp6  mountd
|   100005  1,2,3      43429/udp   mountd
|   100005  1,2,3      43569/tcp   mountd
|   100005  1,2,3      44533/udp6  mountd
|   100021  1,3,4      35261/tcp6  nlockmgr
|   100021  1,3,4      38233/udp6  nlockmgr
|   100021  1,3,4      38321/tcp   nlockmgr
|   100021  1,3,4      40925/udp   nlockmgr
|   100024  1          35983/tcp6  status
|   100024  1          38416/udp   status
|   100024  1          44239/tcp   status
|   100024  1          49508/udp6  status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
2049/tcp  open   nfs_acl 3 (RPC #100227)
37261/tcp closed unknown
39993/tcp closed unknown
40417/tcp closed unknown
52313/tcp closed unknown
60655/tcp closed unknown
Service Info: OS: [[Linux]]; CPE: cpe:/o:[[linux]]:linux_kernel

Service detection performed. Please report any incorrect results at [[https]]://[[nmap]].org/submit/ .
[[Nmap]] done: 1 IP address (1 host up) scanned in 9.57 seconds

