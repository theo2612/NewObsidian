![[CRUNCHS_CTF_No.2_-_promotion_1.pdf]]

ip discovery

[[nmap]] scan
-sC = Use standard [[NMAP]] scripts. (The same as —script=default) 
-sV = Scan for service version.
-p- = Scan all ports
	22 and 80 open
	
80/tcp open [[ftp]]
	Anonymous login allowed
	get notes, 
	cd ..., get id_rsa
	
use id_rsa to [[ssh]] into [[ftp]]-user - (not previously given)

view /etc/passwd for users with bash
```bash
cat /etc/passwd | grep sh
```
```
root:x:0:0:root:/root:/bin/bash
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
boss:x:1000:1000:james:/home/boss:/bin/bash
ftp-user:x:1001:1002::/home/ftp-user:/bin/bash
intern:x:1002:1002:,,,:/home/intern:/bin/bash
bob:x:1003:1003:,,,:/home/bob:/bin/bash
it:x:1004:1004:,,,:/home/it:/bin/bash
supervisor:x:1005:1005:,,,:/home/supervisor:/bin/bash
ceo:x:1006:1006:,,,:/home/ceo:/bin/bash
debug:x:1007:1007:,,,:/home/debug:/bin/bash
```
users on system
root 
bob
boss
ceo
debug
[[ftp]]-user
interen
it
supervisor








