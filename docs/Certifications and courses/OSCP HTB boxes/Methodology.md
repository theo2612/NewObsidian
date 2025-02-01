- ping machine
	- `ping ###.###.###.###`
```bash

```
- nmap for open ports
	- `nmap -p- -T4 --open -Pn -vvv ###.###.###.### -oN nameNmap.txt`
	- or ''
```bash

```

- nmap for services and versions running on open ports
	- `nmap -p port#, port#, port# -sC -sV ###.###.###.### -oN nameServicesVersionsNmap` 
```bash

```

- Gobuster to enumerate website if machine has 80 or 443
	- `gobuster dir -u http://precious.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -o nameGobuster.txt -t 10`
```bash

```
- -or-
- ffuf to enumerate website if machine has 80 or 443
	- ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.10.10/FUZZ -e .php,.txt -t 10
	- ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.10.10/FUZZ
	- wordlist 3 millipon
```bash

```

- search for exploits, RCEs, etc on service's versions running on those open ports
	- SearchSploit
	- Metaspolit
	- document

- Foothold
	- search local directory
	- search root directory
	- sudo -l
	- look for exploitable binary's
		- `$ find / -perm /4000 2>/dev/null'
		- 

look aroiunm d and check thinkgs our for a sec