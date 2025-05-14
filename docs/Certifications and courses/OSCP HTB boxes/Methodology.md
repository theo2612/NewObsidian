- ping machine
	- `ping ###.###.###.###`
```bash

```

- nmap for open ports
	- `nmap -p- -T4 --open -Pn -vvv ###.###.###.### -oN nameNmap.txt`
```bash

```
- if server is running dns 
	- `dig @10.10.11.174 +short support.htb any`

then
- nmap for services and versions running on open ports
	- `nmap -p port#, port#, port# -sC -sV ###.###.###.### -oN nameServicesVersionsNmap` 
```bash

```

or

- nmap open ports
	- `nmap -p- --min-rate=3000 support.htb -Pn -oN BoxNmapOpenPorts.txt`
```bash

```
- turn the list into a variable , comma separated
	- `export ports=$(cat BoxNmapOpenPorts.txt | awk '/^[0-9]+\/tcp/ {print $1}' | cut -d'/' -f1 | paste -sd,)`
	- `echo $ports` to check
```bash

```
- Scan with nmap again using scripts
	- `nmap -p$ports -sSCV --min-rate=2000 support.htb -Pn -oN BoxNmapServicesVersions.txt`
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

- Foothold - Look around and check things out for a second
	- search local directory
	- search root directory
	- sudo -l
	- look for exploitable binary's
		- `$ find / -perm /4000 2>/dev/null'
		- 

