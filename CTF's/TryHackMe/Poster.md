http://thm.box.ip
reveals an email signup box

the basic command injection that I tried didn't reveal anything. 
I used an actual email address and clicked sign up and nothing came to my inbox

nmap scan to prob the box network reveals postgresql running on port 5432

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

firing up Metasploit - and searching for postgres
auxiliary module that allows us to enumerate user credentials
#9 auxiliary/scanner/postgres/postgres_login PostgreSQL Login Utility
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

Set module to 9 
Set the LHOSTS option globally across modules
```bash
msf6 > use 9
msf6 auxiliary(scanner/postgres/postgres_login) > options
msf6 auxiliary(scanner/postgres/postgres_login) > set -g rhosts 10.10.78.111

```