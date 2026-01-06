# HTB — Escape

## Obsidian Writeup
Primary writeup lives here:
- `/home/b7h30/Documents/obsidian/docs/CTF/HTB/Escape/Escape.md`

---

## Target Info
- OS: Windows
- Role: Domain Controller
- IP(s): 10.10.11.202
- Domain: sequel.htb / dc.sequel.htb

---

## Artifact Index

### Recon / Scans
- `nmap/EscapeNmapOpenPorts.txt`
- `nmap/EscapeNmapServiceVersions.txt`
- `smbAnon.txt` — guest share listing (Public)

### Enumeration / Loot
- `loot/SQL Server Procedures.pdf` — SQL auth creds `PublicUser/GuestUserCantWrite1`
- `sequelMSSQLhash.txt` — NetNTLMv2 from `xp_dirtree` (includes `sql_svc`, `DC$`)
- `YourMomsWinPEASS.txt` — host recon (winPEAS)
- Certipy outputs: `20251220134649_Certipy.*`, `20251220135453_Certipy.*`
- Tickets/keys: `administrator.pfx`, `administrator.ccache`
- BloodHound: `20251220180507_BloodHound.zip`

### Foothold
- MSSQL auth with `PublicUser/GuestUserCantWrite1`
- Hash capture via `xp_dirtree` → cracked `sql_svc` (`REGGIE1234ronnie`)
- SQL error log leak → `Ryan.Cooper / NuclearMosquito3`
- WinRM as Ryan (user flag)

### Privilege Escalation
- AD CS ESC1 on `UserAuthentication` template (Certipy)
- Requested cert as Administrator → PFX/ccache + NT hash
- DA via `evil-winrm` with Administrator hash

### Proof / Evidence
- User: Ryan desktop flag
- Root: Administrator desktop flag via PTH/Kerberos

---

## Timeline / Decision Points
- **Recon** → DC with SMB/LDAP/MSSQL/WinRM exposed.
- **Enum** → Public SMB share yielded SQL PDF creds.
- **Coercion** → `xp_dirtree` to Responder captured `sql_svc` NetNTLMv2 → cracked.
- **DB Looting** → SQL error logs leaked Ryan creds → WinRM foothold.
- **Escalation** → Certipy ESC1 abuse to forge Administrator cert → DA shell.

---

## Lessons Learned (High Signal)
- Low-priv SQL auth + `xp_dirtree` is reliable for NetNTLMv2 capture.
- SQL error logs can leak plaintext creds; always inspect `xp_readerrorlog`.
- ESC1 + EnrolleeSuppliesSubject + ClientAuth = quick DA via cert forgery.


## Escape (HTB) – Artifact Index

- Main writeup: `Escape.md` (Obsidian primary notes)

### Key Artifacts
- Nmap: `nmap/EscapeNmapOpenPorts.txt`, `nmap/EscapeNmapServiceVersions.txt`
- SMB anon listing: `smbAnon.txt`
- Loot: `loot/SQL Server Procedures.pdf` (public SQL creds)
- Responder capture: `sequelMSSQLhash.txt` (NetNTLMv2 for sql_svc/DC$)
- Certipy outputs: `20251220134649_Certipy.*`, `20251220135453_Certipy.*`
- Tickets/keys: `administrator.pfx`, `administrator.ccache`
- BloodHound: `20251220180507_BloodHound.zip`
- Misc recon: `YourMomsWinPEASS.txt`

### Quick Timeline
- SMB Public share → grabbed `SQL Server Procedures.pdf` (PublicUser/GuestUserCantWrite1).
- MSSQL login with PublicUser → `xp_dirtree` to Responder → captured `sql_svc` NetNTLMv2 → cracked to `REGGIE1234ronnie`.
- MSSQL as `sql_svc` → SQL error logs leaked `Ryan.Cooper / NuclearMosquito3` → WinRM user shell.
- Certipy find/req (UserAuthentication ESC1) as Ryan → forged Administrator cert/PFX → NT hash/TGT.
- DA shell via evil-winrm with hash → root flag.