# HTB — Blackfield

## Obsidian Writeup
Primary writeup lives here:
- `/home/b7h30/Documents/obsidian/docs/CTF/HTB/blackfield/blackfield.md`

---

## Target Info
- OS: Windows
- Role: Domain Controller
- IP(s): 10.10.10.192
- Domain: BLACKFIELD.local

---

## Artifact Index

### Recon / Scans
- Notes:
  - Initial exposed services: SMB, LDAP, Kerberos, WinRM

### Enumeration
- `blackfield/smb_audit_2020.txt` — SMB share access as audit2020
- `blackfield/logs/forensic_ls_root.txt` — forensic share listing
- Key findings:
  - AS-REP roastable users discovered
  - Accessible SMB shares: forensic, profiles$

### Foothold
- Access gained:
  - User: support
  - Method: AS-REP roast → crack

### Privilege Escalation
- Techniques:
  - ForceChangePassword (support -> audit2020)
  - LSASS dump parse -> svc_backup NT hash
  - Backup Operators -> VSS copy of `ntds.dit`
- Key artifacts:
  - `blackfield/loot/lsass.DMP`
  - `blackfield/loot/pypykatz_lsassDump.txt`
  - `blackfield/loot/hives/SYSTEM.save`
  - `blackfield/loot/hives/ntds.dit`
  - `blackfield/logs/secretsdump_ntds.txt`

### Proof / Evidence
- Root proof obtained via Administrator PTH

---

## Timeline / Decision Points

- **Recon** → SMB + LDAP identified → pursue AD attack path
- **Enum** → AS-REP roast viable → cracked support
- **Foothold** → SMB shares revealed forensic artifacts and LSASS dump
- **Escalation** → svc_backup hash from LSASS → Backup Operators
- **Decision** → VSS + `ntds.dit` exfil → secretsdump
- **Root** → Administrator hash PTH → root flag

---

## Lessons Learned (High Signal)
- Backup Operators can leverage SeBackup/SeRestore to copy `ntds.dit` via VSS
- LSASS dumps provide NT hashes for fast PTH pivots
- `ntds.dit` + `SYSTEM` hive is sufficient for full domain hash dump
