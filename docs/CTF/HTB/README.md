# HTB — <MachineName>

## Obsidian Writeup
Primary writeup lives here:
- `/home/b7h30/Documents/obsidian/docs/CTF/HTB/<MachineName>.md`

---

## Target Info
- OS: Windows / Linux
- Role: (DC / Member Server / Web Server / Workstation)
- IP(s): <redacted or HTB IP>
- Domain (if any): <domain>

---

## Artifact Index

### Recon / Scans
- `nmap/`
  - `tcp_full.nmap` — full TCP scan
  - `tcp_full.gnmap`
  - `tcp_full.xml`
- Notes:
  - Initial exposed services: SMB, LDAP, Kerberos, WinRM

### Enumeration
- `logs/`
  - `nxc_smb_shares.txt`
  - `ldap_enum.txt`
  - `kerberos_enum.txt`
- Key findings:
  - AS-REP roastable users discovered
  - Accessible SMB shares: forensic, profiles$

### Foothold
- `loot/`
  - `support_asrep.hash`
- Access gained:
  - User: support
  - Method: AS-REP roast → crack

### Privilege Escalation
- `logs/`
  - `rpc_password_reset.txt`
- Technique:
  - ForcePasswordChange abuse over RPC
- Escalated to:
  - User: audit2020

### Proof / Evidence
- `evidence/`
  - `audit2020_smb_access.png`
  - `password_reset_success.png`
- What this proves:
  - Unauthorized password change
  - Privilege escalation path confirmed

---

## Timeline / Decision Points

- **Recon** → SMB + LDAP identified → pursue AD attack path
- **Enum** → AS-REP roast viable → cracked support
- **Foothold** → SMB shares revealed forensic artifacts
- **Decision** → ForcePasswordChange identified → RPC password change
- **Escalation** → audit2020 access gained

---

## Lessons Learned (High Signal)
- NT_STATUS_PASSWORD_RESTRICTION indicates policy failure, not permission failure
- Windows password resets often fail silently on success
- ForcePasswordChange ≠ full Reset Password rights
- AD privilege escalation is frequently policy + ACL based, not exploit based
