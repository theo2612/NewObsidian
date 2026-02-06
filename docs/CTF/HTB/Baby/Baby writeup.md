# Baby - HackTheBox

**IP:** 10.129.234.71
**Platform:** Active Directory Domain Controller
**Domain:** baby.vl
**DC:** BabyDC.baby.vl
**OS:** Windows Server 2022 (Build 10.0.20348)

**Flags:**
- User: ❌
- Root: ❌

---

## Enumeration

### Port Scan

**Command**
```bash
sudo nmap -p- --min-rate 3000 -Pn -oA nmap/BabyAllPorts 10.129.234.71
```

**Key Findings**
- 21 open TCP ports (standard AD DC services)
- Domain: baby.vl
- DC Name: BabyDC.baby.vl
- Clock skew: +4-5 seconds (acceptable for Kerberos)

**Open Services:**
- DNS (53), Kerberos (88, 464)
- MSRPC (135, 593, multiple high ports)
- SMB (139, 445)
- LDAP (389, 636, 3268, 3269)
- RDP (3389), WinRM (5985)
- ADWS (9389)

**Analysis**
- Pure AD environment - no web services
- Standard Domain Controller attack surface
- WinRM + RDP available for post-credential access

**Decision**
Pursue null session enumeration (SMB/LDAP) to get user list, then AS-REP roasting if available.

---

### Service/Version Scan

**Command**
```bash
sudo nmap -p53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,49664,49667,57920,57921,57929,59620,59632 -sSCV --min-rate=2000 -Pn -oN nmap/BabyServicesVersions.txt 10.129.234.71
```

**Flags/Notes**
- `-sSCV` = SYN scan + default scripts + version detection
- `-sS` = SYN stealth scan
- `-C` = run default NSE scripts
- `-V` = version detection

**Key Output**
```
Domain: baby.vl
DC: BabyDC.baby.vl
OS: Windows Server 2022
SMB signing: enabled and required
```

---

### /etc/hosts Configuration

**Command**
```bash
echo "10.129.234.71 baby.vl BabyDC.baby.vl BabyDC" | sudo tee -a /etc/hosts
```

**Decision**
Required for Kerberos authentication and domain-aware tools. Allows using domain names instead of IP.

---

### SMB Null Session Enumeration

**Status:** Pending

**Planned Commands:**
```bash
nxc smb baby.vl -u '' -p '' --shares
nxc smb baby.vl -u '' -p '' --users
nxc smb baby.vl -u '' -p '' --groups
nxc smb baby.vl -u '' -p '' --pass-pol
```

**Purpose:** Check if null sessions reveal shares, users, groups, or password policy.

**Next Steps:**
- If successful: Use user list for AS-REP roasting
- If failed: Try LDAP anonymous bind
- If both fail: Try RID cycling with guest account

---

## Foothold

*Pending enumeration results*

---

## Privilege Escalation

*Pending foothold*

---

## Lessons Learned

- Port 593 (ncacn_http) is RPC over HTTP, not a web service - don't confuse it with web attack surface
- Modern AD DCs often disable null sessions and anonymous LDAP binds by default
