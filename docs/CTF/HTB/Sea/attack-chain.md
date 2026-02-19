# Attack Chain - Sea

## Current Path
```
Nmap (22, 80) → ffuf (data/, messages/, plugins/, themes/) →
velik71 OSINT → WonderCMS identified → searchsploit CVE-2023-41425 →
52271.py XSS-to-RCE → webshell at /themes/malicious/malicious.php →
reverse shell as www-data → database.json bcrypt hash →
hashcat -m 3200 → mychemicalromance → SSH as amay →
ss -tlnp → port 8080 internal → SSH tunnel (-L 9090:127.0.0.1:8080) →
System Monitor app (HTTP Basic, amay creds reused) →
Burp intercept → log_file parameter (full path, unsanitized) →
path traversal (/etc/shadow reads as root) →
command injection (;id) → root flag leaked →
reverse shell attempts failed (.bashrc exit) →
SSH key injection via command injection →
SSH as root → root flag ✅
```

## Branch Points
- **After nmap:** Only 2 ports → web-focused box
- **CMS identification:** velik71 author → Google → WonderCMS bike theme match
- **Exploit choice:** CVE-2023-41425 (XSS to RCE) was the only viable RCE for WonderCMS 3.4.2
- **Password reuse:** WonderCMS admin password `mychemicalromance` reused for SSH user `amay`
- **Privesc path:** No sudo, no SUID → `ss -tlnp` revealed internal port 8080 → System Monitor app
- **Password reuse again:** amay:mychemicalromance worked for HTTP Basic Auth on internal app
- **Root access method:** Path traversal confirmed root execution → command injection for RCE → reverse shell unstable → pivoted to SSH key injection for stable shell

## Flags
- User: ✅
- Root: ✅ `7fec1998c3419eb978cd445a6b819bcc`
