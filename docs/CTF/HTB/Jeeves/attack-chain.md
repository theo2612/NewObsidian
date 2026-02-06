# Attack Chain - Jeeves

## Full Attack Path
```
Nmap scan → Port 50000 (Jetty 9.4.z-SNAPSHOT)
  → Manual path guessing: /askjeeves/ (box name hint)
    → Jenkins 2.87 (unauthenticated)
      → /askjeeves/script (Groovy Script Console)
        → RCE as jeeves\kohsuke
          → Nishang reverse shell (Invoke-PowerShellTcp.ps1)
            → CEH.kdbx in C:\Users\kohsuke\Documents
              → Cracked with keepass2john + john/rockyou
                → "Backup stuff" = Administrator NTLM hash
                  → impacket-psexec pass-the-hash → SYSTEM
                    → Root flag in ADS: hm.txt:root.txt:$DATA
```

## Branch Points

### Port 80 - IIS (Rabbit Hole)
- Fake "Ask Jeeves" search page → leads nowhere
- jeeves.PNG = fake SQL error page (red herring)
- No directories found via ffuf

### Port 445 - SMB (Dead End initially, used for psexec at the end)
- Anonymous/guest access rejected
- Pass-the-hash via impacket-psexec worked with admin NTLM hash

### Port 50000 - Jetty (Winner)
- CVE-2021-28164 (%2e bypass) → didn't work
- Directory traversal (36318.txt) → didn't work
- Standard wordlists → didn't contain "askjeeves"
- Manual guessing based on box name → **success**

## Completed Steps
- [x] Port scan with nmap (4 ports: 80, 135, 445, 50000)
- [x] Enumerate port 80 IIS (rabbit hole)
- [x] Enumerate port 445 SMB (dead end)
- [x] Enumerate port 50000 Jetty
- [x] Discover Jenkins at /askjeeves/
- [x] RCE via Script Console (Groovy)
- [x] Reverse shell via Nishang Invoke-PowerShellTcp.ps1
- [x] User flag: `e3232272596fb47950d59c4cf1e7066a`
- [x] Found CEH.kdbx KeePass database
- [x] Cracked KeePass master password with john
- [x] Extracted Administrator NTLM hash
- [x] Pass-the-hash with impacket-psexec → SYSTEM
- [x] Root flag (ADS): `afbc5bd4b615a60648cec41c6ac92530`

## BOX COMPLETE
