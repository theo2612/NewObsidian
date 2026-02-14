# Sea - HackTheBox

- **IP:** 10.129.20.143
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

| Path | Status | Notes |
|------|--------|-------|
| `/` / `index.php` / `home` | 200 (3680 bytes) | Main page |
| `/404` / `0` | 200 (3371 bytes) | Custom 404 page |
| `/data` | 301 | Directory — needs deeper fuzzing |
| `/messages` | 301 | Directory — needs deeper fuzzing |
| `/plugins` | 301 | Directory — needs deeper fuzzing |
| `/themes` | 301 | Directory — needs deeper fuzzing |

**Also found (from browsing):**
- `/contact.php` — "Competition registration - Sea" form (Name, Email, Age, Country, Website)
- Login URL page — needs investigation

**Decision:** Directory structure (`data/`, `messages/`, `plugins/`, `themes/`) suggests a CMS. Need to identify which one.

---

## 3) Next Steps

- [ ] Identify the CMS (check `/themes/`, `/plugins/` for known CMS fingerprints)
- [ ] Fuzz subdirectories (`/data/FUZZ`, `/themes/FUZZ`, `/plugins/FUZZ`)
- [ ] Investigate contact.php — test for XSS/injection in Website field
- [ ] Find the login page URL
- [ ] Check page source for CMS identifiers

---

## Lessons Learned
*(updated as machine progresses)*
