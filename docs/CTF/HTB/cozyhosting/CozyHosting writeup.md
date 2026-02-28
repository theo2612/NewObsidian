# CozyHosting — HTB

**IP:** 10.129.229.88
**OS:** Ubuntu Linux
**Date Started:** 2026-02-21

## Enumeration

### Nmap

Two open ports only:

```
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

- nginx reverse proxying to Spring Boot on `localhost:8080`
- Hostname: `cozyhosting.htb` (added to `/etc/hosts`)

### Web

**Stack:** Spring Boot (confirmed via Whitelabel Error Page on invalid URLs)

**ffuf directory enumeration** (`big.txt`, filtered 403):

| Path | Status | Notes |
|------|--------|-------|
| `/admin` | 401 | Auth required — admin panel |
| `/login` | 200 | Login form (NiceAdmin Bootstrap template) |
| `/logout` | 204 | Logout endpoint |
| `/index` | 200 | Home page |
| `/error` | 500 | Whitelabel error page |

### Spring Boot Actuator (Exposed!)

`/actuator` returned full endpoint listing — **misconfigured, no auth required:**

| Endpoint | Value |
|----------|-------|
| `/actuator/sessions` | Active session IDs with usernames |
| `/actuator/env` | Environment variables |
| `/actuator/mappings` | All API route mappings |
| `/actuator/beans` | Spring beans |
| `/actuator/health` | Health check |

**Key finding:** `/actuator/sessions` leaked active session for `kanderson`:
```
Session ID: 99436176E7884B8F4A0B88D65FE52327
```

### Session Hijacking → Admin Panel

Replaced browser JSESSIONID cookie with kanderson's session token → gained access to `/admin` as **K. Anderson**.

Admin panel features:
- Dashboard with stats (links non-functional)
- **"Include host into automatic patching"** form at bottom
  - Fields: Hostname, Username
  - Posts to: `POST /executessh`
  - Content-Type: `application/x-www-form-urlencoded`
  - Parameters: `host=` and `username=`

### Command Injection Analysis (In Progress)

The `/executessh` endpoint runs SSH with user-supplied input. Error response confirmed input passes directly to SSH command:

```
error=ssh: Could not resolve hostname myotherride.com: Temporary failure in name resolution
```

Backend likely runs: `ssh <username>@<hostname>`

**Tested injection separators (no success yet):**
- Semicolon: `;id`
- Backticks: `` `id` ``
- Command substitution: `$(id)`
- Pipe: `|id`
- Tested both `host` and `username` fields

**Next to try:**
- `${IFS}` as space bypass (spaces may be filtered)
- Check `/actuator/mappings` for input validation clues
- Review Burp Proxy history for exact error responses from each attempt

## Foothold

*Not yet achieved*

## Privilege Escalation

*Not yet achieved*

## Flags
- User: ✗
- Root: ✗

## Lessons Learned

- **Spring Boot Whitelabel Error Page** is a reliable fingerprint → always check `/actuator` endpoints
- **`/actuator/sessions`** can leak active session tokens — trivial session hijacking if exposed
- JSESSIONID cookie swap in browser DevTools is all it takes to hijack a Spring session
- When a web form takes a hostname/username and the backend runs SSH, think **command injection**
- Always intercept with Burp before guessing injection payloads — see the actual request structure first
