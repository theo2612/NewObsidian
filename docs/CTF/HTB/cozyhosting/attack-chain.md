# CozyHosting — Attack Chain

**Current Path:** Nmap → Web Enum (ffuf) → Spring Boot Identified → Actuator Exposed → Session Hijack (kanderson) → Admin Panel → Command Injection (testing)

## Branch Points

### 1. How to access admin panel?
- **Chosen:** Session hijack via `/actuator/sessions` — stole kanderson's JSESSIONID
- Alternative: Brute force login (slow, not needed)
- Alternative: SQL injection on login form (not tested, wasn't needed)

### 2. Command injection on `/executessh` — which field and separator?
- **Testing:** Both `host` and `username` fields
- Tried: `;`, `` ` ``, `$()`, `|` — none worked yet
- **Next:** `${IFS}` space bypass, review error messages for filtering clues, check `/actuator/mappings`

## Next Steps
- [ ] Review Burp Proxy history for error messages from injection attempts
- [ ] Try `${IFS}` as space substitute in injection payloads
- [ ] Check `/actuator/mappings` for input validation or route details
- [ ] Check `/actuator/env` for any leaked credentials/secrets
- [ ] If injection works → reverse shell → user flag
