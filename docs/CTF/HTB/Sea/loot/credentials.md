# Credentials - Sea

| User | Password/Hash | Type | Source | Access Granted | Tested |
|------|---------------|------|--------|----------------|--------|
| WonderCMS admin | $2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q | Bcrypt | database.json | CMS admin panel | ✓ |
| amay | mychemicalromance | Plaintext (cracked) | hashcat -m 3200 | SSH, HTTP Basic (port 8080) | ✓ |
| root | $6$llVzHhr7xHrvx1wJ$gH0PLbyPaIOqLrpjpzGZbM2bZ/iHaOfv/bj1YRrktVeZ8.1KQ0Jr1Rv/TL/3Qdh84Fwec1UhX2v0LVAGsuzq.0 | SHA-512 | /etc/shadow (path traversal) | N/A (not cracked) | - |
| geo | $6$5mAIqOze4GJ4s9Zu$P3IgUSHlcCkKpDJ0862IgP5aqaNilEUZDGIm16FiWdxh1A5dfKjmwhMgp3xctHiHZVWGtmKY25cCrILanDPaG. | SHA-512 | /etc/shadow (path traversal) | N/A (not cracked) | - |

## Notes
- bcrypt hash found in /var/www/sea/data/files/database.json (WonderCMS flat-file store)
- Password `mychemicalromance` cracked from bcrypt hash, reused for SSH as amay AND HTTP Basic on internal port 8080
- Root/geo SHA-512 hashes obtained via path traversal in System Monitor app — not cracked, root shell obtained via SSH key injection instead
