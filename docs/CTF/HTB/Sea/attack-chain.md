# Attack Chain - Sea

## Current Path
```
Nmap scan → SSH (22) + HTTP (80) → /etc/hosts (sea.htb) →
ffuf directory fuzzing → data/, messages/, plugins/, themes/ (301s) →
contact.php found (registration form) → login page found →
CMS identification needed
```

## Branch Points
- **After nmap:** Only 2 ports, web-focused box → web enumeration
- **ffuf results:** Directory structure suggests CMS (plugins/, themes/) → need to identify which CMS

## Next Steps
- [ ] Identify the CMS
- [ ] Fuzz subdirectories
- [ ] Investigate contact.php inputs
- [ ] Find and test login page
