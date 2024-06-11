- Exploiting privileged service principals
	- Service principals and managed identities can also have Azure AD roles
	- Often excluded from MFA/conditional access

- Exploiting service principals' permissions on APIs
	- Application permissions don't expect a signed-in user and can often access sensitive data
	- Phishing technique:
		- Use Azure AD consent grant URL to exploit built-in Azure AD permissions flow and trick users into approving an external application