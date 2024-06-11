## Description

These functions are used to determine if you have Admin level privledges

## The Function

### [If-Admin-Window] 

This function will let you know if you are currently in an Admin Privledge Level window

```PowerShell
function If-Admin-Window {  
	$user = [Security.Principal.WindowsIdentity]::GetCurrent();
	$isAdmin = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
	
if($isAdmin){
	Write-host 'Is Admin Window' -BackgroundColor DarkRed -ForegroundColor White
	}
	else{
	Write-host 'Not Admin Window' -BackgroundColor DarkBlue -ForegroundColor White
	}
}
```

### [If-Admin] 

This function will run the current user against LocalGroupMember to return True or False if Profile has Admin Privledges

```PowerShell
function If-Admin {
	$user = "$env:COMPUTERNAME\$env:USERNAME"
	$isAdmin = (Get-LocalGroupMember 'Administrators').Name -contains $user
if($isAdmin){
	Write-host 'Is Admin' -BackgroundColor DarkRed -ForegroundColor White
	}
	else{
	Write-host 'Not Admin' -BackgroundColor DarkBlue -ForegroundColor White
	}
}
```