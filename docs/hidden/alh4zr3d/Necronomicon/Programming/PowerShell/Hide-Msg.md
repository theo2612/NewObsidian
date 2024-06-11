## Description

This function can be used to hide a secret message in an image

## The Function

### [Hide-Msg] 

In this function you will provide the path of your image and your secret message using the syntax below

```
Hide-Msg -Path "C:\Users\user\Desktop\secret.jpg" -Message "this is your secret message"
```

```PowerShell
function Hide-Msg {

	[CmdletBinding()]
	param (
	
	[Parameter (Mandatory = $True, ValueFromPipeline = $True)]
	[string]$Path,

	[Parameter (Mandatory = $False)]
	[string]$Message 
	)

	echo "`n`n $Message" > $Env:USERPROFILE\Desktop\foo.txt

	cmd.exe /c copy /b "$Path" + "$Env:USERPROFILE\Desktop\foo.txt" "$Path"

	rm $Env:USERPROFILE\Desktop\foo.txt -r -Force -ErrorAction SilentlyContinue

}
```