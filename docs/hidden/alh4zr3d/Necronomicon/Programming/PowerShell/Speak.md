## Description
Speaks through your targets speakers

## The Function

### [Speak] 

Using SAPI.SpVoice you will feed strings to the functions to have it speak through your targets speakers using the following syntax 

```PowerShell
speak "you have been hacked"
```

```Powershell
function speak {

[CmdletBinding()]
param (	
[Parameter (Position=0,Mandatory = $True)]
[string]$Sentence
) 

$s=New-Object -ComObject SAPI.SpVoice
$s.Rate = -2
$s.Speak($Sentence)
}
```