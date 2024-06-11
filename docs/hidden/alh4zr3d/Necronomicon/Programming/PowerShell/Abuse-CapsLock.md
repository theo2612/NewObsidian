# Abuse-CapsLock

## Description

These few functions will be different ways that you can take advantage of the CapsLock button 

## The Functions

### [Caps-Indicator] 

This function is meant to serve as an indicator for stages of your scripts 
Using the following function will make the capslock light blink on and off the number of times the variable $num indicates
The blinking will be in intervals of X amount of seconds as indicated by the $pause variable 
Use the following syntax:
(blinks 3 times pausing for a second between each) 

```PowerShell
Caps-Indicator -pause 250 -blinks 3
```

```PowerShell
function Caps-Indicator {

[CmdletBinding()]
param (	
[Parameter (Mandatory = $True, ValueFromPipeline = $True)]
[string]$pause,

[Parameter (Mandatory = $True)]
[int]$blinks
)

$o=New-Object -ComObject WScript.Shell
for($i = 1; $i -le $blinks * 2; $i++) {
    $o.SendKeys("{CAPSLOCK}");Start-Sleep -Milliseconds $pause
    }
}
```

### [Caps-Off] 

This function will make sure capslock is turned back off if one of your other scripts leaves it one

```PowerShell
function Caps-Off {
Add-Type -AssemblyName System.Windows.Forms
$caps = [System.Windows.Forms.Control]::IsKeyLocked('CapsLock')

#If true, toggle CapsLock key, to ensure that the script doesn't fail
if ($caps -eq $true){

$key = New-Object -ComObject WScript.Shell
$key.SendKeys('{CapsLock}')
}
}
```

