# Default Browser

## Description

This function will get the default browser of your targets PC

## The Function

### [Get-DefaultBrowser] 

This function will make a call to the registry to get the default Browser using the following syntax: 

`$Default-Browser = Get-DefaultBrowser`

```PowerShell
function Get-DefaultBrowser{

# Param([parameter(Mandatory=$true)][alias("Computer")]$ComputerName)
$ComputerName = hostname 
$Registry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
$RegistryKey = $Registry.OpenSubKey("SOFTWARE\\Classes\\http\\shell\\open\\command")
#Get (Default) Value
$Value = $RegistryKey.GetValue("")
 
return $Value
}
```