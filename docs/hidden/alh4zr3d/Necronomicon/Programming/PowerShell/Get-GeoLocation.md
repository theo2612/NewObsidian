## Description

This function will get the geo-location of your target 

## The Function

### [Get-GeoLocation] 

Using the Geo-Watcher function you will get the location of your Target saved to the variable $GL

Latitude and Longitude will be saved individually to the the following variables $Lat and $Lon

```PowerShell
function Get-GeoLocation{
	try {
	Add-Type -AssemblyName System.Device #Required to access System.Device.Location namespace
	$GeoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher #Create the required object
	$GeoWatcher.Start() #Begin resolving current locaton

	while (($GeoWatcher.Status -ne 'Ready') -and ($GeoWatcher.Permission -ne 'Denied')) {
		Start-Sleep -Milliseconds 100 #Wait for discovery.
	}  

	if ($GeoWatcher.Permission -eq 'Denied'){
		Write-Error 'Access Denied for Location Information'
	} else {
		$GL = $GeoWatcher.Position.Location | Select Latitude,Longitude #Select the relevent results.
		$GL = $GL -split " "
		$Lat = $GL[0].Substring(11) -replace ".$"
		$Lon = $GL[1].Substring(10) -replace ".$" 
		return $Lat, $Lon


	}
	}
    # Write Error is just for troubleshooting
    catch {Write-Error "No coordinates found" 
    return "No Coordinates found"
    -ErrorAction SilentlyContinue
    } 

}

$Lat, $Lon = Get-GeoLocation
```


Going a step further we can use [Start-Process] to open a tab in the browser with a map of their current location

by navigating to the following URL with the $Lon and $Lat variable plugged into it 

```PowerShell
Start-Process "https://www.latlong.net/c/?lat=$Lat&long=$Lon"
```