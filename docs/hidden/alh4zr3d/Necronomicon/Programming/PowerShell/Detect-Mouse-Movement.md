## Description 

Detecting the mouse movement of a target could be helpful in 2 different situations: finding out if they just came back to their PC or finding out if they stepped away from their PC. These functions will pause your script until one of these conditions are met.

## The Functions

### [Target-Comes] 
In this first function the position of the cursor will be checked every 3 seconds

If the position of the cursor has not changed the capslock button will be pressed every 3 seconds as well

This is to stop the screen from sleeping and use the capslock light as an indicator the function is still waiting 

When the position of the cursor is different the function will break out of the loop and resume the script

This is helpful if you are wanting to run a script once they return to their computer

```PowerShell
function Target-Comes {
Add-Type -AssemblyName System.Windows.Forms
$originalPOS = [System.Windows.Forms.Cursor]::Position.X
$o=New-Object -ComObject WScript.Shell

    while (1) {
        $pauseTime = 3
        if ([Windows.Forms.Cursor]::Position.X -ne $originalPOS){
            break
        }
        else {
            $o.SendKeys("{CAPSLOCK}");Start-Sleep -Seconds $pauseTime
        }
    }
}
```

### [Target-Leaves] 
In the second function the position of the cursor will be checked 

Then the script will sleep for the number of seconds defined by the $PauseTime variable 

If the cursor is in the same position it will break out of the function and continue the script

This is helpful if you are trying to determine if the target is away to run a script while they are gone

```PowerShell
function Target-Leaves {
[CmdletBinding()]
param (	
[Parameter (Position=0, Mandatory = $True)]
[Int]$Seconds
) 
Add-Type -AssemblyName System.Windows.Forms

    while (1) {
	  $originalPOS = [System.Windows.Forms.Cursor]::Position.X
	  Start-Sleep -Seconds $Seconds
        if ([Windows.Forms.Cursor]::Position.X -eq $originalPOS){
            break
        }
        else {
            Start-Sleep -Seconds 1
        }
    }
}
```
