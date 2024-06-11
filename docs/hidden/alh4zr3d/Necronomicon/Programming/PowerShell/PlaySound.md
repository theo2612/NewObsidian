## Description

Play a sound file from the console window

## The Function

### [PlaySound] 

Pass the path of the sound file into this function to have it play using the following syntax:
```PowerShell
PlaySound "C:\Users\User\AppData\Local\Temp\sound.wav"
```

```PowerShell
function PlaySound {
[CmdletBinding()]
param (	
[Parameter (Mandatory = $True, Position=0, ValueFromPipeline = $True)]
[string]$File
)
$PlaySound=New-Object System.Media.SoundPlayer;$PlaySound.SoundLocation=$File;$PlaySound.playsync()
}
```