## Description

These two functions can be used to convert an image to and from base64 format

## [SYNTAX]

### Encode an Image 
```PowerShell
img-b64 -img "C:\Users\user\Desktop\image.jpg" -location desk
```
### Decode a File 
```PowerShell
b64-img -file "C:\Users\user\Desktop\image.jpg" -location desk
```
## The Functions

### [img-b64] 

This function will convert your image to base64 format 

Use the image tag to provide the path of the image you are trying to convert

Using the Location parameter will determine if the file containing the base64 code is saved to the desktop or temp folder

If no location is designated it will save it to the desktop by default

```PowerShell
function img-b64 {
[CmdletBinding()]
param (
[Parameter (Mandatory = $True, ValueFromPipeline = $True)]
[string]$img,

[Parameter (Mandatory = $False)]
[ValidateSet('desk', 'temp')]
[string]$location
)

if (!$location) {$location = "desk"}

$loc = switch ( $location )
{
	"desk"  { "$Env:USERPROFILE\Desktop"
	}
	"temp" { "$env:TMP" 
	}
}

[Convert]::ToBase64String((Get-Content -Path $img -Encoding Byte)) >> "$loc\encImage.txt"
}
```

### [b64-img] 

This function will convert your base64 encoded file back into an image 

Use the file tag to provide the path of the file you are trying to convert

Using the Location parameter will determine if the file containing the base64 code is saved to the desktop or temp folder

If no location is designated it will save it to the desktop by default

```PowerShell
function b64-img {
[CmdletBinding()]
param (
[Parameter (Mandatory = $True)]
[string]$file,

[Parameter (Mandatory = $False)]
[ValidateSet('desk', 'temp')]
[string]$location
)

if (!$location) {$location = "desk"}

$loc = switch ( $location )
{
	"desk"  { "$Env:USERPROFILE\Desktop"
	}
	"temp" { "$env:TMP" 
	}
}

Add-Type -AssemblyName System.Drawing
$Base64 = Get-Content -Raw -Path $file
$Image = [Drawing.Bitmap]::FromStream([IO.MemoryStream][Convert]::FromBase64String($Base64))
$Image.Save("$loc\decImage.jpg")
}
```