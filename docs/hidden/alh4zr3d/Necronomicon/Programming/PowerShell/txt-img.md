## Description
This function will convert a text file to an image

## [SYNTAX]

### Encode an Image 
```PowerShell
txt-img -txtPath "C:\Users\User\Desktop\text.txt" -imgPath "C:\Users\User\Desktop\img.jpg"
```

## The Function

### [txt-img] 

This function will convert your text file to an image

Use the txtPath tag to provide the path of the text file you are trying to convert

Using the imgPath parameter will set where the image is saved to and what it is saved as

If no imgPath is designated it will save it to the desktop with the name foo.jpg by default

```PowerShell
function txt-img {
[CmdletBinding()]
param (

[Parameter (Mandatory = $True, ValueFromPipeline = $True)]
[string]$txtPath,

[Parameter (Mandatory = $False)]
[string]$imgPath
)

if (!$imgPath) {$imgPath = "$Env:USERPROFILE\Desktop\foo.jpg"}

$content = [IO.File]::ReadAllText($txtPath)
Add-Type -AssemblyName System.Drawing
$bmp = new-object System.Drawing.Bitmap 1920,1080 
$font = new-object System.Drawing.Font Consolas,18 
$brushBg = [System.Drawing.Brushes]::White 
$brushFg = [System.Drawing.Brushes]::Black 
$graphics = [System.Drawing.Graphics]::FromImage($bmp) 
$graphics.FillRectangle($brushBg,0,0,$bmp.Width,$bmp.Height) 
$graphics.DrawString($content,$font,$brushFg,500,100) 
$graphics.Dispose() 
$bmp.Save($imgPath) 
}
```