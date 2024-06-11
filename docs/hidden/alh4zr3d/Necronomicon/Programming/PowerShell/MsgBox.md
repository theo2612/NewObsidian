## Description

This function will make a generic pop up message box 

## The Function

### [MsgBox] 

The title, button, and image parameters are optional.

You can use tab completion on the button and image parameter

Generate a Message Box pop up using the following syntax: 

 ```PowerShell
MsgBox -message 'this is the message body' -title "this is the title" -button OKCancel -image Warning
```
or
```PowerShell
MsgBox -m 'this is the message body' -t "this is the title" -b OKCancel -i Warning
```

```PowerShell
function MsgBox {

[CmdletBinding()]
param (	
[Parameter (Mandatory = $True)]
[Alias("m")]
[string]$message,

[Parameter (Mandatory = $False)]
[Alias("t")]
[string]$title,

[Parameter (Mandatory = $False)]
[Alias("b")]
[ValidateSet('OK','OKCancel','YesNoCancel','YesNo')]
[string]$button,

[Parameter (Mandatory = $False)]
[Alias("i")]
[ValidateSet('None','Hand','Question','Warning','Asterisk')]
[string]$image
)

Add-Type -AssemblyName PresentationCore,PresentationFramework

if (!$title) {$title = " "}
if (!$button) {$button = "OK"}
if (!$image) {$image = "None"}

[System.Windows.MessageBox]::Show($message,$title,$button,$image)

}
```