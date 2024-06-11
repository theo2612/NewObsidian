## Description

This function will convert a PowerShell script to a Batch file

## The Function

### [PowerShell-2-Batch] 

Using this function will convert your powershell payload over to Base64 and then change the extension on it to be a .BAT file

Make the conversion with this function using the following syntax: 

```Powershell
P2B -Path "C:\Users\User\Desktop\example.ps1"
```
or
```PowerShell
"C:\Users\User\Desktop\example.ps1" | P2B
```

```PowerShell
function P2B {
    param
    (
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]
        $Path
    )
 
    process
    {
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes((Get-Content -Path $Path -Raw -Encoding UTF8)))
        $newPath = [Io.Path]::ChangeExtension($Path, ".bat")
        "@echo off`npowershell -w h -NoP -NonI -Exec Bypass -enc $encoded" | Set-Content -Path $newPath -Encoding Ascii
    }
}
```