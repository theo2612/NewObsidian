## Description

A function to minimize all the apps on your targets screen

## The Function

### [Minimize-Apps] 

A short description of how your function works

```PowerShell
Function Minimize-Apps
{
    $apps = New-Object -ComObject Shell.Application
    $apps.MinimizeAll()
}
```