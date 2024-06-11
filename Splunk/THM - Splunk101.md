To land into the Search App upon login automatically, Edit user-prefs.confs
```powershell
`C:\Program Files\Splunk\etc\apps\user-prefs\default\user-prefs.conf
```
```bash
/opt/splunk/etc/apps/user-pref/default/user-prefs.conf
```
change from this
```
[general_default]
default_namespace = $default
appOrder = search
```
to this 
```
[general_default]
default_namespace = search
appOrder = search
```
then stop and restart services
```powershell
C:\Users\Administrator>net stop splunkd

The Splunkd Service service was stopped successfully.


C:\Users\Administrator>net start splunkd
The Splunkd Service service is starting.....
The Splunkd Service service was started successfully.
```

If you wish to remove an app (or an add-on), you can do so via the command-line.
Below is the command to perform this task on Windows.
```powershell
`C:\Program Files\Splunk\bin>splunk.exe remove app app-name -auth splunk-username:splunk-password`
```


