# Setting an Organizational Level Policy in [[Active Directory]]
* Click *start*
* Select *Adminstrative tools*
* Select *Group Policy Management
* Expand selected *forest*
* Expand *Domains*
* Expand selected *domain*
* Right click on selected *Organizational Unit (OU)*
* select *Create a GPO in this domain, and link it here*
* Enter new GPO name in field *Name*
* Click *ok*
* expand selected *Organizational Unit (OU)*
* right click new GPO created under (OU) *Name*
* select *edit*
* expand *User configuration*
* expand *Policies*
* expand *Administrative Templates*
* double click *Control Panel*
* double click *Prohibit access to Control Panel*
* click *Enabled* button
* click *ok*
* visual double check on Control Panel summary page it is enabled
* cmd gpupdate /force
```powershell
C:\>gpupdate /force
```
* Use the following command to add user 'zombie' to the backup operators group
```powershell
C:\>net localgroup "backup operators" zombie /add
```
* Use the following command to view the backup operators group
```powershell
C:\>net localgroup "backup operators"
```
* type logoff to reboot
* after reboot, login with user you created to double check that control panel access has been removed