To *add user* at cmd line use the following command
```powershell
C:\>net user terrance P@ssw0rd /add
```

To get *information* about a user
```powershell
C:\>net user terrance

C:\>net user superman
```

To *delete* user at cmd line use the following command
```powershell
C:\>net user terrance /del
```

To *exit* the cmd line type exit
```powershell
C:\>exit
```

**Change minimum password length through Group Policy Management GUI**
To open Group Policy Management
* Click *Start*
* Select *Adminstrative Tools*
* Select *Group Policy Management*
* click *+* to expand Forest
* click *+* to expand Domain
* click *+* to expand Organizational Unit (OU)
* right click *Default Domain policy* 
* select *edit*
* click *+* to expand Computer Configuration
* click *+* to expand Policies
* click *+* to expand Windows Settings
* click *+* to expand Security Settings
* click *+* to expand Account Policies
* click on *Password Policy*
* Double-click *Minimum Password Length*
* Change default value of policy setting *password must be at least* from 7 to ??
* Click *ok* to apply the setting to the domain
* Verify the modified minimum password with visual check on password Policy summary page
* to update the policy change go to CMD
```powershell
C:\>gpupdate /force
```
* test new policy by trying add a new user with password less than 10 char - below fails
```powershell
C:\>net user peaches P@ssw0rd /add
```
* * test new policy by trying add a new user with password less than 10 char - below succeds
```powershell
C:\>net user peaches P@ssw0rd12 /add
```





