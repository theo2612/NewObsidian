/etc  
The root directory /etc is a commonplace location to store system files that are used by your OS  
sudoers - contains a list of the user and groups that have permisson to run sudo or commands as the root user  
passwd and shadow - special for linux as they show how your system stores the passwords for each user in encrypted formatting called sha12  
  
/var  
short for variable data.  
stores data that is accessed or written by services or applications running on the system.  
ex log files from running services and apps are written to /var/log  
ex data that is not associated with a specific user  
  
/root  
unlike /home, /root is actually the home for the “root” user.  
this would have their data in /home/root by default  
  
/tmp  
short for temporary  
volatile and used to store data accessed once or twice  
once machine is restarted this file is deleted  
any user can write to this folder