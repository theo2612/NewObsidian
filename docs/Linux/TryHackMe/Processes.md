Processes are programs running on your machine.  
Managed by the kernel  
each process has an ID associated with it, aka PID  
PID increments in the order the process starts  
60th process = PID 60  
  
Viewing processes  
$ ps  
#provides a list of running processes of the users session  
#status code  
#sesson that is running it  
#CPU usage  
#name of the program or command being executed  
  
$ ps aux  
#shows processes run by other users and those that don't run from as session/system processes  
  
$ top  
#shows you real time statistics about processes running on your system  
#refreshes every 10seconds  
#refreshes when you use the arrow keys  
  
Managing processes  
sending signals to kill processes  
$kill 1337  
#kills PID 1337  
  
Signals that can be sent to a process when its killed  
SIGTERM - kill the process, but allow it to do some cleanup tasks beforehand  
SIGKILL - Kill the process, but do not allow it do any cleanup after the fact  
SIGSTOP - Stop/suspend a process  
  
How do processes start?  
Namespaces - The Operating System/OS uses namespaces to split up the resources available on the computer. ie CPU, RAM.  
Like splitting the computer into slices - similar to cake. Processes within that slice will have access to a certain amount of computing power, but it will be a small portion of what is actually available  
Namespaces are great for security-  
Way of isolating processes from another  
Only those in the same namespace will be able to see each other.  
  
systemd  
The process with ID of 0 is a process that is started when the system boots  
This is the system's init on Ubuntu, such as systemd and provides a way of managing a user's processes  
Sits between the OS and the user  
Once a system boots and intializes, systemd is one of the first processes that are started  
Any program or software that we start will start as a child of systemd  
It will be controlled by systemd but will run as it's own process  
  
Getting Processes/Services to start on boot  
Some applications can be started on boot  
ie. Web servers, database servers, file transfer servers  
these services are often critical and are essential to start on boot  
  
systemctl - $ systemctl [option] [service]  
allows us to interact with the systemd process/daemon  
$ systemctl start apache2  
#starts apache webserver  
4 options for systemctl  
start  
stop  
enable  
disable  
  
Backgrounding processes  
add the ‘&’ to the end of your command  
$ echo “Your Face” &  
great for copying files or any command that take a long time.  
$ Ctrl+Z  
used to pause when running a script  
  
Forgrounding processes  
$ fg  
#brings the output back to the screen.