$ touch file-1 file-2  
#This command will create two files, named file-1 and file-2 respectively, in your current working directory.  
  
$ find file*  
#As you can see, the command outputs both of your files.  
  
$ find *1  
#Only file-1 is in the output  
  
$ find /  
# searches the whole filesystem  
  
$ find / -type d -name “*exploits*"  
# searches the whole filesystem for directories whose name contains “explains”  
  
$ find / -type f -name “*.xml”  
# find all files whose name ends with “.xml”  
  
$ find /home -type f -iname user.txt  
find all files in the /home directory (recursive) whose name is “user.txt” case insensitve  
  
  
$ find / -type f -user kittycat  
#Find all files owned by the user "kittycat"  
  
$ find / -type f -size 150c  
#Find all files that are exactly 150 bytes in size  
  
$ find /home -type f size -2k -name “*.txt”  
#Find all files in the /home directory (recursive) with size less than 2 KiB’s and extension ".txt"  
  
$ find / -type f -perm 644  
#Find all files that are exactly readable and writeable by the owner, and readable by everyone else (use octal format)  
  
$ find / -type f -perm /444  
#Find all files that are only readable by anyone (use octal format)  
  
$ find / -type f -perm -o=w -name “*.sh”  
#Find all files with write permission for the group "others", regardless of any other permissions, with extension ".sh" (use symbolic format)  
  
$ find /usr/bin -type f -user root -perm -u=s  
#Find all files in the /usr/bin directory (recursive) that are owned by root and have at least the SUID permission (use symbolic format)  
  
$ find / -type f -atime +10 -name "*.png"  
#Find all files that were not accessed in the last 10 days with extension ".png"  
  
$ find /usr/bin -type f -mmin -120  
#Find all files in the /usr/bin directory (recursive) that have been modified within the last 2 hours  
  
$ find / -type f -name 2> /dev/null  
# You can save the results of the search to a file, and more importantly, you can suppress the output of any possible errors to make the output more readable.