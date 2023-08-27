1) Install Access Control Lists
2) Create your directory or skip if you have a directory
3) Check the existing permissions of the directory
4) Create your new group to grant access to. You can use existing groups, but I like to create groups based on what they will have access to.
5) Add your new group as secondary groups to each user you want to assign access to
6) Assign permissions using that long command. I will break it down further down in the message
7) Check your new permissions to see that your new group now has whatever level of access you granted (rwx, in this case)
8) You can either grep for your group name or just cat out the file of /etc/group to see what users are in that group and have access

The command is:
sudo setfacl -Rm g:GROUPNAME:rwx,d:g:GROUPNAME:rwx /DIR

setfacl = Sets the File Access Control List access
-R = Recursive (optional, if you want recursive)
m = Modify the permissions

g: = Group. You can also use u: to grant permissions to a user. I highly suggest not doing that. There can be exceptions, but groups are always a good choice
GROUPNAME: = The name that you created for your group. Generally, at work, I will use some sort of naming scheme for this group, such as the team who has access and what level of access or maybe the service that this group has access to (usually more for the sudoers stuff). Something like hackers_rwx for your hacking users or hacker_ro for read only (rx). However you want to name it. Make it meaningful.
rwx = the level of access you want to assign
,d = set the default ACLs for new files created within. When you run this command without the default, then it only applies to files in the directory now. Same applies with running chown root:root /dir. You only apply them once and any new files do not inherit these changes.
Next part repeats the previous, but these are the defaults you want for new files.
/DIR = wherever you want to assign permissions.

Do not use on CHOWN and CHMOD for additional permissions!
![[Pasted image 20230114113828.png]]
![[Pasted image 20230114113845.png]]
![[Pasted image 20230114113857.png]]


sudo setfacl -Rm g:GROUPNAME:rwx,d:g:GROUPNAME:rwx /DIR (replace the groupname with a group you have made specifically for access and DIR with the directory). You can then assign recursive permissions on a directory without screwing with the owners. It also sets the default ACLs for newly created files. Make sure you create a group to use first and add the user to that group.