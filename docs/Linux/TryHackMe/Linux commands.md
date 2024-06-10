echo - outputs text to the screen  
echo “1337 haxor”  
  
whoami - what user I am logged in as  
  
ls - listing contents of directory  
  
cd - change directrory  
  
cat - concatenate - outputs contents of a file  
  
pwd - print working directory  
  
find - finds files  
$ find -name <filename>  
$ find -name *.txt  
#finds all files in working directory ending in .txt  
  
grep - searches contents of files for specific values  
$ grep “81.143.211.90" access.log  
#searches for the file access.log for 81.143.211.90  
  
touch - creates a file  
$ touch note  
#creates file called ‘note’  
  
mkdir - creates a directory/folder  
$ mkdir mydirectory  
#creates directory called ‘mydirectory’  
  
cp - copy a file or folder  
$ cp note note2  
#copy note and give the new file name ‘note2’  
  
mv - move a file or folder  
$ mv note2 note3  
#move/rename note2 as note3  
  
rm - remove a file or folder  
$ rm note  
#removes/deletes file called ‘note’  
$ rm -R mydirectory  
#removes/deletes directory called ‘mydirectory’  
#must include -R  
  
  
file - determine the type of a file  
$ file note  
#show the type of file ‘note’