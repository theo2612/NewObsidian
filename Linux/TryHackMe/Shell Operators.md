& - allows you to run commands in the background of your terminal  
add to the end of your command  
  
&& - allows you to combine multiple commands together in one line of your terminal  
$ command1 && command2  
  
> - redirector or takes output from a command (like cat to output a file) and direct it somewhere else  
$ echo hey > welcome  
# prints ‘hey’ to screen but redirects > it to file ‘welcome’  
  
>> - redirector but appends the output rather than replacing  
$ echo hello >> welcome  
#prints ‘hello’ to the screen but redirects and appends >> to the file ‘welcome’