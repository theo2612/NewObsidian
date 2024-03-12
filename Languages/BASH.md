# Bash Cheat Sheet

## Beginner Concepts

### Basic Commands
```bash
# Basic Commands
pwd         # Print current directory
ls          # List directory contents
cd          # Change directory
mkdir       # Make directory
touch       # Create empty file

# File Operations
cat         # Display file content
cp          # Copy files and directories
mv          # Move or rename files and directories
rm          # Remove files and directories

# Text Manipulation
echo        # Print message
grep        # Search text
sed         # Stream editor
awk         # Text processing

# Text Manipulation
echo        # Print message
grep        # Search text
sed         # Stream editor
awk         # Text processing

# Permissions
chmod       # Change file permissions
chown       # Change file ownership
chgrp       # Change group ownership

# Environment Variables
export      # Set environment variables
env         # Display environment variables
```

## Intermediate Concepts
```bash
# Shell Scripting
#!/bin/bash  # Shebang line
$1, $2, ...  # Positional parameters
if ...; then
    # Code block
fi

# Conditional Statements
if ...; then
    # Code block
elif ...; then
    # Code block
else
    # Code block
fi

# Loops
for ...; do
    # Code block
done

while ...; do
    # Code block
done

# Functions
function_name() {
    # Code block
}
function_name   # Call function

# Command Substitution
variable=$(command)

# Job Control
&           # Run command in background
jobs        # List background jobs
fg          # Bring job to foreground
bg          # Resume job in background

# Redirection and Pipes
>           # Redirect output to file
>>          # Append output to file
<           # Redirect input from file
|           # Pipe output to another command

# Conditionals and Loops with Advanced Commands
find ... -exec ... \;    # Execute command for each file found
xargs ...                # Build and execute command lines from standard input


```




# Introduction
Start scripts with 
```bash
#!/bin/bash
```

Save Scripts to /bin/ directory
```bash
$ cd /bin/
```

Give scripts "execute" permission
```bash
$ chmod +x script.sh
```

To ensure that scripts in ~/bin/ are available, you must add this directory to your PATH within your configuration file
```bash
$ PATH=~/bin:$PATH
```

# Variables
Within bash scripts, or the terminal, varibles are declared by setting the variable name equal to another value. So to set the variable **greeting** to **"Hello"**, syntax would be,
```bash
$ greeting="Hello"
```

To access the value of the variable, use the name of the variable prepended with a dollar sign, **($)**. From previous example, to print the variable to the screen, use the following.
```bash
$ echo $greeting
```

# Conditionals
Use **if** to start the conditional,
followed by the condition in square brackets ([ ]). 
Leave a space between a bracket and the conditional statement! 
**then** begins the code that will run if the condition is met. 
**else** begins the code that will run if the condition is not met. 
Lastly, the conditional is closed with a backwards if, **fi**. 
```bash
if [ $index -lt 5 ]
then
  echo $index
else
  echo 5
fi
```
Above I used -lt which is “less than”. The result of this conditional is that if $index is less than 5, it will print to the screen. If it is 5 or greater, “5” will be printed to the screen.
List of comparison operators for numbers you can use within bash scripts:
* Equal: -eq
* Not equal: -ne
* Less than or equal: -le
* Less than: -lt
* Greater than or equal: -ge
* Greater than: -gt
* Is null: -z
When comparing strings, put the variable into quotes **(`"`)**. This prevents errors if the variable is null or contains spaces. The common operators for comparing strings are:
* Equal: `==`
* Not equal: `!=`
```bash
#!/bin/bash

first_greeting="Nice to meet you!"
later_greeting="How are you?"
greeting_occasion=0 
 

if [ $greeting_occasion -lt 1 ]
then
	echo $first_greeting
else
	echo $later_greeting
fi
```

# Loops
3 different ways to loop
* for - iterate through a list and execute an action at each step
* while - keep looping while the provided condition is true
* until - keep looping until the condition is true

for - iterate through a list and execute an action at each step	
	note below word is being defined at the top of the for loop so there is no $ prepended. we prepend the $ when accessing the value of the variable
```bash
for word in $paragraph
do
  echo $word
done
```


