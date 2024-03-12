# Hydra Cheat Sheet

## Hydra basic command with threads to speed up
```bash
hydra -l <username> -P <passwords_file> <target> <service> -t 4 -o hydra_results.txt | tee hydra_output.txt
```
- -l `<username>`: Specifies the username to be used for the login attempts.
- -P `<passwords_file>`: Specifies the file containing the list of passwords to be used for the brute force attack.
- `<target>`: Specifies the target IP address or hostname.
- `<service>`: Specifies the service to be targeted (e.g., ftp, ssh, http).
- -t 4: Specifies a conservative thread count of 4. This means Hydra will perform up to 4 login attempts concurrently.
- -o hydra_results.txt: Specifies the output file where the scan results will be saved.
- | tee hydra_output.txt: This part of the command uses the tee command to redirect the output of Hydra to both the specified output file (hydra_results.txt) and the screen. The tee command copies input from standard input and sends it to both standard output and the specified file.

## Beginner Concepts

### Basic Usage
```bash
# Basic Usage
hydra -l <username> -P <passwords_file> <target> <service>

# Brute Force Attack
hydra -l <username> -P <passwords_file> <target> <service>

# Specifying Username and Password
-l <username>    # Specify a single username
-L <usernames_file>  # Specify a file containing multiple usernames
-P <passwords_file>  # Specify a file containing passwords

# Target and Service
<target>         # IP address or hostname of the target system
<service>        # Service to attack (e.g., ftp, ssh, http)

```

### Intermediate Concepts
```bash
# Customizing Attacks
hydra -l <username> -P <passwords_file> <target> <service> <options>

# Parallel Logins
-M <parallel_logins>   # Specify maximum parallel connections (default: 16)

# User-Agent Spoofing
-H "User-Agent: <user_agent_string>"   # Specify a custom User-Agent header

# Timeout
-e ns -t <timeout>   # Set the timeout for responses (e.g., 5s, 10m)

# Output to File
-o <output_file>    # Save the results to a file

# HTTPS Support
-ssl   # Use SSL/TLS encryption for the connection

# Brute Force Options
-s <port>     # Specify a custom port for the service
-x <min: max: incr>    # Specify a range for password length (e.g., -x 6:8:2)

```