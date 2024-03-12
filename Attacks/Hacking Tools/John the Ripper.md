# John the Ripper Cheat Sheet

## Typical John the Ripper command that performs a brute force attack with the option to specify threads to speed up the attack. 

```bash
john --format=<hash_format> --wordlist=<wordlist> --fork=<num_processes> <hash_file>
```
- --format=<hash_format>: Specifies the hash format of the input hash(es) to be cracked.
- --wordlist=`<wordlist>`: Specifies the wordlist file containing potential passwords to use for the brute force attack.
- --fork=`<num_processes>`: Specifies the number of processes (threads) to use for parallel processing. This option allows John the Ripper to perform multiple password-cracking attempts concurrently, speeding up the attack. Replace `<num_processes>` with the desired number of threads.


## Beginner Concepts

### Basic Usage
```bash
# Basic Usage
john <hash_file>

# Brute Force Attack
john --format=<hash_format> --wordlist=<wordlist> <hash_file>

# Specifying Hash Format
--format=<hash_format>    # Specify the hash format of the input hash(es)

# Wordlist Attack
--wordlist=<wordlist>     # Specify the wordlist file containing potential passwords

# Show Cracked Passwords
john --show <hash_file>

# Show Progress
john --status=ses <hash_file>

```

## Intermediate Concepts
```bash
# Incremental Mode
john --incremental <hash_file>

# Customizing Incremental Mode
john --incremental=<charset> <hash_file>

# Rules for Wordlist Attack
--rules=<rule_file>    # Specify rules to modify wordlist passwords

# Multiple Hashes
john --format=<hash_format> --wordlist=<wordlist> --fork=<num_processes> <hash_file>

# Customizing Output Format
john --format=<hash_format> --wordlist=<wordlist> --fork=<num_processes> --stdout <hash_file>

# Customizing Cracked Password Output
john --format=<hash_format> --wordlist=<wordlist> --fork=<num_processes> --show <hash_file>

```