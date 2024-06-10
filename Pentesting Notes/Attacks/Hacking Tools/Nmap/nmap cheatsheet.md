# Nmap Cheat Sheet

## Initial port scan
```bash
nmap -T4 -vvv -oN open_port_scan_results.txt <target_ip>
```
- -T4: Sets the timing template to 4, which increases the scan speed while still maintaining accuracy. This means the scan will be conducted more aggressively than the default timing template.
- -vvv: Enables verbose output with maximum verbosity level, providing detailed information about the scan progress in real time. This will display extensive information about the scan process, including open ports, service versions, and potential errors.
- -oN scan_results.txt: Specifies the output format as normal and saves the results to a file named scan_results.txt. The scan results, including the verbose output, will be written to this file.
- <target_ip>: The IP address you want to scan. The scan will be performed on this target IP address.

## Service, version, OS detection and scripts scan
```bash
nmap -p (port, port, port) -A --script=default -vvv <target_ip> -oN service_version_OS_scan_results.txt
```
- -p (list,ports,to,be,scanned): This option specifies the ports to be scanned, similar to the previous explanation. You can specify a comma-separated list of individual ports, port ranges, or port lists.
- -A: This option enables aggressive scan mode, which includes OS detection, version detection, script scanning, and traceroute.
- --script=default: This option specifies the NSE (Nmap Scripting Engine) script to be executed during the scan, as explained before. In this case, the default script category is used.
- -vvv: This option enables maximum verbosity level, providing very detailed and extensive output about the scan progress. It displays a high level of verbosity, useful for debugging or analyzing the scan results in detail.
- <target_ip>: This is the IP address of the target host or network to be scanned, as explained before.
- -oN scan_results.txt: This option specifies the output format as normal and saves the results to a file named scan_results.txt, similar to the previous explanation.

## Beginner Concepts

### Basic Scanning
```bash
# Basic Scanning
nmap <target>      # Scan a single target
nmap <target1> <target2>  # Scan multiple targets

# Scan Types
nmap -sP <target>       # Ping scan (discover hosts)
nmap -sS <target>       # TCP SYN scan
nmap -sT <target>       # TCP connect scan
nmap -sU <target>       # UDP scan
nmap -sV <target>       # Version detection

# Scan Options
nmap -p <port> <target>     # Scan specific port(s)
nmap -F <target>            # Fast scan (100 most common ports)
nmap -T<0-5> <target>       # Timing template (0-5, higher is faster)
nmap -A <target>            # Aggressive scan (OS detection, version detection, script scanning)

# Output Options
nmap -oN output.txt <target>   # Output to normal format
nmap -oX output.xml <target>   # Output to XML format
nmap -oG output.grep <target>  # Output to grepable format
```

## Intermediate Concepts
```bash
# Scripting Engine
nmap --script <script> <target>     # Run specific NSE script(s)
nmap --script-help <script>         # Get help for NSE script

# OS Detection
nmap -O <target>            # Perform OS detection

# Firewall Evasion
nmap -f <target>            # Fragment packets
nmap --mtu <MTU> <target>  # Specify MTU size

# Timing and Performance
nmap -T<0-5> <target>       # Timing template (0-5, higher is faster)
nmap --max-rtt-timeout <time> <target>   # Maximum round trip time timeout

# Scan Optimization
nmap --min-parallelism <num> <target>    # Minimum parallelism level
nmap --min-hostgroup <num> <target>      # Minimum number of hosts per group

# Output Filtering
nmap --open <target>        # Show only open ports
nmap --closed <target>      # Show only closed ports
nmap --host-timeout <time> <target>   # Host timeout value


```