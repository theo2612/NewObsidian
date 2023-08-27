- Volatility is an open-source memory forensics toolkit written in python
- Volatility allows us to analyse memory dumps taken from Windows, Linux and Mac OS devices and is an extremely popular tool in memory forensics
- Volatility allows us to
	- List all processes that were running on the device at the time of the capture
	- List active and closed network connections
	- Use Yara rules to search for indicators of malware
	- Retrieve hashed passwords, clipboard contents, and contents of the command prompt

run with
```bash
python3 vol.py
```


```shell-session
cmnatic@aoc2022-day-11:~/volatility3$ python3 vol.py -h
Volatility 3 Framework 2.4.1
usage: volatility [-h] [-c CONFIG] [--parallelism [{processes,threads,off}]] [-e EXTEND] [-p PLUGIN_DIRS] [-s SYMBOL_DIRS] [-v] [-l LOG] [-o OUTPUT_DIR] [-q]
                  [-r RENDERER] [-f FILE] [--write-config] [--save-config SAVE_CONFIG] [--clear-cache] [--cache-path CACHE_PATH] [--offline]
                  [--single-location SINGLE_LOCATION] [--stackers [STACKERS [STACKERS ...]]]
                  [--single-swap-locations [SINGLE_SWAP_LOCATIONS [SINGLE_SWAP_LOCATIONS ...]]]
                  plugin ...

An open-source memory forensics framework

optional arguments:
  -h, --help            Show this help message and exit, for specific plugin options use 'volatility  --help'
  -c CONFIG, --config CONFIG
```

|Option|Descrption|Example|
|---|---|---|
|-f |This argument is where you provide the name and location of the memory dump that you wish to analyse.|`python3 vol.py -f /path/to/my/memorydump.vmem` |
|-v |This argument increases the verbosity of Volatility. This is sometimes useful to understand what Volatility is doing in cases of debugging. |`python3 vol.py -v` |
|-p |This argument allows you to override the default location of where plugins are stored. |`python3 vol.py -p /path/to/my/custom/plugins` | 
|-o |This argument allows you to specify where extracted processes or DLLs are stored. |`python3 vol.py -o /output/extracted/files/here` |

|Plugin|Description|Objective|
|-|-|-|
|windows.pslist|This plugin lists all of the processes that were running at the time of the capture.|To discover what processes were running on the system.|
|windows.psscan|This plugin allows us to analyse a specific process further.|To discover what a specific process was actually doing.  |
|windows.dumpfiles|This plugin allows us to export the process, where we can perform further analysis (i.e. static or dynamic analysis).|To export a specific binary that allows us further to analyse it through static or dynamic analysis.  |
|windows.netstat|This plugin lists all network connections at the time of the cpture.|To understand what connections were being made. For example, was a process causing the computer to connect to a malicious server? We can use this IP address to implement defensive measures on other devices. For example, if we know an IP address is malicious, and another device is communicating with it, then we know that device is also infected.|
