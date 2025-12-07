# Telnet 3270
- TN3270 
- open source client
- x3270
- in clear text encrypted with epsidic
- Free
- provides easy screen recording
# SNA
- System Network Architecture
- Networks before TCP/IP
- Logical Units gets an ID
- Identified in the network 
	- Typically your terminal gets a LU / Logical Unit
# VTAM
- When we connect it is likely the first screen

# Commands
1. LOGON
	1. - LOGON APPLID(TSO) DATA(ROOT)
2. LOGOFF
3. IBMTEST
	1. IBMECHO A ... 9

# TSO 
- Time sharing option
	- Shell environment
	- used to be optional
- The "BASH" shell of  z/OS
- Lot's of commands we can run
- You 'CALL' executables
- You 'EXEC' REXX scripts

# REXX
- Restructured Extender Executor
- Scripting Language
- Preinstalled on all z/OS

# JCL
- Job Control Language
- looks like garbage
- You 'SUBmit' jobs
- Useful to do stuff where you can submit JCL but don't have an interactive terminal

# RACF'd
- Resource Access Control Facility
	- IBM security Product
- Think '[[Active Directory]]' but for your mainframe
- Could also be:
	- CA-TopSecret
	- CA-ACF2
- Most important rights (aka attributes)
	- SPECIAL
		- Make any change to RACF
		- Can't do anything but can give myself the ability to do anything
		- Have the ability to sudo root, if they type the right command
	- OPERATIONS
		- Edit any file

# Virtual Storage
- Memory
- Lot's of important stuff in memory

# APF
- Authorized Program Facility
- Think 'programs with setuid 0'
- Except, it's not access rights
- APF programs can edit ANY region of memory
- RACF, when you log in takes your access rights from the database and puts into a place in memory that is write protected. You as a normal user cannot change it.
- and references that instead of it's DB
- Both SPECIAL and OPERATIONS are one bit flags in your ACEE.
- If we can change our memory than we give ourselves access to whatever we want.
- If we can change these 2 bits then we can own the mainframe.

# CICS
- Customer Information Control System
- Websites before websites existed
- Transaction IDs = URL
	- But they are only 4 characters long
	- I.E. CESN, CSGM, CEDA

#

