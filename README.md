[![Github Release Version](https://img.shields.io/github/release/moosedojo/apt2.svg)](https://github.com/MooseDojo/apt2/releases)
[![Python 2.6-2.7](https://img.shields.io/badge/Python-2.6--2.7-yellow.svg)](http://www.python.org/download/)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/MooseDojo/apt2/master/LICENSE.txt)
[![Black Hat USA Arsenal](https://www.toolswatch.org/badges/arsenal/2016.svg)](https://www.blackhat.com/us-16/arsenal.html)
[![Black Hat EU Arsenal](https://www.toolswatch.org/badges/arsenal/2016.svg)](https://www.blackhat.com/eu-16/arsenal.html)

# APT2 - An Automated Penetration Testing Toolkit

```
       dM.    `MMMMMMMb. MMMMMMMMMM
      ,MMb     MM    `Mb /   MM   \
      d'YM.    MM     MM     MM   ____
     ,P `Mb    MM     MM     MM  6MMMMb
     d'  YM.   MM    .M9     MM MM'  `Mb
    ,P   `Mb   MMMMMMM9'     MM      ,MM
    d'    YM.  MM            MM     ,MM'
   ,MMMMMMMMb  MM            MM   ,M'
   d'      YM. MM            MM ,M'
 _dM_     _dMM_MM_          _MM_MMMMMMMM


 An Automated Penetration Testing Toolkit
```
This tool will perform an NMap scan, or import the results of a scan from Nexpose, Nessus, or NMap. The processesd results will be used to launch exploit and enumeration modules according to the configurable Safe Level and enumerated service information.

All module results are stored on localhost and are part of APT2's Knowledge Base (KB). The KB is accessible from within the application and allows the user to view the harvested results of an exploit module.

## Setup

***NOTE:*  APT2 is currently only tested on Linux based OSes.  If you can confirm that it works on other OSes, please let us know.**

On Kali Linux install python-nmap library:
python setup.py install

## Current External Program/Script Dependencies
To make full use of all of APT2's modules, the following external dependencies should be install on your system:

convert, dirb, hydra, java, john, ldapsearch, msfconsole, nmap, nmblookup, phantomjs, responder, rpcclient, secretsdump.py, smbclient, snmpwalk, sslscan, xwd

## Configuration (Optional)
APT2 uses the *default.cfg* file in the misc directory. Edit this file to configure APT2 to run as you desire.

Current options include:
- metasploit
- nmap
- threading

##### Metasploit RPC API (metasploit)
APT2 can utuilize your host's Metasploit RPC interface (MSGRPC). Additional Information can be found here: https://metasploit.help.rapid7.com/v1.1/docs/rpc-api

##### NMAP
Configure NMAP scan settings to include the target, scan type, scan port range, and scan flags. These settings can be configured while the program is running.

##### Threading
Configure the number of the threads APT2 will use.

## Run:
#### No Options:
`apt2`
#### With Configuration File
`apt2 -C <config.txt>`
#### Import Nexpose, Nessus, or NMap XML
`apt2 -f <nmap.xml>`
#### Specify Target Range to Start
`apt2 --target 192.168.1.0/24`

## Safe Level
Safe levels indicate how safe a module is to run againsts a target. The scale runs from 1 to 5 with 5 being the safest. The default configuration uses a Safe Level of 4 but can be set with the `-s` or `--safelevel` command line flags.

## Usage:
```
usage: apt2 [-h] [-C <config.txt>] [-f [<input file> [<input file> ...]]]
               [--target] [--ip <local IP>] [-v] [-s SAFE_LEVEL] [-b]
               [--listmodules]

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbosity       increase output verbosity
  -s SAFE_LEVEL, --safelevel SAFE_LEVEL
                        set min safe level for modules
  -b, --bypassmenu      bypass menu and run from command line arguments

inputs:
  -C <config.txt>       config file
  -f [<input file> [<input file> ...]]
                        one of more input files seperated by spaces
  --target              initial scan target(s)

ADVANCED:
  --ip <local IP>       defaults to ip of interface

misc:
  --listmodules         list out all current modules

```

## Modules
```
-----------------------
LIST OF CURRENT MODULES
-----------------------
nmaploadxml               Load NMap XML File
hydrasmbpassword          Attempt to bruteforce SMB passwords
nullsessionrpcclient      Test for NULL Session
msf_snmpenumshares        Enumerate SMB Shares via LanManager OID Values
nmapbasescan              Standard NMap Scan
impacketsecretsdump       Test for NULL Session
msf_dumphashes            Gather hashes from MSF Sessions
msf_smbuserenum           Get List of Users From SMB
anonftp                   Test for Anonymous FTP
searchnfsshare            Search files on NFS Shares
crackPasswordHashJohnTR   Attempt to crack any password hashes
msf_vncnoneauth           Detect VNC Services with the None authentication type
nmapsslscan               NMap SSL Scan
nmapsmbsigning            NMap SMB-Signing Scan
responder                 Run Responder and watch for hashes
msf_openx11               Attempt Login To Open X11 Service
nmapvncbrute              NMap VNC Brute Scan
msf_gathersessioninfo     Get Info about any new sessions
nmapsmbshares             NMap SMB Share Scan
userenumrpcclient         Get List of Users From SMB
httpscreenshot            Get Screen Shot of Web Pages
httpserverversion         Get HTTP Server Version
nullsessionsmbclient      Test for NULL Session
openx11                   Attempt Login To Open X11 Servicei and Get Screenshot
msf_snmplogin             Attempt Login Using Common Community Strings
msf_snmpenumusers         Enumerate Local User Accounts Using LanManager/psProcessUsername OID Values
httpoptions               Get HTTP Options
nmapnfsshares             NMap NFS Share Scan
msf_javarmi               Attempt to Exploit A Java RMI Service
anonldap                  Test for Anonymous LDAP Searches
ssltestsslserver          Determine SSL protocols and ciphers
gethostname               Determine the hostname for each IP
sslsslscan                Determine SSL protocols and ciphers
nmapms08067scan           NMap MS08-067 Scan
msf_ms08_067              Attempt to exploit MS08-067
```

## Videos
Demo given at: BlackHat US 2016 Tools Arsenal/Defcon 24 Demo Lab

[![BHUS TA DEMO](https://img.youtube.com/vi/6RJlfc5bVRk/0.jpg)](https://www.youtube.com/watch?v=6RJlfc5bVRk)

Demo given at: BlackHat EU 2016 Tools Arsenal

[![BHEU TA DEMO](https://img.youtube.com/vi/94hk6bNwQfU/0.jpg)](https://www.youtube.com/watch?v=94hk6bNwQfU)
