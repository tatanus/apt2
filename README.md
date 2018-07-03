[![Github Release Version](https://img.shields.io/github/release/moosedojo/apt2.svg)](https://github.com/MooseDojo/apt2/releases)
[![Python 2.6-2.7](https://img.shields.io/badge/Python-2.6--2.7-yellow.svg)](http://www.python.org/download/)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/MooseDojo/apt2/master/LICENSE.txt)

[![Black Hat USA Arsenal](https://github.com/toolswatch/badges/blob/master/arsenal/2016.svg)](https://www.toolswatch.org/2016/06/the-black-hat-arsenal-usa-2016-remarkable-line-up/) - USA

[![DEFCON 24 Demolabs](https://img.shields.io/badge/DEFCON%2024-Demo%20Labs-red.svg)](https://www.defcon.org/html/defcon-24/dc-24-demolabs.html)

[![Black Hat EU Arsenal](https://github.com/toolswatch/badges/blob/master/arsenal/2016.svg)](https://www.toolswatch.org/2016/09/the-black-hat-arsenal-europe-2016-line-up/) - EU

[![Black Hat ASIA Arsenal](https://github.com/toolswatch/badges/blob/master/arsenal/2018.svg)](https://www.toolswatch.org/2018/01/black-hat-arsenal-asia-2018-great-lineup/) - ASIA

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

***NOTE:*  APT2 is currently only tested on Linux based OSes.  If you can confirm that it works on other OSes, please let us know.**

## Current External Program/Script Dependencies
To make full use of all of APT2's modules, the following external dependencies should be install on your system:

convert, dirb, hydra, java, jexboss, john, ldapsearch, msfconsole, nmap, nmblookup, phantomjs, responder, rpcclient, secretsdump.py, smbclient, snmpwalk, sslscan, xwd

## Configuration (Optional)
APT2 uses the *default.cfg* file in the misc directory. Edit this file to configure APT2 to run as you desire.

##### Metasploit RPC API (metasploit)
APT2 can utuilize your host's Metasploit RPC interface (MSGRPC). Additional Information can be found here: https://metasploit.help.rapid7.com/v1.1/docs/rpc-api

##### NMAP
Configure NMAP scan settings to include the target, scan type, scan port range, and scan flags. These settings can be configured while the program is running.

##### Threading
Configure the number of the threads APT2 will use.

## Run:
#### No Options:
`python apt2.py`
#### With Configuration File
`python apt2.py -C <config.txt>`
#### Import Nexpose, Nessus, or NMap XML
`python apt2.py -f <nmap.xml>`
#### Specify Target Range to Start
`python apt2.py --target 192.168.1.0/24`

## Safe Level
Safe levels indicate how safe a module is to run againsts a target. The scale runs from 1 to 5 with 5 being the safest. The default configuration uses a Safe Level of 4 but can be set with the `-s` or `--safelevel` command line flags.

## Usage:
```
usage: apt2.py [-h] [-C <config.txt>] [-f [<input file> [<input file> ...]]]
               [--target] [--ip <local IP>] [-v] [-s SAFE_LEVEL]
               [-x EXCLUDE_TYPES] [--listmodules]

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbosity       increase output verbosity
  -s SAFE_LEVEL, --safelevel SAFE_LEVEL
                        set min safe level for modules. 0 is unsafe and 5 is
                        very safe. Default is 4
  -x EXCLUDE_TYPES, --exclude EXCLUDE_TYPES
                        specify a comma seperatec list of module types to
                        exclude from running

inputs:
  -C <config.txt>       config file
  -f [<input file> [<input file> ...]]
                        one of more input files seperated by spaces
  --target              initial scan target(s)

advanced:
  --ip <local IP>       defaults to 192.168.100.118

misc:
  --listmodules         list out all current modules and exit
```

## Modules
```
+--------------------------------+--------+------+-----------------------------------------------------------------------------+
| Module                         | Type   | Safe | Description                                                                 |
+--------------------------------+--------+------+-----------------------------------------------------------------------------+
| exploit_hydrasmbpassword       | action | 2    | Attempt to bruteforce SMB passwords                                         |
| exploit_jexboss                | action | 4    | Run JexBoss and look for vulnerabilities                                    |
| exploit_msf_javarmi            | action | 5    | Attempt to Exploit A Java RMI Service                                       |
| exploit_msf_jboss_maindeployer | action | 3    | Attempt to gain shell via Jboss                                             |
| exploit_msf_ms08_067           | action | 4    | Attempt to exploit MS08-067                                                 |
| exploit_msf_ms17_010           | action | 4    | Attempt to exploit MS17-010                                                 |
| exploit_msf_psexec_pth         | action | 4    | Attempt to authenticate via PSEXEC PTH                                      |
| exploit_msf_tomcat_mgr_login   | action | 4    | Attempt to determine if a tomcat instance has default creds                 |
| exploit_msf_tomcat_mgr_upload  | action | 3    | Attempt to gain shell via Tomcat                                            |
| exploit_responder              | action | 3    | Run Responder and watch for hashes                                          |
| post_impacketsecretsdump       | action | 5    | Dump passwords and hashes                                                   |
| post_msf_dumphashes            | action | 4    | Gather hashes from MSF Sessions                                             |
| post_msf_gathersessioninfo     | action | 4    | Get Info about any new sessions                                             |
| scan_anonftp                   | action | 4    | Test for Anonymous FTP                                                      |
| scan_anonldap                  | action | 5    | Test for Anonymous LDAP Searches                                            |
| scan_gethostname               | action | 5    | Determine the hostname for each IP                                          |
| scan_httpoptions               | action | 5    | Get HTTP Options                                                            |
| scan_httpscreenshot            | action | 5    | Get Screen Shot of Web Pages                                                |
| scan_httpserverversion         | action | 5    | Get HTTP Server Version                                                     |
| scan_msf_jboss_vulnscan        | action | 4    | Attempt to determine if a jboss instance has default creds                  |
| scan_msf_openx11               | action | 5    | Attempt Login To Open X11 Service                                           |
| scan_msf_smbuserenum           | action | 5    | Get List of Users From SMB                                                  |
| scan_msf_snmpenumshares        | action | 5    | Enumerate SMB Shares via LanManager OID Values                              |
| scan_msf_snmpenumusers         | action | 5    | Enumerate Local User Accounts Using LanManager/psProcessUsername OID Values |
| scan_msf_snmplogin             | action | 5    | Attempt Login Using Common Community Strings                                |
| scan_msf_vncnoneauth           | action | 5    | Detect VNC Services with the None authentication type                       |
| scan_nmap_msvulnscan           | action | 4    | Nmap MS Vuln Scan                                                           |
| scan_nmap_nfsshares            | action | 5    | NMap NFS Share Scan                                                         |
| scan_nmap_smbshares            | action | 5    | NMap SMB Share Scan                                                         |
| scan_nmap_smbsigning           | action | 5    | NMap SMB-Signing Scan                                                       |
| scan_nmap_sslscan              | action | 5    | NMap SSL Scan                                                               |
| scan_nmap_vnc_auth_bypass      | action | 5    | NMap VNC Auth Bypass                                                        |
| scan_nmap_vncbrute             | action | 5    | NMap VNC Brute Scan                                                         |
| scan_openx11                   | action | 5    | Attempt Login To Open X11 Servicei and Get Screenshot                       |
| scan_rpcclient_nullsession     | action | 5    | Test for NULL Session                                                       |
| scan_rpcclient_userenum        | action | 5    | Get List of Users From SMB                                                  |
| scan_searchsmbshare            | action | 4    | Search files on SMB Shares                                                  |
| scan_smbclient_nullsession     | action | 5    | Test for NULL Session                                                       |
| scan_snmpwalk                  | action | 5    | Run snmpwalk using found community string                                   |
| scan_sslscan                   | action | 5    | Determine SSL protocols and ciphers                                         |
| scan_testsslserver             | action | 5    | Determine SSL protocols and ciphers                                         |
| dictload                       | input  | None | Load DICT Input File                                                        |
| nmaploadxml                    | input  | None | Load NMap XML File                                                          |
| reportgen                      | report | None | Generate HTML Report                                                        |
+--------------------------------+--------+------+-----------------------------------------------------------------------------+


```

## Videos
Demo given at: BlackHat US 2016 Tools Arsenal/Defcon 24 Demo Lab

[![BHUS TA DEMO](https://img.youtube.com/vi/6RJlfc5bVRk/0.jpg)](https://www.youtube.com/watch?v=6RJlfc5bVRk)

Demo given at: BlackHat EU 2016 Tools Arsenal

[![BHEU TA DEMO](https://img.youtube.com/vi/94hk6bNwQfU/0.jpg)](https://www.youtube.com/watch?v=94hk6bNwQfU)
