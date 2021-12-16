# Log4Shell Enumeration, Mitigation and Attack Detection Tool
### Build 8b, 13th December 2021
_By Datto, For the MSP Community_

## Summary
This is a PowerShell-based script that can be run on a Windows system (it has been neither written for, nor tested with, other platforms) to:
* (Optionally) inoculate the system against Log4Shell attacks with vulnerable Log4j versions by setting the `LOG4J_FORMAT_MSG_NO_LOOKUPS` environment variable to `TRUE`
    * Check whether any JAR files on the system contains code linking it to a vulnerable Log4j version
        * _This is not conclusive and should be used for reference only_
* Using the YARA tool and [Florian Roth's definitions](https://github.com/Neo23x0/signature-base/blob/master/yara/expl_log4j_cve_2021_44228.yar), check all JAR, LOG and TXT files on the system for indicators of Log4Shell attacks

The script was originally developed as a Component for the [Datto RMM software](https://www.datto.com/rmm); however, as part of Datto's ongoing commitment to the MSP, it has been released for free for the Community.

## Usage

Three environment variables _(ie: $env:variableName)_ must be furnished, either by editing the script or by adding them in your runtime environment:
* usrScanScope
    * Value of 1: Only scan home drive (usually C:) _(Fastest scan time)_
    * Value of 2: Scan all fixed and removable drives
    * Value of 3: Scan all drives, including Network drives _(Slowest scan time -- may take several hours)_
* usrUpdateDefs
    * Value of `true`: Download the latest YARA definitions from Florian Roth to scan files against
    * Value of `false`: Use definitions attached
* usrMitigate
    * Value of Y: Inoculate system by setting `LOG4J_FORMAT_MSG_NO_LOOKUPS` environment variable to `TRUE`
    * Value of N: De-inoculate system by setting `LOG4J_FORMAT_MSG_NO_LOOKUPS` environment variable to `FALSE` (Use with caution!)
    * Value of X: Ignore inoculation subroutine entirely

## Included in package

* [Yara](https://github.com/VirusTotal/yara) 4.1.3-1755 (32- & 64-bit) & COPYING document
* Florian Roth's YARA definitions for Log4Shell as of 13th December 2021

## Credits
This script was written by seagull for Datto RMM and the wider MSP Community. It may be freely copied, edited and redistributed provided credits to Datto, seagull & a link to this GitHub repo remain in the comments.  
YARA is a tool by the VirusTotal project. The definitions used here were created by Florian Roth.  
www.datto.com/rmm
