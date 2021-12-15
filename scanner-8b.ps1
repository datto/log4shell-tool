<#
    Log4j Vulnerability (CVE-2021-44228) file scanner [windows] :: build 8b/seagull
    Uses Florian Roth and Jai Minton's research (thank you!)
    RELEASED PUBLICLY for all MSPs, originally a Datto RMM ComStore Component.
    If you use code from this script, please credit Datto & seagull.

    USER VARIABLES:
    usrScanscope  (1/2/3): just home drive / all fixed drives / all drives
    usrUpdateDefs (bool):  download the latest yara definitions from florian?
    usrMitigate   (Y/N/X): ternary option to enable/disable 2.10+ mitigation (or do nothing). https://twitter.com/CyberRaiju/status/1469505680138661890
#>

[string]$varch=[intPtr]::Size*8
$script:varDetection=0
$varEpoch=[int][double]::Parse((Get-Date -UFormat %s))

write-host "Log4j/Log4Shell CVE-2021-44228 Scanning/Mitigation Tool (seagull/Datto)"
write-host "======================================================================="
if ($env:CS_CC_HOST) {
    write-host "Set up a File/Folder Size Monitor against devices"
    write-host "(File/s named $env:PROGRAMDATA\CentraStage\L4Jdetections.txt : is over : 0MB)"
    write-host "to alert proactively if this Component reports signs of infection."
    write-host "======================================================================="
}

#is there already a detections.txt file?
if (test-path "$env:PROGRAMDATA\CentraStage\L4Jdetections.txt" -ErrorAction SilentlyContinue) {
    write-host "- An existing L4JDetections.txt file was found. It has been renamed to:"
    write-host "  $varEpoch-L4JDetections.txt"
    Rename-Item -Path "$env:PROGRAMDATA\CentraStage\L4Jdetections.txt" "$env:PROGRAMDATA\CentraStage\$varEpoch-L4Jdetections.txt" -Force
}

#did the user turn NOLOOKUPS (2.10+ mitigation) on?
switch ($env:usrMitigate) {
    'Y' {
        if ([System.Environment]::GetEnvironmentVariable('LOG4J_FORMAT_MSG_NO_LOOKUPS','machine') -eq 'true') {
            write-host "- Log4j 2.10+ exploit mitigation (LOG4J_FORMAT_MSG_NO_LOOKUPS) already set."
        } else {
            write-host "- Enabling Log4j 2.10+ exploit mitigation: Enable LOG4J_FORMAT_MSG_NO_LOOKUPS"
            [Environment]::SetEnvironmentVariable("LOG4J_FORMAT_MSG_NO_LOOKUPS","true","Machine")
        }
    } 'N' {
        write-host "- Reversing Log4j 2.10+ explot mitigation (enable LOG4J_FORMAT_MSG_NO_LOOKUPS)"
        write-host "  (NOTE: This potentially makes a secure system vulnerable again! Use with caution!)"
        [Environment]::SetEnvironmentVariable("LOG4J_FORMAT_MSG_NO_LOOKUPS","false","Machine")
    } 'X' {
        write-host "- Not adjusting existing LOG4J_FORMAT_MSG_NO_LOOKUPS setting."
    }
}

#map input variable usrScanScope to an actual value
switch ($env:usrScanScope) {
    1   {
        write-host "- Scan scope: Home Drive"
        $script:varDrives=@($env:HomeDrive)
    } 2 {
        write-host "- Scan scope: Fixed & Removable Drives"
        $script:varDrives=Get-WmiObject -Class Win32_logicaldisk | ? {$_.DriveType -eq 2 -or $_.DriveType -eq 3} | ? {$_.FreeSpace} | % {$_.DeviceID}
    } 3 {
        write-host "- Scan scope: All drives, including Network"
        $script:varDrives=Get-WmiObject -Class Win32_logicaldisk | ? {$_.FreeSpace} | % {$_.DeviceID}
    } default {
        write-host "! ERROR: Unable to map scan scope variable to a value. (This should never happen!)"
        write-host "  The acceptable values for env:usrScanScope are:"
        write-host "    1: Scan files on Home Drive"
        write-host "    2: Scan files on fixed and removable drives"
        write-host "    3: Scan files on all detected drives, even network drives"
        exit 1
    }
}

#if user opted to update yara rules, do that
if ($env:usrUpdateDefs -match 'true') {
    [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    $varYaraNew=(new-object System.Net.WebClient).DownloadString('https://github.com/Neo23x0/signature-base/raw/master/yara/expl_log4j_cve_2021_44228.yar')
    #quick verification check
    if ($varYaraNew -match 'TomcatBypass') {
        Set-Content -Value $varYaraNew -Path yara.yar -Force
        write-host "- New YARA definitions downloaded."
    } else {
        write-host "! ERROR: New YARA definition download failed."
        write-host "  Falling back to built-in definitions."
        copy-item -Path expl_log4j_cve_2021_44228.yar -Destination yara.yar -Force
    }
} else {
    copy-item -Path expl_log4j_cve_2021_44228.yar -Destination yara.yar -Force
    write-host "- Not downloading new YARA definitions."
}

#check yara32 and yara64 are there and that they'll run
foreach ($iteration in ('yara32.exe','yara64.exe')) {
    if (!(test-path $iteration)) {
        write-host "! ERROR: $iteration not found. It needs to be in the same directory as the script."
        write-host "  Download Yara from https://github.com/virustotal/yara/releases/latest and place them here."
        exit 1
    } else {
        write-host "- Verified presence of $iteration."
    }

    cmd /c "$iteration -v >nul 2>&1"
    if ($LASTEXITCODE -ne 0) {
        write-host "! ERROR: YARA was unable to run on this device."
        write-host "  The Visual C++ Redistributable is required in order to use YARA."
        if ($env:CS_CC_HOST) {
            write-host "  An installer Component is available from the ComStore."
        }
        exit 1
    }
}

#start a logfile
$host.ui.WriteErrorLine("`r`nPlease expect some permissions errors as some locations are forbidden from traversal.`r`n=====================================================`r`n")
set-content -Path "log.txt" -Force -Value "Files scanned:"
Add-Content "log.txt" -Value "====================================================="
Add-Content "log.txt" -Value " :: Scan Started: $(get-date) ::"


#get a list of all files-of-interest on the device (depending on scope) :: GCI is broken; permissions errors when traversing root dirs cause aborts (!!!)
$arrFiles=@()
foreach ($drive in $varDrives) {
    gci "$drive\" -force | ? {$_.PSIsContainer} | % {
        gci -path "$drive\$_\" -rec -force -include *.jar,*.log,*.txt -ErrorAction 0 | % {
            $arrFiles+=$_.FullName
        }
    }
}

#scan i: JARs containing vulnerable Log4j code
write-host "====================================================="
write-host "- Scanning for JAR files containing potentially insecure Log4j code..."
$arrFiles | ? {$_ -match '\.jar$'} | % {
    if (select-string -Quiet -Path $_ "JndiLookup.class") {
        write-host "! ALERT: Potentially vulnerable file at $($_)!"
        if (!(test-path "$env:PROGRAMDATA\CentraStage\L4Jdetections.txt" -ErrorAction SilentlyContinue)) {set-content -path "$env:PROGRAMDATA\CentraStage\L4Jdetections.txt" -Value "! CAUTION !`r`n$(get-date)"}
        Add-Content "$env:PROGRAMDATA\CentraStage\L4Jdetections.txt" -Value "POTENTIALLY VULNERABLE JAR: $($_)"
        $script:varDetection=1
    }
}

#scan ii: YARA for logfiles & JARs
write-host "====================================================="
write-host "- Scanning LOGs, TXTs and JARs for common attack strings via YARA scan......"
foreach ($file in $arrFiles) {
    if ($file -match 'CentraStage' -or $file -match 'L4Jdetections\.txt') {
        #do nothing -- this isn't a security threat; we're looking at the pathname of the log, not the contents
    } else {
        #add it to the logfile, with a pause for handling
        try {
            Add-Content "log.txt" -Value $file -ErrorAction Stop
        } catch {
            Start-Sleep -Seconds 1
            Add-Content "log.txt" -Value $file -ErrorAction SilentlyContinue
        }

        #scan it
        clear-variable yaResult -ErrorAction SilentlyContinue
        $yaResult=cmd /c "yara$varch.exe `"yara.yar`" `"$file`" -s"
        if ($yaResult) {
            #sound an alarm
            write-host "====================================================="
            $script:varDetection=1
            write-host "! DETECTION:"
            write-host $yaResult
            #write to a file
            if (!(test-path "$env:PROGRAMDATA\CentraStage\L4Jdetections.txt" -ErrorAction SilentlyContinue)) {set-content -path "$env:PROGRAMDATA\CentraStage\L4Jdetections.txt" -Value "! INFECTION DETECTION !`r`n$(get-date)"}
            Add-Content "$env:PROGRAMDATA\CentraStage\L4Jdetections.txt" -Value $yaResult
        }
    }
}

Add-Content "log.txt" -Value " :: Scan Finished: $(get-date) ::"

if ($script:varDetection -eq 1) {
    write-host "====================================================="
    write-host "! Evidence of one or more Log4Shell attack attempts has been found on the system."
    write-host "  The location of the files demonstrating this are noted in the following log:"
    write-host "  $env:PROGRAMDATA\CentraStage\L4Jdetections.txt"
} else {
    write-host "- There is no indication that this system has received Log4Shell attack attempts ."
}

write-host `r
write-host "Datto recommends that you follow best practices with your systems by implementing WAF rules,"
write-host "mitigation and remediation recommendations from your vendors. For more information on Datto's"
write-host "response to the log4j vulnerabilty, please refer to https://www.datto.com/blog/dattos-response-to-log4shell."