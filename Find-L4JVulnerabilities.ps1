<#
.SYNOPSIS
    Log4j Vulnerability (CVE-2021-44228) file scanner [windows] :: build 8b/seagull - ProVal Tech Fork
.EXAMPLE
    Runs the scan tool, using Everything (https://www.voidtools.com) to search for files. Updates YARA definitions and adds the env variable LOG4J_FORMAT_MSG_NO_LOOKUPS mitigation.
    PS C:\> .\scanner-8b.ps1 -EverythingSearch -usrUpdateDefs $true -usrMitigate 'Y'
.PARAMETER usrScanscope
    Sets the scope for drive scanning. -EverythingSearch overrides this setting.
    1 - Home drive only
    2 - All non-network drives
    3 - All drives (local and network)
.PARAMETER usrUpdateDefs
    Determines if defintion updates for YARA will be updated before scanning.
    $true - Definitions will be updated.
    $false - Definitions will not be updated.
.PARAMETER usrMitigate
    Determines if the LOG4J_FORMAT_MSG_NO_LOOKUPS mitigation will be applied.
    'Y' - Mitigation will be applied.
    'N' - Mitigation will be removed.
    'X' - Take no action.
.PARAMETER EverythingSearch
    Use this switch to enable searching with Everything (https://www.voidtools.com) instead of Get-ChildItem.
    This will install the PSEverything module from PSGallery and temporarily install the Everything service.
.NOTES
    Uses Florian Roth and Jai Minton's research (thank you!)
    RELEASED PUBLICLY for all MSPs, originally a Datto RMM ComStore Component.
    If you use code from this script, please credit Datto & seagull.
    Fork by ProVal Tech
    Fork Changes:
    - Added param block, preserving initial $env variable usage
    - Changed appropriate paths to point to the location of the script and not the current directory of the shell
    - Editing some formatting
    - Implemented Everything search option
    - Implemented Luna scan from https://github.com/lunasec-io/lunasec/tree/master/tools/log4shell
    - Added Robocopy option before using Get-ChildItem
    - Implemented PowerShell upgrade
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)][ValidateSet(1,2,3)][int]$usrScanscope = $env:usrScanscope,
    [Parameter(Mandatory=$false)][bool]$usrUpdateDefs = [System.Convert]::ToBoolean($env:usrUpdateDefs),
    [Parameter(Mandatory=$false)][ValidateSet('Y','N','X')][char]$usrMitigate = $env:usrMitigate,
    [Parameter(Mandatory=$false)][switch]$EverythingSearch,
    [Parameter(Mandatory=$false)][switch]$UpdatePowershell
)

#region Bootstrap
$logPath = $null
$dataPath = $null
$errorPath = $null
$workingPath = $null
$scriptTitle = $null
$powershellTargetVersion = 5
$powershellOutdated = $false
$powershellUpgraded = $false
$isElevated = $false

function Set-Environment {
    <#
    .SYNOPSIS
        Sets ProVal standard variables for logging and error handling.
    .EXAMPLE
        PS C:\> Set-Environment
    #>
    $scriptObject = Get-Item -Path $script:PSCommandPath
    $script:workingPath = $($scriptObject.DirectoryName)
    $script:logPath = "$($scriptObject.DirectoryName)\$($scriptObject.BaseName)-log.txt"
    $script:dataPath = "$($scriptObject.DirectoryName)\$($scriptObject.BaseName)-data.txt"
    $script:errorPath = "$($scriptObject.DirectoryName)\$($scriptObject.BaseName)-error.txt"
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    $script:isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    Remove-Item -Path $script:logPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $script:dataPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $script:errorPath -Force -ErrorAction SilentlyContinue
    $script:scriptTitle = $scriptObject.BaseName
    Write-Log -Text "-----------------------------------------------" -Type INIT
    Write-Log -Text $scriptTitle -Type INIT
    Write-Log -Text "System: $($env:COMPUTERNAME)" -Type INIT
    Write-Log -Text "User: $($env:USERNAME)" -Type INIT
    Write-Log -Text "OS Bitness: $($env:PROCESSOR_ARCHITECTURE)" -Type INIT
    Write-Log -Text "PowerShell Bitness: $(if([Environment]::Is64BitProcess) {64} else {32})" -Type INIT
    Write-Log -Text "PowerShell Version: $(Get-Host | Select-Object -ExpandProperty Version | Select-Object -ExpandProperty Major)" -Type INIT
    Write-Log -Text "-----------------------------------------------" -Type INIT
}

function Write-LogHelper {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ParameterSetName="String")]
        [AllowEmptyString()]
        [string]$Text,
        [Parameter(Mandatory=$true, ParameterSetName="String")]
        [string]$Type
    )
    $formattedLog = "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))  $($Type.PadRight(8)) $Text"
    switch ($Type) {
        "LOG" { 
            Write-Host -Object $formattedLog
            Add-Content -Path $script:logPath -Value $formattedLog
        }
        "INIT" {
            Write-Host -Object $formattedLog -ForegroundColor White -BackgroundColor DarkBlue
            Add-Content -Path $script:logPath -Value $formattedLog
        }
        "WARN" {
            Write-Host -Object $formattedLog -ForegroundColor Black -BackgroundColor DarkYellow
            Add-Content -Path $script:logPath -Value $formattedLog
        }
        "ERROR" {
            Write-Host -Object $formattedLog -ForegroundColor White -BackgroundColor DarkRed
            Add-Content -Path $script:logPath -Value $formattedLog
            Add-Content -Path $script:errorPath -Value $formattedLog
        }
        "SUCCESS" {
            Write-Host -Object $formattedLog -ForegroundColor White -BackgroundColor DarkGreen
            Add-Content -Path $script:logPath -Value $formattedLog
        }
        "DATA" {
            Write-Host -Object $formattedLog -ForegroundColor White -BackgroundColor Blue
            Add-Content -Path $script:logPath -Value $formattedLog
            Add-Content -Path $script:dataPath -Value $Text
        }
        Default {
            Write-Host -Object $formattedLog
            Add-Content -Path $script:logPath -Value $formattedLog
        }
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a message to a log file, the console, or both.
    .EXAMPLE
        PS C:\> Write-Log -Text "An error occurred." -Type ERROR
        This will write an error to the console, the log file, and the error log file.
    .PARAMETER Text
        The message to pass to the log.
    .PARAMETER Type
        The type of log message to pass in. The options are:
        LOG     - Outputs to the log file and console.
        WARN    - Outputs to the log file and console.
        ERROR   - Outputs to the log file, error file, and console.
        SUCCESS - Outputs to the log file and console.
        DATA    - Outputs to the log file, data file, and console.
        INIT    - Outputs to the log file and console.
    .NOTES
        This function is dependant on being run within a script. This will not work run directly from the console.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position = 0, ParameterSetName="String")]
        [AllowEmptyString()][Alias("Message")]
        [string]$Text,
        [Parameter(Mandatory=$true, Position = 0, ParameterSetName="StringArray")]
        [AllowEmptyString()]
        [string[]]$StringArray,
        [Parameter(Mandatory=$false, Position = 1, ParameterSetName="String")]
        [Parameter(Mandatory=$false, Position = 1, ParameterSetName="StringArray")]
        [string]$Type = "LOG"
    )
    if($script:PSCommandPath -eq '') {
        Write-Error -Message "This function cannot be run directly from a terminal." -Category InvalidOperation
        return
    }
    if($null -eq $script:logPath) {
        Set-Environment
    }

    if($StringArray) {
        foreach($logItem in $StringArray) {
            Write-LogHelper -Text $logItem -Type $Type
        }
    } elseif($Text) {
        Write-LogHelper -Text $Text -Type $Type
    }
}

Register-ArgumentCompleter -CommandName Write-Log -ParameterName Type -ScriptBlock {"LOG","WARN","ERROR","SUCCESS","DATA","INIT"}

function Install-Chocolatey {
    if($env:Path -notlike "*C:\ProgramData\chocolatey\bin*") {
        $env:Path = $env:Path + ';C:\ProgramData\chocolatey\bin'
    }
    [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    if(Test-Path -Path "C:\ProgramData\chocolatey\bin\choco.exe") {
        Write-Log -Text "Chocolatey installation detected." -Type LOG
        choco upgrade chocolatey -y | Out-Null
        choco feature enable -n=allowGlobalConfirmation -confirm | Out-Null
        choco feature disable -n=showNonElevatedWarnings -confirm | Out-Null
        return 0
    } else {
        Write-Log -Text "Chocolatey installation failed." -Type ERROR
        return 1
    }
}

function Update-PowerShell {
    if(-not $isElevated) {
        Write-Log -Text "The current PowerShell session is not elevated. PowerShell will not be upgraded." -Type FAIL
        return
    }
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Force
    $powershellMajorVersion = Get-Host | Select-Object -ExpandProperty Version | Select-Object -ExpandProperty Major
    if($powershellMajorVersion -lt $script:powershellTargetVersion) {
        $script:powershellOutdated = $true
        Write-Log -Text "The version of PowerShell ($powershellMajorVersion) will be upgraded to version $($script:powershellTargetVersion)." -Type LOG
        if($(Install-Chocolatey) -ne 0) {
            Write-Log -Text "Unable to install Chocolatey." -Type ERROR
            return
        }
        try {$powerShellInstalled = $(choco list -le "PowerShell") -like "PowerShell*"} catch {}
        if($powerShellInstalled) {
            Write-Log -Text "PowerShell has already been updated to $powerShellInstalled but is running under version $powershellMajorVersion. Ensure that the machine has rebooted after the update." -Type ERROR
            $script:powershellUpgraded = $true
            return
        }
        Write-Log -Text "Starting PowerShell upgrade." -Type LOG
        cup powershell -y -Force
        Start-Sleep -Seconds 5
        $powerShellInstalled = $(choco list -le "PowerShell") -like "PowerShell*"
        if($powerShellInstalled) {
            Write-Log -Text "Updated to $powerShellInstalled. A reboot is required for this process to continue." -Type LOG
            $script:powershellUpgraded = $true
            return
        } else {
            Write-Log -Text "Something went wrong with the PowerShell upgrade. The process is unable to continue." -Type ERROR
            return
        }
    } else {
        Write-Log -Text "PowerShell is already at or above version $($script:powershellTargetVersion)." -Type LOG
    }
}
Set-Environment
if($UpdatePowershell) {
    Update-PowerShell
}
if($powershellUpgraded) { return }
if($powershellOutdated) { return }
#endregion

#region Process
$skipYARA = $false
$yaraLog = "$workingPath\yara-log.txt"
$lunaLog = "$workingPath\luna-log.txt"
Remove-Item -Path $yaraLog -ErrorAction SilentlyContinue
Remove-Item -Path $lunaLog -ErrorAction SilentlyContinue
[Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
if($EverythingSearch) {
    Write-Log -Text "Everything search requested." -Type LOG
    $portableEverythingURL = "https://www.voidtools.com/Everything-1.4.1.1009.x64.zip"
    $portableEverythingZIP = "$workingPath\Everything.zip"
    $portableEverythingPath = "$workingPath\Everything"
    Write-Log -Text "Downloading Everything search from $portableEverythingURL to $portableEverythingPath." -Type LOG
    if(Test-Path "$portableEverythingPath\everything.exe") {
        Write-Log -Text "Previous installation of portable Everything found. Removing." -Type LOG
        & "$portableEverythingPath\everything.exe" -uninstall-service
        Get-Process -Name Everything -ErrorAction SilentlyContinue | Where-Object {$_.Path -eq "$portableEverythingPath\everything.exe"} -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -Path $portableEverythingZIP -ErrorAction SilentlyContinue
    (New-Object System.Net.WebClient).DownloadFile($portableEverythingURL,$portableEverythingZIP)
    Write-Log -Text "Expanding '$portableEverythingZIP'." -Type LOG
    Remove-Item -Path $portableEverythingPath -Recurse -Force -ErrorAction SilentlyContinue
    Add-Type -Assembly System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($portableEverythingZIP, $portableEverythingPath)
    if (!(Get-Service "Everything" -ErrorAction SilentlyContinue)) {
        Write-Log -Text "Installing Everything service."
        & "$portableEverythingPath\everything.exe" -install-service
    }
    Write-Log -Text "Installing Everything config."
    & "$portableEverythingPath\everything.exe" -install-config "$workingPath\EverythingConfig.ini"
    Write-Log -Text "Reindexing Everything."
    & "$portableEverythingPath\everything.exe" -reindex -close
    if(Get-Module -Name PSEverything -ListAvailable -ErrorAction SilentlyContinue) {
        Write-Log -Text "Importing PSEverything."
        Import-Module -Name PSEverything
    } else {
        Write-Log -Text "Installing PSEverything."
        Install-PackageProvider -Name NuGet -Force -ErrorAction SilentlyContinue
        Register-PSRepository -Default
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
        Install-Module PSEverything
    }
    if(-not (Get-Module -Name PSEverything -ErrorAction SilentlyContinue)) {
        Write-Log -Text "Failed to import PSEverything. Failing back to robocopy." -Type WARN
        & "$portableEverythingPath\everything.exe" -uninstall-service
        $EverythingSearch = $false
        $usrScanScope = 2
    }
}

[string]$varch = [intPtr]::Size * 8
$script:varDetection = 0

switch ($usrMitigate) {
    'Y' {
        if ([System.Environment]::GetEnvironmentVariable("LOG4J_FORMAT_MSG_NO_LOOKUPS", "Machine") -eq 'true') {
            Write-Log -Text "Log4j 2.10+ exploit mitigation (LOG4J_FORMAT_MSG_NO_LOOKUPS) already set."
        } else {
            Write-Log -Text "Enabling Log4j 2.10+ exploit mitigation: Enable LOG4J_FORMAT_MSG_NO_LOOKUPS"
            [Environment]::SetEnvironmentVariable("LOG4J_FORMAT_MSG_NO_LOOKUPS","true", "Machine")
        }
    } 'N' {
        Write-Log -Text "Reversing Log4j 2.10+ exploit mitigation (enable LOG4J_FORMAT_MSG_NO_LOOKUPS)"
        Write-Log -Text "(NOTE: This potentially makes a secure system vulnerable again! Use with caution!)"
        [Environment]::SetEnvironmentVariable("LOG4J_FORMAT_MSG_NO_LOOKUPS","false","Machine")
    } 'X' {
        Write-Log -Text "Not adjusting existing LOG4J_FORMAT_MSG_NO_LOOKUPS setting."
    }
}

#map input variable usrScanScope to an actual value
if($EverythingSearch) {
    Write-Log -Text "Everything search requested. Scanning all possible drives."
    $script:varDrives = @(Get-WmiObject -Class Win32_logicaldisk | Where-Object {$_.DriveType -eq 2 -or $_.DriveType -eq 3} | Where-Object {$_.FreeSpace} | ForEach-Object {$_.DeviceID})
} else {
    switch ($usrScanScope) {
        1 {
            Write-Log -Text "- Scan scope: Home Drive"
            $script:varDrives = @($env:HomeDrive)
        } 2 {
            Write-Log -Text "- Scan scope: Fixed & Removable Drives"
            $script:varDrives = @(Get-WmiObject -Class Win32_logicaldisk | Where-Object {$_.DriveType -eq 2 -or $_.DriveType -eq 3} | Where-Object {$_.FreeSpace} | ForEach-Object {$_.DeviceID})
        } 3 {
            Write-Log -Text "- Scan scope: All drives, including Network"
            $script:varDrives = @(Get-WmiObject -Class Win32_logicaldisk | Where-Object {$_.FreeSpace} | ForEach-Object {$_.DeviceID})
        } default {
            Write-Log -Text "ERROR: Unable to map scan scope variable to a value. (This should never happen!)" -Type ERROR
            Write-Log -Text "The acceptable values for env:usrScanScope are:" -Type ERROR
            Write-Log -Text "1: Scan files on Home Drive" -Type ERROR
            Write-Log -Text "2: Scan files on fixed and removable drives" -Type ERROR
            Write-Log -Text "3: Scan files on all detected drives, even network drives" -Type ERROR
            exit 1
        }
    }
}

#if user opted to update yara rules, do that
if ($usrUpdateDefs) {
    [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    $varYaraNew = (New-Object System.Net.WebClient).DownloadString('https://github.com/Neo23x0/signature-base/raw/master/yara/expl_log4j_cve_2021_44228.yar')
    #quick verification check
    if ($varYaraNew -match 'TomcatBypass') {
        Set-Content -Value $varYaraNew -Path "$workingPath\yara.yar" -Force
        Write-Log -Text "New YARA definitions downloaded."
    } else {
        Write-Log -Text "New YARA definition download failed." -Type WARN
        Write-Log -Text "Falling back to built-in definitions." -Type WARN
        Copy-Item -Path "$workingPath\expl_log4j_cve_2021_44228.yar" -Destination "$workingPath\yara.yar" -Force
    }
} else {
    Copy-Item -Path "$workingPath\expl_log4j_cve_2021_44228.yar" -Destination "$workingPath\yara.yar" -Force
    Write-Log -Text "Not downloading new YARA definitions." -Type WARN
}

#check yara32 and yara64 are there and that they'll run
foreach ($iteration in ('yara32.exe','yara64.exe')) {
    if (!(Test-Path "$workingPath\$iteration")) {
        Write-Log -Text """$workingPath\$iteration"" not found. It needs to be in the same directory as the script." -Type ERROR
        Write-Log -Text "  Download Yara from https://github.com/virustotal/yara/releases/latest and place them here." -Type ERROR
        exit 1
    } else {
        Write-Log -Text "Verified presence of ""$workingPath\$iteration""."
    }

    cmd /c """$workingPath\$iteration"" -v >nul 2>&1"
    if ($LASTEXITCODE -ne 0) {
        Write-Log -Text "YARA was unable to run on this device. This may be due to missing the Visual C++ Redistributable. Skipping YARA scanning." -Type WARN
        Write-Log -Text "This binary can be downloaded here: https://aka.ms/vs/17/release/vc_redist.x64.exe"
        $skipYARA = $true
    }
}

Write-Log -Text "Please expect some permissions errors as some locations are forbidden from traversal." -Type WARN
Write-Log -Text " :: Scan Started: $(get-date) ::"

$arrFiles=@()
if($EverythingSearch) {
    $arrFiles = Search-Everything -Global -Extension "jar","log","txt"
    & "$portableEverythingPath\everything.exe" -uninstall-service
    Get-Process -Name Everything | Where-Object {$_.Path -eq "$portableEverythingPath\everything.exe"} | Stop-Process -Force
} else {
    foreach ($drive in $varDrives) {
        try {
            $roboCopyLogPath = "$workingPath\log4jfilescan.csv"
            Write-Log -Text "Starting robocopy scan of '$drive\' for .jar, .txt, and .log files."
            Remove-Item -Path $roboCopyLogPath -ErrorAction SilentlyContinue
            $robocopyExitCode = (Start-Process -FilePath robocopy -ArgumentList "$drive\ $drive\DOESNOTEXIST1000 *.jar *.txt *.log /S /XJ /L /FP /NS /NC /NDL /NJH /NJS /r:0 /w:0 /LOG:$roboCopyLogPath" -Wait -PassThru).ExitCode
            if((-not (Test-Path -Path "$workingPath\log4jfilescan.csv")) -or ($robocopyExitCode -ge 16)) { throw }
            $filesDetected = Import-Csv -Path $roboCopyLogPath -Header H1 | Select-Object -ExpandProperty H1
            Write-Log -Text "Robocopy found $($filesDetected.Count) files to scan on '$drive\'"
            $arrFiles += $filesDetected
        } catch {
            Write-Log -Text "Robocopy search failed. Falling back to Get-ChildItem." -Type WARN
            $filesDetected = Get-ChildItem -path "$drive\" -Recurse -Force -ErrorAction 0 | Where-Object {$_.Extension -in ".jar",".log",".txt"} | Select-Object -ExpandProperty FullName
            Write-Log -Text "Get-ChildItem found $($filesDetected.Count) files to scan on '$drive\'"
        }
    }
}
Write-Log -Text "Scanning $($arrFiles.Length) total files for potential vulnerabilities."

#scan i: JARs containing vulnerable Log4j code
Write-Log -Text "Scanning for JAR files containing potentially insecure Log4j code."
$arrFiles | Where-Object {$_ -match '\.jar$'} | ForEach-Object {
    Write-Verbose -Message "Running insecure code scan on file '$_'"
    if (Select-String -Quiet -Path $_ "JndiLookup.class") {
        Write-Log -Text "! ALERT: Potentially vulnerable file at $($_)!" -Type WARN
        $script:varDetection = 1
    }
}

if(-not $skipYARA) {
    #scan ii: YARA for logfiles & JARs
    Write-Log -Text "Scanning LOGs, TXTs and JARs for common attack strings via YARA scan."
    foreach ($file in $arrFiles) {
        Write-Verbose -Message "Running YARA scan on file '$file'"
        if ($file -notmatch "Find-L4JVulnerabilities|yara-log|luna-log|L4Jdetections|L4JConsoleLog|luna\.log") {
            $yaResult = $null
            $yaResult = cmd /c """$workingPath\yara$varch.exe"" ""$workingPath\yara.yar"" ""$file"" -s"
            if ($yaResult) {
                Write-Log -Text "====================================================="
                $script:varDetection = 1
                Write-Log -Text "! DETECTION:"
                $yaResultsTruncated = ($yaResult | Select-String -Pattern $file -SimpleMatch)
                foreach($yaEntry in $yaResultsTruncated) {
                    Write-Log -Text $yaEntry
                    Add-Content -Path $yaraLog -Value $yaEntry
                }
                Write-Log -Text "Found $($yaResult.Count - $yaResultsTruncated.Count) examples of attack attempts in file '$file'"
            }
        }
    }
}

Write-Log -Text "Scanning for known vulnerable libraries via Luna scan"
Write-Log -Text "Ref: https://github.com/lunasec-io/lunasec/tree/master/tools/log4shell"
$lunaUrl = "https://github.com/lunasec-io/lunasec/releases/download/v1.6.1-log4shell/log4shell_1.6.1-log4shell_Windows_x86_64.exe"
$lunaPath = "$workingPath\log4shell.exe"
Write-Log -Text "Downloading Luna scanner (log4shell)"
Remove-Item -Path $lunaPath -Force -ErrorAction SilentlyContinue
[Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
(New-Object System.Net.WebClient).DownloadFile($lunaUrl,$lunaPath)
foreach($drive in $script:varDrives) {
    Write-Log -Text "Starting Luna scan for drive '$drive'"
    $lunaResults = @(cmd /c """$lunaPath"" scan --ignore-warnings --no-follow-symlinks --json $drive\ 2>&1")
    Write-Log -Text "Completed Luna scan for drive '$drive'"
    Add-Content -Value $lunaResults -Path $lunaLog
    foreach($entry in $lunaResults) {
        if($entry -match """severity"":") {
            Write-Log -Text "! LUNA DETECTION: $entry"
            $script:varDetection = 1
        }
    }
}
Add-Content $logPath -Value " :: Scan Finished: $(get-date) ::"

if ($script:varDetection -eq 1) {
    Write-Log -Text "====================================================="
    Write-Log -Text "! Evidence of one or more Log4Shell attack attempts, vulnerable files, or vulnerable libraries has been found on the system." -Type WARN
    Write-Log -Text "The location of the files demonstrating this are noted in the following logs:" -Type WARN
    Write-Log -Text "General/JAR file scan log: $logPath" -Type WARN
    Write-Log -Text "YARA Log: $yaraLog" -Type WARN
    Write-Log -Text "Luna Log: $lunaLog" -Type WARN
} else {
    Write-Log -Text "There is no indication that this system has vulnerable files, libraries, or has received Log4Shell attack attempts."
}
#endregion