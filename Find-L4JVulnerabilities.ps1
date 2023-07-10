<#
.SYNOPSIS
    Log4j Vulnerability (CVE-2021-44228) file scanner [windows] :: build 8b/seagull - ProVal Tech Fork
.EXAMPLE
    Runs the scan tool, using Everything (https://www.voidtools.com) to search for files. Updates YARA definitions and adds the env variable LOG4J_FORMAT_MSG_NO_LOOKUPS mitigation.
    PS C:\> .\scanner-8b.ps1 -EverythingSearch -usrUpdateDefs $true -usrMitigate 'Y' 

       Runs the scan tool, using Everything (https://www.voidtools.com) to search for files and compare the secure md5 hashes with respect to the CVE-2021-44228.
    PS C:\> .\scanner-8b.ps1 -EverythingSearch -usrMitigate 'Y' -SkipYARA -SkipLuna
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
.PARAMETER SkipYara
    Use this switch to skip YARA scan
.PARAMETER SkipLuna
    Use this switch to skip Luna scan
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
    [Parameter()][ValidateSet(1, 2, 3)][int]$usrScanscope = $env:usrScanscope,
    [Parameter()][bool]$usrUpdateDefs = [System.Convert]::ToBoolean($env:usrUpdateDefs),
    [Parameter()][ValidateSet('Y', 'N', 'X')][char]$usrMitigate = $env:usrMitigate,
    [Parameter()][switch]$EverythingSearch,
    [Parameter()][switch]$UpdatePowershell,
    [Parameter()][switch]$skipYARA,
    [Parameter()][switch]$skipLuna
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
    Write-Log -Text '-----------------------------------------------' -Type INIT
    Write-Log -Text $scriptTitle -Type INIT
    Write-Log -Text "System: $($env:COMPUTERNAME)" -Type INIT
    Write-Log -Text "User: $($env:USERNAME)" -Type INIT
    Write-Log -Text "OS Bitness: $($env:PROCESSOR_ARCHITECTURE)" -Type INIT
    Write-Log -Text "PowerShell Bitness: $(if([Environment]::Is64BitProcess) {64} else {32})" -Type INIT
    Write-Log -Text "PowerShell Version: $(Get-Host | Select-Object -ExpandProperty Version | Select-Object -ExpandProperty Major)" -Type INIT
    Write-Log -Text '-----------------------------------------------' -Type INIT
}

function Write-LogHelper {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'String')]
        [AllowEmptyString()]
        [string]$Text,
        [Parameter(Mandatory = $true, ParameterSetName = 'String')]
        [string]$Type
    )
    $formattedLog = "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))  $($Type.PadRight(8)) $Text"
    switch ($Type) {
        'LOG' { 
            Write-Host -Object $formattedLog
            Add-Content -Path $script:logPath -Value $formattedLog
        }
        'INIT' {
            Write-Host -Object $formattedLog -ForegroundColor White -BackgroundColor DarkBlue
            Add-Content -Path $script:logPath -Value $formattedLog
        }
        'WARN' {
            Write-Host -Object $formattedLog -ForegroundColor Black -BackgroundColor DarkYellow
            Add-Content -Path $script:logPath -Value $formattedLog
        }
        'ERROR' {
            Write-Host -Object $formattedLog -ForegroundColor White -BackgroundColor DarkRed
            Add-Content -Path $script:logPath -Value $formattedLog
            Add-Content -Path $script:errorPath -Value $formattedLog
        }
        'SUCCESS' {
            Write-Host -Object $formattedLog -ForegroundColor White -BackgroundColor DarkGreen
            Add-Content -Path $script:logPath -Value $formattedLog
        }
        'DATA' {
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
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'String')]
        [AllowEmptyString()][Alias('Message')]
        [string]$Text,
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'StringArray')]
        [AllowEmptyString()]
        [string[]]$StringArray,
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'String')]
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'StringArray')]
        [string]$Type = 'LOG'
    )
    if ($script:PSCommandPath -eq '') {
        Write-Error -Message 'This function cannot be run directly from a terminal.' -Category InvalidOperation
        return
    }
    if ($null -eq $script:logPath) {
        Set-Environment
    }

    if ($StringArray) {
        foreach ($logItem in $StringArray) {
            Write-LogHelper -Text $logItem -Type $Type
        }
    }
    elseif ($Text) {
        Write-LogHelper -Text $Text -Type $Type
    }
}

Register-ArgumentCompleter -CommandName Write-Log -ParameterName Type -ScriptBlock { 'LOG', 'WARN', 'ERROR', 'SUCCESS', 'DATA', 'INIT' }

function Install-Chocolatey {
    if ($env:Path -notlike '*C:\ProgramData\chocolatey\bin*') {
        $env:Path = $env:Path + ';C:\ProgramData\chocolatey\bin'
    }
    [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    if (Test-Path -Path 'C:\ProgramData\chocolatey\bin\choco.exe') {
        Write-Log -Text 'Chocolatey installation detected.' -Type LOG
        choco upgrade chocolatey -y | Out-Null
        choco feature enable -n=allowGlobalConfirmation -confirm | Out-Null
        choco feature disable -n=showNonElevatedWarnings -confirm | Out-Null
        return 0
    }
    else {
        Write-Log -Text 'Chocolatey installation failed.' -Type ERROR
        return 1
    }
}

function Update-PowerShell {
    if (-not $isElevated) {
        Write-Log -Text 'The current PowerShell session is not elevated. PowerShell will not be upgraded.' -Type FAIL
        return
    }
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Force
    $powershellMajorVersion = Get-Host | Select-Object -ExpandProperty Version | Select-Object -ExpandProperty Major
    if ($powershellMajorVersion -lt $script:powershellTargetVersion) {
        $script:powershellOutdated = $true
        Write-Log -Text "The version of PowerShell ($powershellMajorVersion) will be upgraded to version $($script:powershellTargetVersion)." -Type LOG
        if ($(Install-Chocolatey) -ne 0) {
            Write-Log -Text 'Unable to install Chocolatey.' -Type ERROR
            return
        }
        try { $powerShellInstalled = $(choco list -le 'PowerShell') -like 'PowerShell*' } catch {}
        if ($powerShellInstalled) {
            Write-Log -Text "PowerShell has already been updated to $powerShellInstalled but is running under version $powershellMajorVersion. Ensure that the machine has rebooted after the update." -Type ERROR
            $script:powershellUpgraded = $true
            return
        }
        Write-Log -Text 'Starting PowerShell upgrade.' -Type LOG
        cup powershell -y -Force
        Start-Sleep -Seconds 5
        $powerShellInstalled = $(choco list -le 'PowerShell') -like 'PowerShell*'
        if ($powerShellInstalled) {
            Write-Log -Text "Updated to $powerShellInstalled. A reboot is required for this process to continue." -Type LOG
            $script:powershellUpgraded = $true
            return
        }
        else {
            Write-Log -Text 'Something went wrong with the PowerShell upgrade. The process is unable to continue.' -Type ERROR
            return
        }
    }
    else {
        Write-Log -Text "PowerShell is already at or above version $($script:powershellTargetVersion)." -Type LOG
    }
}
Set-Environment
if ($UpdatePowershell) {
    Update-PowerShell
}
if ($powershellUpgraded) { return }
if ($powershellOutdated) { return }
#endregion

#region Process
#$skipYARA = $false
if (!($skipYARA)) {
    $yaraLog = "$workingPath\yara-log.txt"
    Remove-Item -Path $yaraLog -ErrorAction SilentlyContinue
}
if (!($skipluna)) {
    $lunaLog = "$workingPath\luna-log.txt"
    Remove-Item -Path $lunaLog -ErrorAction SilentlyContinue
}
[Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
if ($EverythingSearch) {
    Write-Log -Text 'Everything search requested.' -Type LOG
    $portableEverythingURL = 'https://www.voidtools.com/Everything-1.4.1.1009.x64.zip'
    $portableEverythingZIP = "$workingPath\Everything.zip"
    $portableEverythingPath = "$workingPath\Everything"
    Write-Log -Text "Downloading Everything search from $portableEverythingURL to $portableEverythingPath." -Type LOG
    if (Test-Path "$portableEverythingPath\everything.exe") {
        Write-Log -Text 'Previous installation of portable Everything found. Removing.' -Type LOG
        & "$portableEverythingPath\everything.exe" -uninstall-service
        Get-Process -Name Everything -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq "$portableEverythingPath\everything.exe" } -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -Path $portableEverythingZIP -ErrorAction SilentlyContinue
    (New-Object System.Net.WebClient).DownloadFile($portableEverythingURL, $portableEverythingZIP)
    Write-Log -Text "Expanding '$portableEverythingZIP'." -Type LOG
    Remove-Item -Path $portableEverythingPath -Recurse -Force -ErrorAction SilentlyContinue
    Add-Type -Assembly System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($portableEverythingZIP, $portableEverythingPath)
    if (!(Get-Service 'Everything' -ErrorAction SilentlyContinue)) {
        Write-Log -Text 'Installing Everything service.'
        & "$portableEverythingPath\everything.exe" -install-service
    }
    Write-Log -Text 'Installing Everything config.'
    & "$portableEverythingPath\everything.exe" -install-config "$workingPath\EverythingConfig.ini"
    Write-Log -Text 'Reindexing Everything.'
    & "$portableEverythingPath\everything.exe" -reindex -close
    if (Get-Module -Name PSEverything -ListAvailable -ErrorAction SilentlyContinue) {
        Write-Log -Text 'Importing PSEverything.'
        Import-Module -Name PSEverything
    }
    else {
        Write-Log -Text 'Installing PSEverything.'
        Install-PackageProvider -Name NuGet -Force -ErrorAction SilentlyContinue
        Register-PSRepository -Default
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
        Install-Module PSEverything
    }
    if (-not (Get-Module -Name PSEverything -ErrorAction SilentlyContinue)) {
        Write-Log -Text 'Failed to import PSEverything. Failing back to robocopy.' -Type WARN
        & "$portableEverythingPath\everything.exe" -uninstall-service
        $EverythingSearch = $false
        $usrScanScope = 2
    }
}

[string]$varch = [intPtr]::Size * 8
$script:varDetection = 0

switch ($usrMitigate) {
    'Y' {
        if ([System.Environment]::GetEnvironmentVariable('LOG4J_FORMAT_MSG_NO_LOOKUPS', 'Machine') -eq 'true') {
            Write-Log -Text 'Log4j 2.10+ exploit mitigation (LOG4J_FORMAT_MSG_NO_LOOKUPS) already set.'
        }
        else {
            Write-Log -Text 'Enabling Log4j 2.10+ exploit mitigation: Enable LOG4J_FORMAT_MSG_NO_LOOKUPS'
            [Environment]::SetEnvironmentVariable('LOG4J_FORMAT_MSG_NO_LOOKUPS', 'true', 'Machine')
        }
    } 'N' {
        Write-Log -Text 'Reversing Log4j 2.10+ exploit mitigation (enable LOG4J_FORMAT_MSG_NO_LOOKUPS)'
        Write-Log -Text '(NOTE: This potentially makes a secure system vulnerable again! Use with caution!)'
        [Environment]::SetEnvironmentVariable('LOG4J_FORMAT_MSG_NO_LOOKUPS', 'false', 'Machine')
    } 'X' {
        Write-Log -Text 'Not adjusting existing LOG4J_FORMAT_MSG_NO_LOOKUPS setting.'
    }
}

#map input variable usrScanScope to an actual value
if ($EverythingSearch) {
    Write-Log -Text 'Everything search requested. Scanning all possible drives.'
    $script:varDrives = @(Get-CimInstance -Class Win32_logicaldisk | Where-Object { $_.DriveType -eq 2 -or $_.DriveType -eq 3 } | Where-Object { $_.FreeSpace } | ForEach-Object { $_.DeviceID })
}
else {
    switch ($usrScanScope) {
        1 {
            Write-Log -Text '- Scan scope: Home Drive'
            $script:varDrives = @($env:HomeDrive)
        } 2 {
            Write-Log -Text '- Scan scope: Fixed & Removable Drives'
            $script:varDrives = @(Get-CimInstance -Class Win32_logicaldisk | Where-Object { $_.DriveType -eq 2 -or $_.DriveType -eq 3 } | Where-Object { $_.FreeSpace } | ForEach-Object { $_.DeviceID })
        } 3 {
            Write-Log -Text '- Scan scope: All drives, including Network'
            $script:varDrives = @(Get-CimInstance -Class Win32_logicaldisk | Where-Object { $_.FreeSpace } | ForEach-Object { $_.DeviceID })
        } default {
            Write-Log -Text 'ERROR: Unable to map scan scope variable to a value. (This should never happen!)' -Type ERROR
            Write-Log -Text 'The acceptable values for env:usrScanScope are:' -Type ERROR
            Write-Log -Text '1: Scan files on Home Drive' -Type ERROR
            Write-Log -Text '2: Scan files on fixed and removable drives' -Type ERROR
            Write-Log -Text '3: Scan files on all detected drives, even network drives' -Type ERROR
            exit 1
        }
    }
}

#if user opted to update yara rules, do that
if (!($skipYARA)) {
    if ($usrUpdateDefs) {
        [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
        $varYaraNew = (New-Object System.Net.WebClient).DownloadString('https://github.com/Neo23x0/signature-base/raw/master/yara/expl_log4j_cve_2021_44228.yar')
        #quick verification check
        if ($varYaraNew -match 'TomcatBypass') {
            Set-Content -Value $varYaraNew -Path "$workingPath\yara.yar" -Force
            Write-Log -Text 'New YARA definitions downloaded.'
        }
        else {
            Write-Log -Text 'New YARA definition download failed.' -Type WARN
            Write-Log -Text 'Falling back to built-in definitions.' -Type WARN
            Copy-Item -Path "$workingPath\expl_log4j_cve_2021_44228.yar" -Destination "$workingPath\yara.yar" -Force
        }
    }
    else {
        Copy-Item -Path "$workingPath\expl_log4j_cve_2021_44228.yar" -Destination "$workingPath\yara.yar" -Force
        Write-Log -Text 'Not downloading new YARA definitions.' -Type WARN
    }

    #check yara32 and yara64 are there and that they'll run
    foreach ($iteration in ('yara32.exe', 'yara64.exe')) {
        if (!(Test-Path "$workingPath\$iteration")) {
            Write-Log -Text """$workingPath\$iteration"" not found. It needs to be in the same directory as the script." -Type ERROR
            Write-Log -Text '  Download Yara from https://github.com/virustotal/yara/releases/latest and place them here.' -Type ERROR
            exit 1
        }
        else {
            Write-Log -Text "Verified presence of ""$workingPath\$iteration""."
        }

        cmd /c """$workingPath\$iteration"" -v >nul 2>&1"
        if ($LASTEXITCODE -ne 0) {
            Write-Log -Text 'YARA was unable to run on this device. This may be due to missing the Visual C++ Redistributable. Skipping YARA scanning.' -Type WARN
            Write-Log -Text 'This binary can be downloaded here: https://aka.ms/vs/17/release/vc_redist.x64.exe'
            $skipYARA = $true
        }
    }
}
Write-Log -Text 'Please expect some permissions errors as some locations are forbidden from traversal.' -Type WARN
Write-Log -Text " :: Scan Started: $(Get-Date) ::"

$arrFiles = @()
if ($EverythingSearch) {
    $arrFiles = Search-Everything -Global -Extension 'jar', 'log', 'txt'
    & "$portableEverythingPath\everything.exe" -uninstall-service
    Get-Process -Name Everything | Where-Object { $_.Path -eq "$portableEverythingPath\everything.exe" } | Stop-Process -Force
}
else {
    foreach ($drive in $varDrives) {
        try {
            $roboCopyLogPath = "$workingPath\log4jfilescan.csv"
            Write-Log -Text "Starting robocopy scan of '$drive\' for .jar, .txt, and .log files."
            Remove-Item -Path $roboCopyLogPath -ErrorAction SilentlyContinue
            $robocopyExitCode = (Start-Process -FilePath robocopy -ArgumentList "$drive\ $drive\DOESNOTEXIST1000 *.jar *.txt *.log /S /XJ /L /FP /NS /NC /NDL /NJH /NJS /r:0 /w:0 /LOG:$roboCopyLogPath" -Wait -PassThru -NoNewWindow).ExitCode
            if ((-not (Test-Path -Path "$workingPath\log4jfilescan.csv")) -or ($robocopyExitCode -ge 16)) { throw }
            $filesDetected = Import-Csv -Path $roboCopyLogPath -Header H1 | Select-Object -ExpandProperty H1
            Write-Log -Text "Robocopy found $($filesDetected.Count) files to scan on '$drive\'"
            $arrFiles += $filesDetected
        }
        catch {
            Write-Log -Text 'Robocopy search failed. Falling back to Get-ChildItem.' -Type WARN
            $filesDetected = Get-ChildItem -Path "$drive\" -Recurse -Force -ErrorAction 0 | Where-Object { $_.Extension -in '.jar', '.log', '.txt' } | Select-Object -ExpandProperty FullName
            Write-Log -Text "Get-ChildItem found $($filesDetected.Count) files to scan on '$drive\'"
            $arrFiles += $filesDetected
        }
    }
}
Write-Log -Text "Scanning $($arrFiles.Length) total files for potential vulnerabilities."
#region Ticket T20221228.0055
$MD5_BAD = @{
    # JndiManager.class (source: https://github.com/nccgroup/Cyber-Defence/blob/master/Intelligence/CVE-2021-44228/modified-classes/md5sum.txt)
    '04fdd701809d17465c17c7e603b1b202' = 'log4j 2.9.0 - 2.11.2'
    '21f055b62c15453f0d7970a9d994cab7' = 'log4j 2.13.0 - 2.13.3'
    '3bd9f41b89ce4fe8ccbf73e43195a5ce' = 'log4j 2.6 - 2.6.2'
    '415c13e7c8505fb056d540eac29b72fa' = 'log4j 2.7 - 2.8.1'
    '5824711d6c68162eb535cc4dbf7485d3' = 'log4j 2.12.0 - 2.12.1'
    '102cac5b7726457244af1f44e54ff468' = 'log4j 2.12.2'
    '6b15f42c333ac39abacfeeeb18852a44' = 'log4j 2.1 - 2.3'
    '8b2260b1cce64144f6310876f94b1638' = 'log4j 2.4 - 2.5'
    'a193703904a3f18fb3c90a877eb5c8a7' = 'log4j 2.8.2'
    'f1d630c48928096a484e4b95ccb162a0' = 'log4j 2.14.0 - 2.14.1'
    '5d253e53fa993e122ff012221aa49ec3' = 'log4j 2.15.0'
    'ba1cf8f81e7b31c709768561ba8ab558' = 'log4j 2.16.0'
}

# Known GOOD
$MD5_GOOD = @{
    '3dc5cf97546007be53b2f3d44028fa58' = 'log4j 2.17.0'
    '3c3a43af0930a658716b870e66db1569' = 'log4j 2.17.1'
}

[System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem') | Out-Null
Write-Log -Text 'Scanning for JAR files containing potentially insecure Log4j code.'
$arrFiles | Where-Object { $_ -match '\.jar$' } | ForEach-Object {
    Write-Verbose -Message "Running insecure code scan on file '$_'"
    $jarFile = Get-Item -LiteralPath $_
    $jarExtractDirectory = "$env:TEMP\$($jarFile.BaseName)"
    Remove-Item -LiteralPath $jarExtractDirectory -Recurse -Force -ErrorAction SilentlyContinue
    [System.IO.Compression.ZipFile]::ExtractToDirectory($_, $jarExtractDirectory) 2>$null | Out-Null
    $jndiManagerFiles = Get-ChildItem -LiteralPath $jarExtractDirectory -Recurse -File -Filter '*JNDIManager.class*'
    foreach ($jndiManagerFile in $jndiManagerFiles) {
        #found a matching jndimanager.class file.
        $checksum = (Get-FileHash -Algorithm MD5 -Path $jndiManagerFile.FullName).Hash
        if ($checksum -in $MD5_BAD.keys) {
            #moving alert down to test path for the lookup class to verify undeniably that this is a found issue.
            #Changing this to a log rather than a warn, because, just because it's found in the bad list doesn't mean it's effected until it goes into the next check.
            Write-Log -Text "MD5 found in bad list referencing $($MD5_BAD.$checksum)" -Type Log
            #if it's bad, check for jndilookup.class, it will be two directories up under the lookup directory.
            $parentOfParentDirectory = $jndiManagerFile.Directory.Parent
            if (Test-Path "$parentOfParentDirectory\lookup\JndiLookup.class") {
                #Write-Host "lookupclass file found on $_"
                Write-Log -Text "! Alert: The MD5 hash for $jarfile was found in the bad list and the jndilookup.class file was verified to exist at $parentOfParentDirectory\lookup\JndiLookup.class, this file needs to be patched." -Type WARN
                $script:varDetection = 1
            }
            else {
                #Write-Host "lookupclass file didn't found on $_"
                Write-Log -Text "The MD5 hash for $jarfile was found in the bad list but the jndilookup.class file doesn't exist." -Type Log
                $script:varDetection = 1
            }
        }
        elseif ($checksum -in $MD5_GOOD.keys) {
            Write-Log -Text "MD5 found in good list referencing $($MD5_BAD.$checksum)" -Type Log
        }  
        else {
            Write-Log -Text 'MD5 was not found in any list' -Type Log
        }
    }
}

#endregion
if (-not $skipYARA) {
    #scan ii: YARA for logfiles & JARs
    Write-Log -Text 'Scanning LOGs, TXTs and JARs for common attack strings via YARA scan.'
    foreach ($file in $arrFiles) {
        Write-Verbose -Message "Running YARA scan on file '$file'"
        if ($file -notmatch 'Find-L4JVulnerabilities|yara-log|luna-log|L4Jdetections|L4JConsoleLog|luna\.log') {
            $yaResult = $null
            $yaResult = & "$workingPath\yara$varch.exe" "$workingPath\yara.yar" "$file" -s
            if ($yaResult) {
                Write-Log -Text '====================================================='
                $script:varDetection = 1
                Write-Log -Text '! DETECTION:'
                $yaResultsTruncated = ($yaResult | Select-String -Pattern $file -SimpleMatch)
                foreach ($yaEntry in $yaResultsTruncated) {
                    Write-Log -Text $yaEntry
                    Add-Content -Path $yaraLog -Value $yaEntry
                }
                Write-Log -Text "Found $($yaResult.Count - $yaResultsTruncated.Count) examples of attack attempts in file '$file'"
            }
        }
    }
}
if (!($skipluna)) {
    Write-Log -Text 'Scanning for known vulnerable libraries via Luna scan'
    Write-Log -Text 'Ref: https://github.com/lunasec-io/lunasec/tree/master/tools/log4shell'
    $lunaUrl = 'https://github.com/lunasec-io/lunasec/releases/download/v1.6.1-log4shell/log4shell_1.6.1-log4shell_Windows_x86_64.exe'
    $lunaPath = "$workingPath\log4shell.exe"
    Write-Log -Text 'Downloading Luna scanner (log4shell)'
    Remove-Item -Path $lunaPath -Force -ErrorAction SilentlyContinue
    [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
(New-Object System.Net.WebClient).DownloadFile($lunaUrl, $lunaPath)
    foreach ($drive in $script:varDrives) {
        Write-Log -Text "Starting Luna scan for drive '$drive'"
        $lunaResults = & $lunaPath scan --ignore-warnings --no-follow-symlinks --json $drive\ 2>&1
        Write-Log -Text "Completed Luna scan for drive '$drive'"
        Add-Content -Value $lunaResults -Path $lunaLog
        foreach ($entry in $lunaResults) {
            if ($entry -match '"severity":') {
                Write-Log -Text "! LUNA DETECTION: $entry"
                $script:varDetection = 1
            }
        }
    }
}
Add-Content $logPath -Value " :: Scan Finished: $(Get-Date) ::"

if ($script:varDetection -eq 1) {
    Write-Log -Text '====================================================='
    Write-Log -Text '! Evidence of one or more Log4Shell attack attempts, vulnerable files, or vulnerable libraries has been found on the system.' -Type WARN
    Write-Log -Text 'The location of the files demonstrating this are noted in the following logs:' -Type WARN
    Write-Log -Text "General/JAR file scan log: $logPath" -Type WARN
    if (!($skipYARA)) {
        Write-Log -Text "YARA Log: $yaraLog" -Type WARN
    }
    if (!($skipluna)) {
        Write-Log -Text "Luna Log: $lunaLog" -Type WARN
    }
}
else {
    Write-Log -Text 'There is no indication that this system has vulnerable files, libraries, or has received Log4Shell attack attempts.'
}
#endregion
# SIG # Begin signature block
# MIInbQYJKoZIhvcNAQcCoIInXjCCJ1oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBG68M279Uj3wB4
# YbtTsiRavq970DGDIpvrgLYoStYJxKCCILUwggXYMIIEwKADAgECAhEA5CcElfaM
# kdbQ7HtJTqTfHDANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJQTDEiMCAGA1UE
# ChMZVW5pemV0byBUZWNobm9sb2dpZXMgUy5BLjEnMCUGA1UECxMeQ2VydHVtIENl
# cnRpZmljYXRpb24gQXV0aG9yaXR5MSIwIAYDVQQDExlDZXJ0dW0gVHJ1c3RlZCBO
# ZXR3b3JrIENBMB4XDTE4MDkxMTA5MjY0N1oXDTIzMDkxMTA5MjY0N1owfDELMAkG
# A1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMRgwFgYD
# VQQKDA9TU0wgQ29ycG9yYXRpb24xMTAvBgNVBAMMKFNTTC5jb20gUm9vdCBDZXJ0
# aWZpY2F0aW9uIEF1dGhvcml0eSBSU0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQD5D92jK33L0Cr+7GeFpucuG7p34eP1r6Ts+kpdkcRXR2sYd2t28v2T
# 5D0PwhaeC2bDVpSeF4OFzlbv8hb9AGL1IglU6GUXTkG54E9Gl6obyLhuYl5psV/b
# KgJ+/GzK80HY7dDo/D9hSO2wAxQdEA5LGeC7TuyGZf82815nAgudhlVh/Xo47f7i
# GQC3b6FQYnV0PKD6yCWStG56Isf4HqHjst2RMasrHQT/pUoEN+mFpDMr/eLWVTR8
# GaRKaMeyqNO3yqGTiOvBl7yM+R3ZIoQkdMcEPWqpKZPM67hb4f5fJao0WMjBI1Sd
# G5gRwzicfj2GbKUPQIZ8AvRcAk8oy65xnw86yDP+ESU16vy6xWA92XwY1bKp03V4
# A3IiyjrDH+8s5S6p+p4stlFG/a8D1upgaOqFFjZrhekewLPdxCTcgCqBQW2UPsjg
# yYFBAJ5ev3/FCJiiGCxCQLP5bzgnS06A9D2BR+CIfOoczrV1XFEuHCt/GnIo5wC1
# 0XTG1+SfrQeTtlM1Nfw35MP2XRa+IXPekgr4oGNqvJaSaj74vGVVm971DYkmBPwl
# GqYlacvCbcp84llfl6zr7y7IvNcbWTwrzPIZyJNrJ2MZz/zpJvjKcZt/k/40Z4RO
# mev8s3gJM3C6ZqZ27Rtz6xqlDcQiEyCUVgpOLGxOsf3PnAm6ojPthwIDAQABo4IB
# UTCCAU0wEgYDVR0TAQH/BAgwBgEB/wIBAjAdBgNVHQ4EFgQU3QQJB6L1en1SUxKS
# le44gCUNplkwHwYDVR0jBBgwFoAUCHbNywf/JPbFze27kLzihDdGdfcwDgYDVR0P
# AQH/BAQDAgEGMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9zc2xjb20uY3JsLmNl
# cnR1bS5wbC9jdG5jYS5jcmwwcwYIKwYBBQUHAQEEZzBlMCkGCCsGAQUFBzABhh1o
# dHRwOi8vc3NsY29tLm9jc3AtY2VydHVtLmNvbTA4BggrBgEFBQcwAoYsaHR0cDov
# L3NzbGNvbS5yZXBvc2l0b3J5LmNlcnR1bS5wbC9jdG5jYS5jZXIwOgYDVR0gBDMw
# MTAvBgRVHSAAMCcwJQYIKwYBBQUHAgEWGWh0dHBzOi8vd3d3LmNlcnR1bS5wbC9D
# UFMwDQYJKoZIhvcNAQELBQADggEBAB+VmiNU7oXC89RvuekEj0Z/LPcywKdDrAcA
# 7eCpRS39F+HtAEDIr5is9cAZrRuglzBAbOxb+6OTToyJYht88Dpfp0LPWMp1ZZwi
# TL92e5iTnBWDM7EO3FE4h3yVnBJplB4AeHR+3MAGd7pwLYcs12id47qFrUnzj2S0
# FQaDksaXpECTi63xZ5S0uVpnVDyoG9kFz+Sk+YgSAAaIJYXUXu7zk1fWgfgsrvf1
# UUirtmI6edvsLvI/FFY6yNnLpKJPJajRm6stMCBQBxpv8fGUHTmDY+gf/UnQ6B1G
# skaCJr2cneGiaEFIUW56/DWW9FTSvCtE5UfXd4KlSqtflzOrJBEwggZyMIIEWqAD
# AgECAghkM1HTxzifCDANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzEOMAwG
# A1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24xGDAWBgNVBAoMD1NTTCBDb3Jw
# b3JhdGlvbjExMC8GA1UEAwwoU1NMLmNvbSBSb290IENlcnRpZmljYXRpb24gQXV0
# aG9yaXR5IFJTQTAeFw0xNjA2MjQyMDQ0MzBaFw0zMTA2MjQyMDQ0MzBaMHgxCzAJ
# BgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjERMA8G
# A1UECgwIU1NMIENvcnAxNDAyBgNVBAMMK1NTTC5jb20gQ29kZSBTaWduaW5nIElu
# dGVybWVkaWF0ZSBDQSBSU0EgUjEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQCfgxNzqrDGbSHL24t6h3TQcdyOl3Ka5LuINLTdgAPGL0WkdJq/Hg9Q6p5t
# ePOf+lEmqT2d0bKUVz77OYkbkStW72fL5gvjDjmMxjX0jD3dJekBrBdCfVgWQNz5
# 1ShEHZVkMGE6ZPKX13NMfXsjAm3zdetVPW+qLcSvvnSsXf5qtvzqXHnpD0OctVIF
# D+8+sbGP0EmtpuNCGVQ/8y8Ooct8/hP5IznaJRy4PgBKOm8yMDdkHseudQfYVdIY
# yQ6KvKNc8HwKp4WBwg6vj5lc02AlvINaaRwlE81y9eucgJvcLGfE3ckJmNVz68Qh
# o+Uyjj4vUpjGYDdkjLJvSlRyGMwnh/rNdaJjIUy1PWT9K6abVa8mTGC0uVz+q0O9
# rdATZlAfC9KJpv/XgAbxwxECMzNhF/dWH44vO2jnFfF3VkopngPawismYTJboFbl
# SSmNNqf1x1KiVgMgLzh4gL32Bq5BNMuURb2bx4kYHwu6/6muakCZE93vUN8BuvIE
# 1tAx3zQ4XldbyDgeVtSsSKbt//m4wTvtwiS+RGCnd83VPZhZtEPqqmB9zcLlL/Hr
# 9dQg1Zc0bl0EawUR0tOSjAknRO1PNTFGfnQZBWLsiePqI3CY5NEv1IoTGEaTZeVY
# c9NMPSd6Ij/D+KNVt/nmh4LsRR7Fbjp8sU65q2j3m2PVkUG8qQIDAQABo4H7MIH4
# MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU3QQJB6L1en1SUxKSle44gCUN
# plkwMAYIKwYBBQUHAQEEJDAiMCAGCCsGAQUFBzABhhRodHRwOi8vb2NzcHMuc3Ns
# LmNvbTARBgNVHSAECjAIMAYGBFUdIAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwOwYD
# VR0fBDQwMjAwoC6gLIYqaHR0cDovL2NybHMuc3NsLmNvbS9zc2wuY29tLXJzYS1S
# b290Q0EuY3JsMB0GA1UdDgQWBBRUwv4QlQCTzWr158DX2bJLuI8M4zAOBgNVHQ8B
# Af8EBAMCAYYwDQYJKoZIhvcNAQELBQADggIBAPUPJodwr5miyvXWyfCNZj05gtOI
# I9iCv49UhCe204MH154niU2EjlTRIO5gQ9tXQjzHsJX2vszqoz2OTwbGK1mGf+tz
# G8rlQCbgPW/M9r1xxs19DiBAOdYF0q+UCL9/wlG3K7V7gyHwY9rlnOFpLnUdTsth
# HvWlM98CnRXZ7WmTV7pGRS6AvGW+5xI+3kf/kJwQrfZWsqTU+tb8LryXIbN2g9KR
# +gZQ0bGAKID+260PZ+34fdzZcFt6umi1s0pmF4/n8OdX3Wn+vF7h1YyfE7uVmhX7
# eSuF1W0+Z0duGwdc+1RFDxYRLhHDsLy1bhwzV5Qe/kI0Ro4xUE7bM1eV+jjk5hLb
# q1guRbfZIsr0WkdJLCjoT4xCPGRo6eZDrBmRqccTgl/8cQo3t51Qezxd96JSgjXk
# tefTCm9r/o35pNfVHUvnfWII+NnXrJlJ27WEQRQu9i5gl1NLmv7xiHp0up516eDa
# p8nMLDt7TAp4z5T3NmC2gzyKVMtODWgqlBF1JhTqIDfM63kXdlV4cW3iSTgzN9vk
# bFnHI2LmvM4uVEv9XgMqyN0eS3FE0HU+MWJliymm7STheh2ENH+kF3y0rH0/NVjL
# w78a3Z9UVm1F5VPziIorMaPKPlDRADTsJwjDZ8Zc6Gi/zy4WZbg8Zv87spWrmo2d
# zJTw7XhQf+xkR6OdMIIGdjCCBF6gAwIBAgIQeVwkxuz4snsBAPX7/vbayDANBgkq
# hkiG9w0BAQsFADB4MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNV
# BAcMB0hvdXN0b24xETAPBgNVBAoMCFNTTCBDb3JwMTQwMgYDVQQDDCtTU0wuY29t
# IENvZGUgU2lnbmluZyBJbnRlcm1lZGlhdGUgQ0EgUlNBIFIxMB4XDTIyMDkwODE4
# MTExNloXDTIzMDkwNzE4MTExNlowfzELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB0Zs
# b3JpZGExGjAYBgNVBAcMEUFsdGFtb250ZSBTcHJpbmdzMSAwHgYDVQQKDBdQcm92
# YWwgVGVjaG5vbG9naWVzIEluYzEgMB4GA1UEAwwXUHJvdmFsIFRlY2hub2xvZ2ll
# cyBJbmMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC8rFgT0frNYMOu
# jhP3zY5GLj2hndjE1m5UiIUtUXJ0N/X+U7ZzplXEAOrEifqApdBlTrCicq4G5qwk
# 8UV6q0gU6tDxiL8IUHNf6716MTLZuTr08gdLWY6t75Pi8JYz9FtgyiMNB8mo22MY
# 9DpBrW+uNCEO7hZP/siq+rRgroeyn8ClmKrlEvNXHIprqkaE/jBgmVWai3OrwMfK
# 7G7o0MMBAgIoIzyHBWD4nB4Bk66IbAyY6C3ORwBrpgzfT51+/yv2aEKbuZllTRRx
# pjFohqC02BYNrltAnypTO7lWdTWyfl/aTyY93kubWVJMrw5V7aQkbjtZuJUMO3uY
# DmDc8bw3kRYfT/ygA4RZBGkwWNrwOUR2XgOFjK4374jzpa/JW6TaU/v9espLB7RL
# YoUwKONPyMTEE5cBJOK91IwBeoeib0SSYadvtC2VxhaViB12il3mgOxP14o/ckRL
# 4sL3oiABqpYsPgBK0tq6We+JVyX+9GF2Gkje3Gc4jO+1s/B3cNECAwEAAaOCAXMw
# ggFvMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUVML+EJUAk81q9efA19myS7iP
# DOMwWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzAChjxodHRwOi8vY2VydC5zc2wu
# Y29tL1NTTGNvbS1TdWJDQS1Db2RlU2lnbmluZy1SU0EtNDA5Ni1SMS5jZXIwUQYD
# VR0gBEowSDAIBgZngQwBBAEwPAYMKwYBBAGCqTABAwMBMCwwKgYIKwYBBQUHAgEW
# Hmh0dHBzOi8vd3d3LnNzbC5jb20vcmVwb3NpdG9yeTATBgNVHSUEDDAKBggrBgEF
# BQcDAzBNBgNVHR8ERjBEMEKgQKA+hjxodHRwOi8vY3Jscy5zc2wuY29tL1NTTGNv
# bS1TdWJDQS1Db2RlU2lnbmluZy1SU0EtNDA5Ni1SMS5jcmwwHQYDVR0OBBYEFOAY
# zCQ+hpcdCmsNYDdqF4DvoC5DMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsF
# AAOCAgEASHm1T/O4wAemUn5bAfQSnWz4raO9XPSwWytQqjMadSyCTqnz/uO37+dd
# sYBnla323Abl/7zV73Tg2dYDy4yM9W9MxL9Z3aylngcRI7cz4A/262ny2pRrjY3Y
# NSNeM1q4eGBXsMb2bqKVE1dZ9g9qSk+LpLOpExEpH4mvZjjjrUL0kQhlvytSDWpI
# QiZgIYI7JFW7TUXCdNtjnRLhqIJ08sfygk4tduO10XRC4NpxXeZEeqoU8EpW8Jfr
# IRH5zg/rWVygCltSHLkVaGk0jpWrLZCDmquG9CohhNdAPG2PMhZdAlijafyeg5YH
# zvK56qmWZvGemVbRK/TOXCh8UZNK3DjDT8ouylTe1Y0rG6Ml9yX7rBHaOu3seiiJ
# 5o/mWfse8KR57nQ584kkL3qACm9WV2WmVPRQKWeziv9CsQzilVKMshBlQDqNYIAf
# oIaIduQjQoXjmNN00x6IL3cvlzOlRUaw+Pj/BTttjcs+x6mbHCd0VuJPb+92SbRS
# wDSAnqeWcxTwPY50U3zaaw3SgH/ZWeXfRXC5KJ8Pd7Mq4+0wbpqodzGarlZc8Z+8
# AkaHruRrhYFD05+Cr23/h9gl67G3xaY2mrweqlLY8c+J6BqP4mR4vWq11YajIIZQ
# AG6XcWbVznjn//R5cOeiUz037bI9Wjj91JXf45BE4dqvukgTWcUwggbsMIIE1KAD
# AgECAhAwD2+s3WaYdHypRjaneC25MA0GCSqGSIb3DQEBDAUAMIGIMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKTmV3IEplcnNleTEUMBIGA1UEBxMLSmVyc2V5IENpdHkx
# HjAcBgNVBAoTFVRoZSBVU0VSVFJVU1QgTmV0d29yazEuMCwGA1UEAxMlVVNFUlRy
# dXN0IFJTQSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xOTA1MDIwMDAwMDBa
# Fw0zODAxMTgyMzU5NTlaMH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVy
# IE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28g
# TGltaXRlZDElMCMGA1UEAxMcU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBDQTCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMgbAa/ZLH6ImX0BmD8gkL2c
# gCFUk7nPoD5T77NawHbWGgSlzkeDtevEzEk0y/NFZbn5p2QWJgn71TJSeS7JY8IT
# m7aGPwEFkmZvIavVcRB5h/RGKs3EWsnb111JTXJWD9zJ41OYOioe/M5YSdO/8zm7
# uaQjQqzQFcN/nqJc1zjxFrJw06PE37PFcqwuCnf8DZRSt/wflXMkPQEovA8NT7OR
# AY5unSd1VdEXOzQhe5cBlK9/gM/REQpXhMl/VuC9RpyCvpSdv7QgsGB+uE31DT/b
# 0OqFjIpWcdEtlEzIjDzTFKKcvSb/01Mgx2Bpm1gKVPQF5/0xrPnIhRfHuCkZpCkv
# RuPd25Ffnz82Pg4wZytGtzWvlr7aTGDMqLufDRTUGMQwmHSCIc9iVrUhcxIe/arK
# CFiHd6QV6xlV/9A5VC0m7kUaOm/N14Tw1/AoxU9kgwLU++Le8bwCKPRt2ieKBtKW
# h97oaw7wW33pdmmTIBxKlyx3GSuTlZicl57rjsF4VsZEJd8GEpoGLZ8DXv2DolNn
# yrH6jaFkyYiSWcuoRsDJ8qb/fVfbEnb6ikEk1Bv8cqUUotStQxykSYtBORQDHin6
# G6UirqXDTYLQjdprt9v3GEBXc/Bxo/tKfUU2wfeNgvq5yQ1TgH36tjlYMu9vGFCJ
# 10+dM70atZ2h3pVBeqeDAgMBAAGjggFaMIIBVjAfBgNVHSMEGDAWgBRTeb9aqitK
# z1SA4dibwJ3ysgNmyzAdBgNVHQ4EFgQUGqH4YRkgD8NBd0UojtE1XwYSBFUwDgYD
# VR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwEwYDVR0lBAwwCgYIKwYB
# BQUHAwgwEQYDVR0gBAowCDAGBgRVHSAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6
# Ly9jcmwudXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FDZXJ0aWZpY2F0aW9uQXV0
# aG9yaXR5LmNybDB2BggrBgEFBQcBAQRqMGgwPwYIKwYBBQUHMAKGM2h0dHA6Ly9j
# cnQudXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FBZGRUcnVzdENBLmNydDAlBggr
# BgEFBQcwAYYZaHR0cDovL29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0BAQwF
# AAOCAgEAbVSBpTNdFuG1U4GRdd8DejILLSWEEbKw2yp9KgX1vDsn9FqguUlZkCls
# Ycu1UNviffmfAO9Aw63T4uRW+VhBz/FC5RB9/7B0H4/GXAn5M17qoBwmWFzztBEP
# 1dXD4rzVWHi/SHbhRGdtj7BDEA+N5Pk4Yr8TAcWFo0zFzLJTMJWk1vSWVgi4zVx/
# AZa+clJqO0I3fBZ4OZOTlJux3LJtQW1nzclvkD1/RXLBGyPWwlWEZuSzxWYG9vPW
# S16toytCiiGS/qhvWiVwYoFzY16gu9jc10rTPa+DBjgSHSSHLeT8AtY+dwS8BDa1
# 53fLnC6NIxi5o8JHHfBd1qFzVwVomqfJN2Udvuq82EKDQwWli6YJ/9GhlKZOqj0J
# 9QVst9JkWtgqIsJLnfE5XkzeSD2bNJaaCV+O/fexUpHOP4n2HKG1qXUfcb9bQ11l
# PVCBbqvw0NP8srMftpmWJvQ8eYtcZMzN7iea5aDADHKHwW5NWtMe6vBE5jJvHOsX
# TpTDeGUgOw9Bqh/poUGd/rG4oGUqNODeqPk85sEwu8CgYyz8XBYAqNDEf+oRnR4G
# xqZtMl20OAkrSQeq/eww2vGnL8+3/frQo4TZJ577AWZ3uVYQ4SBuxq6x+ba6yDVd
# M3aO8XwgDCp3rrWiAoa6Ke60WgCxjKvj+QrJVF3UuWp0nr1Irpgwggb1MIIE3aAD
# AgECAhA5TCXhfKBtJ6hl4jvZHSLUMA0GCSqGSIb3DQEBDAUAMH0xCzAJBgNVBAYT
# AkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZv
# cmQxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDElMCMGA1UEAxMcU2VjdGlnbyBS
# U0EgVGltZSBTdGFtcGluZyBDQTAeFw0yMzA1MDMwMDAwMDBaFw0zNDA4MDIyMzU5
# NTlaMGoxCzAJBgNVBAYTAkdCMRMwEQYDVQQIEwpNYW5jaGVzdGVyMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMMI1NlY3RpZ28gUlNBIFRpbWUgU3Rh
# bXBpbmcgU2lnbmVyICM0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# pJMoUkvPJ4d2pCkcmTjA5w7U0RzsaMsBZOSKzXewcWWCvJ/8i7u7lZj7JRGOWogJ
# ZhEUWLK6Ilvm9jLxXS3AeqIO4OBWZO2h5YEgciBkQWzHwwj6831d7yGawn7XLMO6
# EZge/NMgCEKzX79/iFgyqzCz2Ix6lkoZE1ys/Oer6RwWLrCwOJVKz4VQq2cDJaG7
# OOkPb6lampEoEzW5H/M94STIa7GZ6A3vu03lPYxUA5HQ/C3PVTM4egkcB9Ei4GOG
# p7790oNzEhSbmkwJRr00vOFLUHty4Fv9GbsfPGoZe267LUQqvjxMzKyKBJPGV4ag
# czYrgZf6G5t+iIfYUnmJ/m53N9e7UJ/6GCVPE/JefKmxIFopq6NCh3fg9EwCSN1Y
# pVOmo6DtGZZlFSnF7TMwJeaWg4Ga9mBmkFgHgM1Cdaz7tJHQxd0BQGq2qBDu9o16
# t551r9OlSxihDJ9XsF4lR5F0zXUS0Zxv5F4Nm+x1Ju7+0/WSL1KF6NpEUSqizADK
# h2ZDoxsA76K1lp1irScL8htKycOUQjeIIISoh67DuiNye/hU7/hrJ7CF9adDhdgr
# OXTbWncC0aT69c2cPcwfrlHQe2zYHS0RQlNxdMLlNaotUhLZJc/w09CRQxLXMn2Y
# bON3Qcj/HyRU726txj5Ve/Fchzpk8WBLBU/vuS/sCRMCAwEAAaOCAYIwggF+MB8G
# A1UdIwQYMBaAFBqh+GEZIA/DQXdFKI7RNV8GEgRVMB0GA1UdDgQWBBQDDzHIkSqT
# vWPz0V1NpDQP0pUBGDAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH/BAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDBKBgNVHSAEQzBBMDUGDCsGAQQBsjEBAgEDCDAl
# MCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzAIBgZngQwBBAIw
# RAYDVR0fBD0wOzA5oDegNYYzaHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdv
# UlNBVGltZVN0YW1waW5nQ0EuY3JsMHQGCCsGAQUFBwEBBGgwZjA/BggrBgEFBQcw
# AoYzaHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUlNBVGltZVN0YW1waW5n
# Q0EuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkq
# hkiG9w0BAQwFAAOCAgEATJtlWPrgec/vFcMybd4zket3WOLrvctKPHXefpRtwyLH
# BJXfZWlhEwz2DJ71iSBewYfHAyTKx6XwJt/4+DFlDeDrbVFXpoyEUghGHCrC3vLa
# ikXzvvf2LsR+7fjtaL96VkjpYeWaOXe8vrqRZIh1/12FFjQn0inL/+0t2v++kwzs
# baINzMPxbr0hkRojAFKtl9RieCqEeajXPawhj3DDJHk6l/ENo6NbU9irALpY+zWA
# T18ocWwZXsKDcpCu4MbY8pn76rSSZXwHfDVEHa1YGGti+95sxAqpbNMhRnDcL411
# TCPCQdB6ljvDS93NkiZ0dlw3oJoknk5fTtOPD+UTT1lEZUtDZM9I+GdnuU2/zA2x
# OjDQoT1IrXpl5Ozf4AHwsypKOazBpPmpfTXQMkCgsRkqGCGyyH0FcRpLJzaq4Jgc
# g3Xnx35LhEPNQ/uQl3YqEqxAwXBbmQpA+oBtlGF7yG65yGdnJFxQjQEg3gf3AdT4
# LhHNnYPl+MolHEQ9J+WwhkcqCxuEdn17aE+Nt/cTtO2gLe5zD9kQup2ZLHzXdR+P
# EMSU5n4k5ZVKiIwn1oVmHfmuZHaR6Ej+yFUK7SnDH944psAU+zI9+KmDYjbIw74A
# hxyr+kpCHIkD3PVcfHDZXXhO7p9eIOYJanwrCKNI9RX8BE/fzSEceuX1jhrUuUAx
# ggYOMIIGCgIBATCBjDB4MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAO
# BgNVBAcMB0hvdXN0b24xETAPBgNVBAoMCFNTTCBDb3JwMTQwMgYDVQQDDCtTU0wu
# Y29tIENvZGUgU2lnbmluZyBJbnRlcm1lZGlhdGUgQ0EgUlNBIFIxAhB5XCTG7Piy
# ewEA9fv+9trIMA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKA
# AKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIM3ZSaEhab10Uu4RHA4wZ92u
# eJiWkoIDgT59CfwlIFOqMA0GCSqGSIb3DQEBAQUABIIBgB0REXmCkO+YUrtsyQNf
# xe4dx1jPeD3xKqAKpG5Qe8EhAqM9noX0KSBF1j4rX5L/SjxX+gOh6TZ8oAls8E+g
# Vd8Hc2SIWIPcFN+W1e103uW2EyFaZACY4hmoOuelQmWaH2G9iWDHYC3waJW4gOZE
# FdZywkrKvkd6VkjCimZLdIQswcEodplugT3xlDGzh4FLvlWS8WZUwyIcvCT6JjyW
# 5wShoPo5NOATXGzoM+qNGxWXld8uXMqPnRhMy0iovAobxkuFKY0EM1zcnF15/z8h
# 3apLFnC+LyVqA7FYKJMJbQaKM4CnHbyVI7QMa4O1h+bvQdHaYZNXi/sHdK0VFGNL
# 09Y/G6nJzZdY3X86TLMz9TjmcDNOWe/p3jgb8l5/bIIh8FsjKcblyp2N2UkSOXrB
# xfb4NlniLhuJiOW7+n9ROl4xIPwyGf6NBkq+SeLBySm4qcHUBy2yUksW5skDSW1A
# 2aEgKBr/ceYKLxDr1bXWNbc2VPyMEPUgUYfi1WvmOtXwG6GCA0swggNHBgkqhkiG
# 9w0BCQYxggM4MIIDNAIBATCBkTB9MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3Jl
# YXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRgwFgYDVQQKEw9TZWN0
# aWdvIExpbWl0ZWQxJTAjBgNVBAMTHFNlY3RpZ28gUlNBIFRpbWUgU3RhbXBpbmcg
# Q0ECEDlMJeF8oG0nqGXiO9kdItQwDQYJYIZIAWUDBAICBQCgeTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMzA3MDcxNjM2MDBaMD8G
# CSqGSIb3DQEJBDEyBDAt4Yqr+FcmlAf+SiBXaiNywZkGECGGofR+xcR2tE3frGAA
# I3TQGuWiZoH26QAYSDQwDQYJKoZIhvcNAQEBBQAEggIAf/B7BivP8eA4Tkompjjf
# FUb87t7K1F9otRzS3ETor2z+wJhicHXOtjcGUi0+xinBPbQuB1tOZYOX30tjj07F
# 2km0hQ/jkYaN28MPoiZDUnWn1Ue+GZxBwkGPBeJ1kWFaxtB1faGL70lKnDPHe3pS
# c83tOXPlKRXuXk4Whbf217nVPBqVozTBN/g8Nv+0yqsNIclagdCbwY9ZzknrUgG6
# dEv5NyCW2mLTXbbPZkB7VPA5PczQk4AO2qNTaKa8w+W2fzpQhO0oqlFner6RR4V1
# OR202Bz9CdsaJycxnjGMR2w8iwClPBfovf5DFsSzzK0BFuF/QZyuEAT53r4m7qt1
# M2kG1ibORTj662uri7/Y7sAd15lWTa5mN9XUqCH0OGNW16NxV6gQGBn3Ly7if2JS
# 53jqZ8dcgkskg0w2lR2KEvoVHXOCgCuBeqQDN87KrIwRdfzFARSew2OOLY3kuNwR
# ddI46S4peJXAqxVcD5Of6JDjWv9N0CqbJWwiSKANp6rV+dUhfZSvTIvJ4GCFn6Ib
# O3NytPsdW+v4JfmjJijHBRNzy8cYqW+FRtFExwnGpU1Plrx/hQJ65Ii1l+bmvD2B
# LbhN5STLw94r4iRyGt6NMa91RwYyEyy4U4HFVHBqTjuubbqTzQZwPMhyjRiDNbTs
# n/YUwysFWGmz/WIdiTqbJJQ=
# SIG # End signature block
