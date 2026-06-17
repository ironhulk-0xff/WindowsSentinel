@echo off
setlocal EnableExtensions EnableDelayedExpansion

:: ============================================================
::  Deploy-WDAC.bat - WindowsSentinel WDAC Deployment Tool
::
::  Usage:
::    Deploy-WDAC.bat /setup     - Full setup wizard (Audit Mode)
::    Deploy-WDAC.bat /enforce   - Switch deployed policy to Enforce Mode
::    Deploy-WDAC.bat /report    - Generate audit report only
::    Deploy-WDAC.bat /remove    - Remove the deployed policy
::    Deploy-WDAC.bat /harden    - Enforce policy + apply insider threat hardening
::    Deploy-WDAC.bat /help      - Show full help and step descriptions
::
::  Run as Administrator.
:: ============================================================

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Please run this script as Administrator.
    pause
    exit /b 1
)

:: Set console width for full-screen display
mode con: cols=120 lines=50

:: ============================================================
:: GLOBAL VARIABLES
:: ============================================================
set "WDAC_FOLDER=C:\WDAC"
set "POLICY_NAME=WindowsSentinelPolicy"
set "BASE_TEMPLATE=C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml"
set "XML_PATH=C:\WDAC\WSSentinel.xml"

set SETUP_MODE=0
set ENFORCE_MODE=0
set ENFORCE_DLL=0
set ENFORCE_SYS=0
set ENFORCE_PS1=0
set ENFORCE_SCRIPTS=0
set ENFORCE_HTA=0
set ENFORCE_WSF=0
set ENFORCE_PKG=0
set ALLOW_COPYPASTE=0
set "EXT_LIST="
set REPORT_ONLY=0
set REMOVE_MODE=0
set HARDEN_MODE=0
set FAST_DEPLOY=0
set HELP_MODE=0

if /i "%1"=="/setup"   set SETUP_MODE=1
if /i "%1"=="/enforce" set ENFORCE_MODE=1
if /i "%1"=="/report"  set REPORT_ONLY=1
if /i "%1"=="/remove"  set REMOVE_MODE=1
if /i "%1"=="/help"    set HELP_MODE=1
if /i "%1"=="/harden"  set HARDEN_MODE=1

:: /help - show full help then exit
if "!HELP_MODE!"=="1" goto SHOW_HELP

:: No flag supplied - print short usage and exit
if "!SETUP_MODE!!ENFORCE_MODE!!REPORT_ONLY!!REMOVE_MODE!!HARDEN_MODE!"=="00000" goto SHOW_USAGE

:: Create WDAC folder immediately so /report and /remove modes work
if not exist "%WDAC_FOLDER%" mkdir "%WDAC_FOLDER%"

cls
echo ============================================================
echo    WDAC Policy Deployment - WindowsSentinel v1
echo ============================================================
echo.
echo    Author      : Ironhulk
echo    Telegram    : @irohulk_0xff
echo    X (Twitter) : @irohulk_0xff
echo.
echo ============================================================
echo.
echo   WindowsSentinel deploys a Windows Defender Application Control
echo   policy that restricts which programs are allowed to run on
echo   this machine. Only Microsoft-signed binaries and apps you
echo   explicitly whitelist will be permitted to execute.
echo.
echo   The policy runs in two stages:
echo     Audit Mode   - Monitors and logs what would be blocked.
echo                    Nothing is blocked yet. Safe to explore.
echo     Enforce Mode - Actively blocks unauthorized executables.
echo                    Only whitelisted apps will run.
echo.
echo   All policy files are stored in C:\WDAC\
echo   Recovery script : C:\WDAC\Remove-WDAC.ps1
echo   Full help       : Deploy-WDAC.bat /help
echo.
echo ============================================================
echo IMPORTANT SECURITY NOTICE
echo ============================================================
echo.
echo Some Antivirus (AV) and Endpoint Detection and Response (EDR)
echo products may block, quarantine, or interfere with WDAC policy
echo generation and deployment.
echo.
echo If you encounter errors during execution:
echo   - Temporarily disable tamper protection if permitted.
echo   - Add this script and C:\WDAC\ to your AV/EDR exclusions.
echo   - Restore any files quarantined by your security software.
echo.
echo Supported AV/EDR products can be detected automatically later
echo in the deployment process.
echo.
echo ============================================================
echo.
if "!REMOVE_MODE!"=="1" goto DO_REMOVE
if "!HARDEN_MODE!"=="1" goto DO_HARDEN
if "!REPORT_ONLY!"=="1" goto GENERATE_REPORT
if "!ENFORCE_MODE!"=="1" goto DO_ENFORCE_ENTRY

:: ============================================================
:: STEP 0 - WDAC PRE-FLIGHT CHECK
:: ============================================================
echo [STEP 0] Checking existing WDAC policies on this machine...
echo.
echo Press enter to start or ctrl+c to exit...

:: Call citool directly from batch - avoids stdin/stdout issues when
:: calling from inside PowerShell. Output is written to a temp file.
set "CITOOL_OUT=%WDAC_FOLDER%\citool_out.txt"
set "CITOOL_AVAILABLE=0"
where citool.exe >nul 2>&1
if not errorlevel 1 (
    set CITOOL_AVAILABLE=1
    powershell -Command "citool.exe --list-policies | Out-File -FilePath 'C:\WDAC\citool_out.txt' -Encoding UTF8 -Force"
)

set "PF=%WDAC_FOLDER%\preflight_check.ps1"
if exist "%PF%" del "%PF%"

>> "%PF%" echo $citoolAvailable = [int]%CITOOL_AVAILABLE%
>> "%PF%" echo $outFile         = "C:\WDAC\citool_out.txt"
>> "%PF%" echo if ($citoolAvailable -eq 0 -or -not (Test-Path $outFile)) {
>> "%PF%" echo     Write-Host "  [SKIP] citool.exe not found (requires Windows 11)."
>> "%PF%" echo     Write-Host "         Skipping pre-flight check - proceeding manually."
>> "%PF%" echo     exit 0
>> "%PF%" echo }
>> "%PF%" echo $raw = Get-Content $outFile -ErrorAction SilentlyContinue
>> "%PF%" echo Remove-Item $outFile -Force -ErrorAction SilentlyContinue
>> "%PF%" echo $policies = [System.Collections.Generic.List[hashtable]]::new()
>> "%PF%" echo $current  = $null
>> "%PF%" echo foreach ($line in $raw) {
>> "%PF%" echo     $l = $line.Trim()
>> "%PF%" echo     if ($l -eq "Policy:") {
>> "%PF%" echo         if ($current) { $policies.Add($current) }
>> "%PF%" echo         $current = @{ ID=""; BasePolicyID=""; Name=""; Platform=$false; Enforced=$false; Authorized=$false; OnDisk=$false }
>> "%PF%" echo         continue
>> "%PF%" echo     }
>> "%PF%" echo     if (-not $current) { continue }
>> "%PF%" echo     if ($l -match "^Policy ID:\s+(.+)")              { $current.ID           = $Matches[1].Trim() }
>> "%PF%" echo     if ($l -match "^Base Policy ID:\s+(.+)")         { $current.BasePolicyID = $Matches[1].Trim() }
>> "%PF%" echo     if ($l -match "^Friendly Name:\s+(.+)")          { $current.Name         = $Matches[1].Trim() }
>> "%PF%" echo     if ($l -match "^Platform Policy:\s+(.+)")        { $current.Platform     = ($Matches[1].Trim() -eq "true") }
>> "%PF%" echo     if ($l -match "^Is Currently Enforced:\s+(.+)")  { $current.Enforced     = ($Matches[1].Trim() -eq "true") }
>> "%PF%" echo     if ($l -match "^Is Authorized:\s+(.+)")          { $current.Authorized   = ($Matches[1].Trim() -eq "true") }
>> "%PF%" echo     if ($l -match "^Has File on Disk:\s+(.+)")       { $current.OnDisk       = ($Matches[1].Trim() -eq "true") }
>> "%PF%" echo }
>> "%PF%" echo if ($current) { $policies.Add($current) }
>> "%PF%" echo $enforced    = @($policies ^| Where-Object { $_.Enforced })
>> "%PF%" echo $platform    = @($policies ^| Where-Object { $_.Enforced -and $_.Platform })
>> "%PF%" echo $userDeploy  = @($policies ^| Where-Object { $_.Enforced -and -not $_.Platform })
>> "%PF%" echo $sacPolicy   = @($policies ^| Where-Object { $_.Name -match "VerifiedAndReputable[^E]" -and $_.Enforced })
>> "%PF%" echo $sacOn       = ($sacPolicy.Count -gt 0)
>> "%PF%" echo $conflicts   = $false
>> "%PF%" echo Write-Host "  Policies detected     : $($policies.Count)"
>> "%PF%" echo Write-Host "  Currently enforced    : $($enforced.Count)"
>> "%PF%" echo Write-Host "  Microsoft platform    : $($platform.Count)"
>> "%PF%" echo Write-Host "  User/enterprise       : $($userDeploy.Count)"
>> "%PF%" echo Write-Host ""
>> "%PF%" echo if ($sacOn) {
>> "%PF%" echo     Write-Host "  [WARN] Smart App Control is ON"
>> "%PF%" echo     Write-Host "         SAC uses its own WDAC base policy which may conflict"
>> "%PF%" echo     Write-Host "         with WindowsSentinel. Recommended: disable SAC first."
>> "%PF%" echo     Write-Host "         Settings > Privacy and Security > Windows Security > App and Browser Control"
>> "%PF%" echo     Write-Host ""
>> "%PF%" echo     $conflicts = $true
>> "%PF%" echo } else {
>> "%PF%" echo     Write-Host "  [OK] Smart App Control   : OFF"
>> "%PF%" echo }
>> "%PF%" echo if ($platform.Count -gt 0) {
>> "%PF%" echo     Write-Host "  [OK] Microsoft platform policies (managed by Windows - safe):"
>> "%PF%" echo     foreach ($p in $platform) {
>> "%PF%" echo         $status = if ($p.Enforced) { "ENFORCED" } else { "inactive" }
>> "%PF%" echo         $n = $p.Name
>> "%PF%" echo         if ($n.Length -gt 55) { $n = $n.Substring(0,52) + "..." }
>> "%PF%" echo         Write-Host ("         {0,-56} [{1}]" -f $n, $status)
>> "%PF%" echo     }
>> "%PF%" echo     Write-Host ""
>> "%PF%" echo }
>> "%PF%" echo if ($userDeploy.Count -gt 0) {
>> "%PF%" echo     Write-Host "  [WARN] Non-platform enforced policies found - possible conflicts:"
>> "%PF%" echo     foreach ($p in $userDeploy) {
>> "%PF%" echo         Write-Host "         Name : $($p.Name)"
>> "%PF%" echo         Write-Host "         ID   : $($p.ID)"
>> "%PF%" echo         Write-Host "         This policy may conflict with WindowsSentinel rules."
>> "%PF%" echo         Write-Host ""
>> "%PF%" echo     }
>> "%PF%" echo     $conflicts = $true
>> "%PF%" echo } else {
>> "%PF%" echo     Write-Host "  [OK] No conflicting enterprise or third-party WDAC policies"
>> "%PF%" echo }
>> "%PF%" echo Write-Host ""
>> "%PF%" echo if ($conflicts) {
>> "%PF%" echo     Write-Host "  Result: WARNINGS DETECTED - review before continuing."
>> "%PF%" echo     exit 2
>> "%PF%" echo } else {
>> "%PF%" echo     Write-Host "  Result: PRE-FLIGHT PASSED - safe to proceed."
>> "%PF%" echo     exit 0
>> "%PF%" echo }

powershell -ExecutionPolicy Bypass -File "%PF%"
set PREFLIGHT_RESULT=%errorLevel%
del "%PF%" >nul 2>&1
echo.

if "!PREFLIGHT_RESULT!"=="2" (
    echo   --------------------------------------------------------
    echo   One or more warnings were detected above.
    echo   Deploying WindowsSentinel on top of conflicting policies
    echo   may block legitimate software or behave unexpectedly.
    echo.
    set "PREFLIGHT_CHOICE="
    set /p PREFLIGHT_CHOICE="  Continue anyway? [Y/N]: "
    if /i "!PREFLIGHT_CHOICE!" neq "Y" (
        echo   Setup cancelled.
        goto END_NOCLEAN
    )
    echo.
)

:: ============================================================
:: STEP 1 - PREREQUISITES
:: ============================================================
echo [STEP 1] Checking prerequisites...
echo.

if not exist "%BASE_TEMPLATE%" (
    echo   ERROR: Base template not found:
    echo     %BASE_TEMPLATE%
    echo   This script requires Windows 10/11 Enterprise or Server 2016+.
    pause & exit /b 1
)

powershell -Command "Get-Command ConvertFrom-CIPolicy -ErrorAction SilentlyContinue" >nul 2>&1
if %errorLevel% neq 0 (
    echo   ERROR: ConfigCI PowerShell module not found.
    echo   This script requires Windows 10/11 Enterprise or Server 2016+.
    pause & exit /b 1
)

echo   [+] Prerequisites passed.
echo.

:: ============================================================
:: STEP 2 - FILE EXTENSION SELECTION
:: ============================================================
echo [STEP 2] File extension enforcement...
echo.
echo   Select which file types to enforce:
echo.
echo   +-----+---------------+--------------------------------------------------+
echo   ^| No. ^| Extension     ^| Description                                      ^|
echo   +-----+---------------+--------------------------------------------------+
echo   ^|  1  ^| .exe          ^| Executables (apps, tools, programs)              ^|
echo   ^|  2  ^| .dll          ^| Libraries (loaded into running processes)        ^|
echo   ^|  3  ^| .sys          ^| Kernel drivers                                   ^|
echo   ^|  4  ^| .ps1          ^| PowerShell scripts                               ^|
echo   ^|  5  ^| .bat / .cmd   ^| Batch scripts                                    ^|
echo   ^|  6  ^| .vbs / .js    ^| VBScript / JScript                               ^|
echo   ^|  7  ^| .hta          ^| HTML Applications (common attack vector)         ^|
echo   ^|  8  ^| .wsf / .wsh   ^| Windows Script Host files                        ^|
echo   ^|  9  ^| .appx / .msix ^| Package installers (Store / sideloaded apps)     ^|
echo   ^|  A  ^| ALL           ^| All of the above (recommended)                   ^|
echo   +-----+---------------+--------------------------------------------------+
echo.
echo   You can combine options separated by commas.
echo   Examples:  1       = EXE only
echo              1,2,3   = EXE, DLL and SYS
echo              1,2,7,8 = EXE, DLL and both script attack vectors
echo              A       = All extensions
echo.
echo   Note: Options 4,5,6,7,8 all use script enforcement (Policy Option 16).
echo         Selecting any one of them enables it for all script types.
echo.

:ASK_EXT
set "EXT_CHOICE="
set /p EXT_CHOICE="  Enter your selection: "

if /i "!EXT_CHOICE!"=="A" (
    set ENFORCE_DLL=1
    set ENFORCE_SYS=1
    set ENFORCE_PS1=1
    set ENFORCE_SCRIPTS=1
    set ENFORCE_HTA=1
    set ENFORCE_WSF=1
    set ENFORCE_PKG=1
    set "EXT_LIST=.exe .dll .sys .ps1 .bat .cmd .vbs .js .hta .wsf .wsh .appx .msix"
    goto EXT_DONE
)

:: Validate - only digits 1-9 and commas allowed
powershell -Command "$p='!EXT_CHOICE!' -split ',' | ForEach-Object {$_.Trim()}; if(($p | Where-Object {$_ -notmatch '^[1-9]$'}).Count -gt 0){exit 1}else{exit 0}" >nul 2>&1
if %errorLevel% neq 0 (
    echo   INVALID: Use numbers 1-9 separated by commas, or A for all.
    goto ASK_EXT
)

:: Pad with commas to prevent partial number matches
set "PADDED=,!EXT_CHOICE!,"

echo !PADDED! | findstr /c:",1," >nul 2>&1
if not errorlevel 1 set "EXT_LIST=!EXT_LIST! .exe"

echo !PADDED! | findstr /c:",2," >nul 2>&1
if not errorlevel 1 (
    set ENFORCE_DLL=1
    set "EXT_LIST=!EXT_LIST! .dll"
)

echo !PADDED! | findstr /c:",3," >nul 2>&1
if not errorlevel 1 (
    set ENFORCE_SYS=1
    set "EXT_LIST=!EXT_LIST! .sys"
)

echo !PADDED! | findstr /c:",4," >nul 2>&1
if not errorlevel 1 (
    set ENFORCE_PS1=1
    set ENFORCE_SCRIPTS=1
    set "EXT_LIST=!EXT_LIST! .ps1"
)

echo !PADDED! | findstr /c:",5," >nul 2>&1
if not errorlevel 1 (
    set ENFORCE_SCRIPTS=1
    set "EXT_LIST=!EXT_LIST! .bat .cmd"
)

echo !PADDED! | findstr /c:",6," >nul 2>&1
if not errorlevel 1 (
    set ENFORCE_SCRIPTS=1
    set "EXT_LIST=!EXT_LIST! .vbs .js"
)

echo !PADDED! | findstr /c:",7," >nul 2>&1
if not errorlevel 1 (
    set ENFORCE_HTA=1
    set ENFORCE_SCRIPTS=1
    set "EXT_LIST=!EXT_LIST! .hta"
)

echo !PADDED! | findstr /c:",8," >nul 2>&1
if not errorlevel 1 (
    set ENFORCE_WSF=1
    set ENFORCE_SCRIPTS=1
    set "EXT_LIST=!EXT_LIST! .wsf .wsh"
)

echo !PADDED! | findstr /c:",9," >nul 2>&1
if not errorlevel 1 (
    set ENFORCE_PKG=1
    set "EXT_LIST=!EXT_LIST! .appx .msix"
)

:EXT_DONE
echo.
echo   Extensions selected: !EXT_LIST!
echo.

if "!ENFORCE_DLL!"=="0" (
    echo   NOTE: DLL enforcement is OFF.
    echo         Malicious DLLs injected into trusted processes will not be blocked.
    echo.
)
if "!ENFORCE_SYS!"=="0" (
    echo   NOTE: Kernel driver enforcement is OFF.
    echo         Unsigned kernel drivers will be allowed to load.
    echo.
)
if "!ENFORCE_SCRIPTS!"=="1" (
    echo   WARNING: Script enforcement is ON.
    echo   This covers: .ps1 .bat .cmd .vbs .js .hta .wsf .wsh
    echo   This script ^(Deploy-WDAC.bat^) WILL BE BLOCKED after Enforce Mode activates.
    echo   Keep the rollback script ^(Remove-WDAC.ps1^) accessible in case you need recovery.
    echo.
)
if "!ENFORCE_PKG!"=="1" (
    echo   NOTE: Package enforcement is ON.
    echo         Only Microsoft-signed .appx/.msix packages will be allowed to install.
    echo.
)

:: ============================================================
:: STEP 3 - VMWARE COPY/PASTE
:: ============================================================
echo [STEP 3] VMware Tools configuration...
echo.
echo   If this machine is a VMware VM, VMware Tools provides:
echo     - Copy/paste between host and VM
echo     - Drag and drop, display scaling
echo.

:ASK_COPYPASTE
set "CP_CHOICE="
set /p CP_CHOICE="  Whitelist VMware Tools? [Y/N]: "
if /i "!CP_CHOICE!"=="Y" (
    set ALLOW_COPYPASTE=1
    echo   [+] VMware Tools will be whitelisted.
    goto CP_DONE
)
if /i "!CP_CHOICE!"=="N" (
    echo       VMware Tools will be blocked.
    goto CP_DONE
)
echo   Please enter Y or N.
goto ASK_COPYPASTE

:CP_DONE
echo.

:: ============================================================
:: STEP 4 - AV/EDR AUTO-DETECT
:: ============================================================
echo [STEP 4] Scanning for AV/EDR products...
echo.
echo ============================================================
echo  Supported AV / EDR Detection Targets
echo ============================================================
echo  This script automatically detects installed security products
echo  and can generate WDAC allow rules for the following vendors:
echo   - Cybereason
echo   - CrowdStrike Falcon
echo   - SentinelOne
echo   - VMware Carbon Black (Bit9)
echo   - Trend Micro
echo   - McAfee
echo   - Symantec / Broadcom Symantec
echo   - Sophos
echo   - ESET
echo   - Kaspersky
echo   - Bitdefender
echo   - Cylance
echo   - Palo Alto Networks (Cortex XDR)
echo   - Elastic Security
echo   - Malwarebytes
echo  Detection is performed by checking common installation paths
echo  under Program Files. Additional products can be added by
echo  extending the $products array in detect_av.ps1.
echo ============================================================

set "DS=%WDAC_FOLDER%\detect_av.ps1"
if exist "%DS%" del "%DS%"

>> "%DS%" echo $products = @(
>> "%DS%" echo     @{Name="Cybereason";   Path="C:\Program Files\Cybereason*"},
>> "%DS%" echo     @{Name="CrowdStrike";  Path="C:\Program Files\CrowdStrike*"},
>> "%DS%" echo     @{Name="SentinelOne";  Path="C:\Program Files\SentinelOne*"},
>> "%DS%" echo     @{Name="Carbon Black"; Path="C:\Program Files\Bit9*"},
>> "%DS%" echo     @{Name="Carbon Black"; Path="C:\Program Files\VMware\VMware Carbon Black*"},
>> "%DS%" echo     @{Name="Trend Micro";  Path="C:\Program Files\Trend Micro*"},
>> "%DS%" echo     @{Name="McAfee";       Path="C:\Program Files\McAfee*"},
>> "%DS%" echo     @{Name="Symantec";     Path="C:\Program Files\Symantec*"},
>> "%DS%" echo     @{Name="Symantec";     Path="C:\Program Files\Broadcom\Symantec*"},
>> "%DS%" echo     @{Name="Sophos";       Path="C:\Program Files\Sophos*"},
>> "%DS%" echo     @{Name="ESET";         Path="C:\Program Files\ESET*"},
>> "%DS%" echo     @{Name="Kaspersky";    Path="C:\Program Files\Kaspersky*"},
>> "%DS%" echo     @{Name="Bitdefender";  Path="C:\Program Files\Bitdefender*"},
>> "%DS%" echo     @{Name="Cylance";      Path="C:\Program Files\Cylance*"},
>> "%DS%" echo     @{Name="Palo Alto";    Path="C:\Program Files\Palo Alto Networks*"},
>> "%DS%" echo     @{Name="Elastic";      Path="C:\Program Files\Elastic*"},
>> "%DS%" echo     @{Name="Malwarebytes"; Path="C:\Program Files\Malwarebytes*"}
>> "%DS%" echo )
>> "%DS%" echo $detected = @()
>> "%DS%" echo foreach ($p in $products) {
>> "%DS%" echo     $found = Get-Item -Path $p.Path -ErrorAction SilentlyContinue
>> "%DS%" echo     if ($found) {
>> "%DS%" echo         $fp = $found.FullName + "\*"
>> "%DS%" echo         if (-not ($detected ^| Where-Object { $_.Path -eq $fp })) {
>> "%DS%" echo             $detected += @{Name=$p.Name; Path=$fp}
>> "%DS%" echo             Write-Host "  [+] Found: $($p.Name) at $($found.FullName)"
>> "%DS%" echo         }
>> "%DS%" echo     }
>> "%DS%" echo }
>> "%DS%" echo try {
>> "%DS%" echo     $sc = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -EA SilentlyContinue
>> "%DS%" echo     foreach ($s in $sc) {
>> "%DS%" echo         if ($s.pathToSignedProductExe -and (Test-Path $s.pathToSignedProductExe)) {
>> "%DS%" echo             $dir = Split-Path $s.pathToSignedProductExe -Parent
>> "%DS%" echo             $fp  = $dir + "\*"
>> "%DS%" echo             if (-not ($detected ^| Where-Object { $_.Path -eq $fp })) {
>> "%DS%" echo                 $detected += @{Name=$s.displayName; Path=$fp}
>> "%DS%" echo                 Write-Host "  [+] Found via SecurityCenter: $($s.displayName) at $dir"
>> "%DS%" echo             }
>> "%DS%" echo         }
>> "%DS%" echo     }
>> "%DS%" echo } catch {}
>> "%DS%" echo $kw = @("crowdstrike","falcon","sentinel","cylance","carbonblack","cybereason","elastic","edr","sophos","eset","kaspersky","bitdefender","mcafee","symantec","malwarebytes")
>> "%DS%" echo $svcs = Get-WmiObject Win32_Service -EA SilentlyContinue ^| Where-Object { $_.PathName -and $_.State -eq "Running" }
>> "%DS%" echo foreach ($svc in $svcs) {
>> "%DS%" echo     $nl = $svc.Name.ToLower()
>> "%DS%" echo     $pl = $svc.PathName.ToLower()
>> "%DS%" echo     $m  = $kw ^| Where-Object { $nl -match $_ -or $pl -match $_ }
>> "%DS%" echo     if ($m) {
>> "%DS%" echo         $exe = $svc.PathName -replace '"','' -replace ' -.*',''
>> "%DS%" echo         if (Test-Path $exe) {
>> "%DS%" echo             $dir = Split-Path $exe -Parent
>> "%DS%" echo             $fp  = $dir + "\*"
>> "%DS%" echo             if (-not ($detected ^| Where-Object { $_.Path -eq $fp })) {
>> "%DS%" echo                 $detected += @{Name=$svc.DisplayName; Path=$fp}
>> "%DS%" echo                 Write-Host "  [+] Found via service: $($svc.DisplayName) at $dir"
>> "%DS%" echo             }
>> "%DS%" echo         }
>> "%DS%" echo     }
>> "%DS%" echo }
>> "%DS%" echo if ($detected.Count -eq 0) { Write-Host "    No third-party AV/EDR products detected." }
>> "%DS%" echo $detected ^| ForEach-Object { $_.Path } ^| Out-File "C:\WDAC\detected_av_paths.txt" -Encoding ASCII

powershell -ExecutionPolicy Bypass -File "%DS%"
echo.

:: ============================================================
:: STEP 5 - INSTALLED APP SCANNER (NEW)
:: ============================================================
echo [STEP 5] Scanning installed applications...
echo.
echo   Scanning Program Files for installed software.
echo   This may take a moment...
echo.

set "AS=%WDAC_FOLDER%\scan_apps.ps1"
if exist "%AS%" del "%AS%"

>> "%AS%" echo $scanPaths = @("C:\Program Files", "C:\Program Files (x86)")
>> "%AS%" echo $apps = [System.Collections.Generic.List[PSObject]]::new()
>> "%AS%" echo $idx  = 0
>> "%AS%" echo foreach ($sp in $scanPaths) {
>> "%AS%" echo     if (-not (Test-Path $sp)) { continue }
>> "%AS%" echo     $folders = Get-ChildItem $sp -Directory -ErrorAction SilentlyContinue
>> "%AS%" echo     foreach ($folder in $folders) {
>> "%AS%" echo         $exe = Get-ChildItem $folder.FullName -Filter "*.exe" -Recurse -Depth 2 -ErrorAction SilentlyContinue ^| Select-Object -First 1
>> "%AS%" echo         if (-not $exe) { continue }
>> "%AS%" echo         # Skip if a folder with the same name was already found in the other scan path
>> "%AS%" echo         if ($apps ^| Where-Object { $_.Name -eq $folder.Name }) { continue }
>> "%AS%" echo         $idx++
>> "%AS%" echo         $isSigned = $false
>> "%AS%" echo         $pubName  = "UNSIGNED"
>> "%AS%" echo         # Stage 1: embedded cert check - fast, no network, no CRL calls
>> "%AS%" echo         # Catches most commercial apps (Firefox, Chrome, WinRAR, etc.)
>> "%AS%" echo         try {
>> "%AS%" echo             $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromSignedFile($exe.FullName)
>> "%AS%" echo             if ($cert -and $cert.Subject) {
>> "%AS%" echo                 $isSigned = $true
>> "%AS%" echo                 $subj     = $cert.Subject
>> "%AS%" echo                 $pubName  = if ($subj -match 'CN=([^,]+)') { $Matches[1] } else { $subj }
>> "%AS%" echo             }
>> "%AS%" echo         } catch {}
>> "%AS%" echo         # Stage 2: catalog cert check - only runs if Stage 1 found nothing
>> "%AS%" echo         # Catches Windows-bundled apps signed via catalog (IE, WMP, Windows Mail, etc.)
>> "%AS%" echo         # Slightly slower but only fires for a small number of apps
>> "%AS%" echo         if (-not $isSigned) {
>> "%AS%" echo             try {
>> "%AS%" echo                 $sig = Get-AuthenticodeSignature $exe.FullName -ErrorAction SilentlyContinue
>> "%AS%" echo                 if ($sig -and $sig.Status -eq "Valid" -and $sig.SignerCertificate) {
>> "%AS%" echo                     $isSigned = $true
>> "%AS%" echo                     $subj     = $sig.SignerCertificate.Subject
>> "%AS%" echo                     $pubName  = if ($subj -match 'CN=([^,]+)') { $Matches[1] } else { $subj }
>> "%AS%" echo                 }
>> "%AS%" echo             } catch {}
>> "%AS%" echo         }
>> "%AS%" echo         $apps.Add([PSCustomObject]@{
>> "%AS%" echo             Index    = $idx
>> "%AS%" echo             Name     = $folder.Name
>> "%AS%" echo             Path     = $folder.FullName
>> "%AS%" echo             MainExe  = $exe.FullName
>> "%AS%" echo             Publisher= $pubName
>> "%AS%" echo             RuleType = if ($isSigned) { "Publisher" } else { "Path" }
>> "%AS%" echo             Signed   = $isSigned
>> "%AS%" echo         })
>> "%AS%" echo     }
>> "%AS%" echo }
>> "%AS%" echo $apps ^| ConvertTo-Json -Depth 3 ^| Out-File "C:\WDAC\detected_apps.json" -Encoding UTF8
>> "%AS%" echo Write-Host ("  {0,4}  {1,-38}  {2,-12}  {3}" -f "No.", "Application", "Rule Type", "Publisher")
>> "%AS%" echo Write-Host ("  {0,4}  {1,-38}  {2,-12}  {3}" -f "----", "----------------------------------", "----------", "--------------------------")
>> "%AS%" echo foreach ($app in $apps) {
>> "%AS%" echo     $n   = $app.Name
>> "%AS%" echo     if ($n.Length -gt 38) { $n = $n.Substring(0,35) + "..." }
>> "%AS%" echo     $pub = $app.Publisher
>> "%AS%" echo     if ($pub.Length -gt 30) { $pub = $pub.Substring(0,28) + ".." }
>> "%AS%" echo     Write-Host ("  {0,4}  {1,-38}  {2,-12}  {3}" -f $app.Index, $n, $app.RuleType, $pub)
>> "%AS%" echo }
>> "%AS%" echo Write-Host ""
>> "%AS%" echo Write-Host "  Total: $($apps.Count) applications found."

powershell -ExecutionPolicy Bypass -File "%AS%"

echo.
echo   Rule type explanation:
echo     Publisher = App is signed (embedded or catalog cert found).
echo                 Rule is tied to the signing certificate.
echo                 Only files from that publisher are trusted - more secure.
echo     Path      = App has no detectable signature.
echo                 Rule is tied to the install folder location.
echo                 Anything placed in that folder will run - weaker.
echo.
echo   All of the above apps will be WHITELISTED (allowed to run).
echo   Enter numbers to EXCLUDE from the whitelist (separated by commas).
echo   Excluded apps will be BLOCKED in Enforce Mode.
echo   Press ENTER with nothing typed to allow ALL apps listed above.
echo.

set "EXCLUDE_LIST="
set /p EXCLUDE_LIST="  Exclude numbers (or press ENTER for all): "
echo.

if "!EXCLUDE_LIST!"=="" (
    echo   [+] All detected applications will be whitelisted.
) else (
    echo   [+] Excluding apps: !EXCLUDE_LIST!
)

:: Write exclusions file - used by build and report scripts
echo !EXCLUDE_LIST!> "%WDAC_FOLDER%\app_exclusions.txt"
echo.

:: ============================================================
:: STEP 6 - LOLBAS DENY LIST
:: ============================================================
echo [STEP 6] LOLBAS - Living Off The Land Binaries deny list...
echo.
echo   The following Microsoft-signed binaries are commonly abused
echo   by attackers to execute code without dropping new files.
echo   Select which ones to DENY on this machine.
echo.
echo   +------+----------------------------------+-------------------------------+---------+
echo   ^| No.  ^| Binary                           ^| Abuse Technique               ^| Impact  ^|
echo   +------+----------------------------------+-------------------------------+---------+
echo   ^|   1  ^| msbuild.exe                      ^| Inline C# via .csproj         ^| Low     ^|
echo   ^|   2  ^| regsvr32.exe                     ^| COM scriptlet execution       ^| Medium  ^|
echo   ^|   3  ^| rundll32.exe                     ^| DLL/script via exports        ^| HIGH    ^|
echo   ^|   4  ^| certutil.exe                     ^| File download / base64 decode ^| Low     ^|
echo   ^|   5  ^| installutil.exe                  ^| .NET WDAC bypass              ^| Low     ^|
echo   ^|   6  ^| regasm.exe                       ^| .NET COM execution            ^| Low     ^|
echo   ^|   7  ^| regsvcs.exe                      ^| .NET COM+ execution           ^| Low     ^|
echo   ^|   8  ^| cmstp.exe                        ^| UAC bypass / INF execution    ^| Low     ^|
echo   ^|   9  ^| odbcconf.exe                     ^| DLL via ODBC response file    ^| Low     ^|
echo   ^|  10  ^| cscript.exe                      ^| JScript/VBScript execution    ^| HIGH    ^|
echo   ^|  11  ^| wscript.exe                      ^| JScript/VBScript execution    ^| HIGH    ^|
echo   ^|  12  ^| mshta.exe                        ^| HTA/JScript/VBScript          ^| Medium  ^|
echo   ^|  13  ^| powershell.exe                   ^| PowerShell execution          ^| CRIT    ^|
echo   ^|  14  ^| pwsh.exe                         ^| PowerShell 7 execution        ^| HIGH    ^|
echo   ^|  15  ^| presentationhost.exe             ^| XAML execution                ^| Low     ^|
echo   ^|  16  ^| ieexec.exe                       ^| .NET remote execution         ^| Low     ^|
echo   ^|  17  ^| microsoft.workflow.compiler.exe  ^| Workflow compile-and-execute  ^| Low     ^|
echo   ^|  18  ^| desktopimgdownldr.exe            ^| Payload retrieval via reg key ^| Low     ^|
echo   ^|  19  ^| syncappvpublishingserver.exe     ^| Script execution via App-V    ^| Low     ^|
echo   ^|  20  ^| bash.exe                         ^| WSL abuse                     ^| Medium  ^|
echo   ^|  21  ^| wsl.exe                          ^| WSL abuse                     ^| Medium  ^|
echo   ^|  22  ^| ftp.exe                          ^| File transfer / exfil         ^| Low     ^|
echo   ^|  23  ^| bitsadmin.exe                    ^| Payload download (legacy)     ^| Low     ^|
echo   ^|  24  ^| forfiles.exe                     ^| Command execution via files   ^| Low     ^|
echo   ^|  25  ^| pcalua.exe                       ^| App Compat Layer execution    ^| Low     ^|
echo   ^|  26  ^| verclsid.exe                     ^| COM object execution          ^| Low     ^|
echo   ^|  27  ^| mofcomp.exe                      ^| WMI MOF compile/execute       ^| Medium  ^|
echo   ^|  28  ^| msiexec.exe                      ^| MSI-based code execution      ^| CRIT    ^|
echo   ^|  29  ^| dxcap.exe                        ^| DLL loading abuse             ^| Low     ^|
echo   ^|  30  ^| cmd.exe                          ^| Shell / batch execution       ^| HIGH    ^|
echo   ^|  31  ^| wt.exe                           ^| Windows Terminal launcher     ^| Medium  ^|
echo   +------+----------------------------------+-------------------------------+---------+
echo.
echo   Impact:  Low/Medium = Safe to deny on production machines
echo            HIGH       = May break admin tools or legacy software
echo            CRIT       = Requires extra confirmation (see warnings below)
echo.
echo   Note: options 10,11,12 deny the binary itself.
echo         Stronger than extension enforcement which only blocks script files.
echo.
echo   Examples:  1,4,5,18  = Deny msbuild, certutil, installutil, desktopimgdownldr
echo              A         = Deny all 31 (CRIT items will prompt for confirmation)
echo              S         = Skip - no deny rules added
echo.

:ASK_LOLBAS
set "LOLBAS_CHOICE="
set /p LOLBAS_CHOICE="  Enter selection (or S to skip): "

if /i "!LOLBAS_CHOICE!"=="S" (
    echo   [+] No LOLBAS deny rules will be added.
    echo.> "%WDAC_FOLDER%\lolbas_deny.txt"
    goto LOLBAS_DONE
)

if /i "!LOLBAS_CHOICE!"=="A" set "LOLBAS_CHOICE=1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31"

powershell -Command "$p='!LOLBAS_CHOICE!' -split ',' | ForEach-Object {$_.Trim()}; if(($p | Where-Object {$_ -notmatch '^([1-9]|[12][0-9]|3[01])$'}).Count -gt 0){exit 1}else{exit 0}" >nul 2>&1
if !errorLevel! neq 0 (
    echo   INVALID: Use numbers 1-31 separated by commas, A for all, or S to skip.
    goto ASK_LOLBAS
)

set "LOLBAS_PADDED=,!LOLBAS_CHOICE!,"

:: Check CRITICAL and HIGH items - each has its own confirmation flow
echo !LOLBAS_PADDED! | findstr /c:",3," >nul 2>&1
if not errorlevel 1 goto WARN_RUNDLL32
goto CHECK_POWERSHELL

:WARN_RUNDLL32
echo.
echo   WARNING: rundll32.exe (option 3)
echo   ---------------------------------------------------------
echo   Denying rundll32.exe will block:
echo     - Classic Control Panel applets (.cpl files)
echo       e.g. Display, Date/Time, Programs and Features
echo     - Legacy third-party installers that call rundll32 directly
echo     - Screensaver configuration dialogs
echo.
echo   NOT affected:
echo     - Modern Windows Settings app (ms-settings://)
echo     - All standard Windows 10/11 functionality using Settings
echo     - GPO-managed machines where Control Panel is already restricted
echo.
echo   If this machine uses the Settings app and modern software,
echo   denying rundll32 is generally safe.
echo   When in doubt, run in Audit Mode first and check Event ID 3077.
echo   ---------------------------------------------------------
echo.
set "RUNDLL_CONFIRM="
set /p RUNDLL_CONFIRM="  Confirm deny rundll32.exe? [Y/N]: "
if /i "!RUNDLL_CONFIRM!"=="Y" goto CHECK_POWERSHELL
echo   Removing rundll32.exe from selection.
set "LOLBAS_CHOICE=!LOLBAS_CHOICE:,3,=,!"
set "LOLBAS_CHOICE=!LOLBAS_CHOICE:3,=!"
set "LOLBAS_CHOICE=!LOLBAS_CHOICE:,3=!"
set "LOLBAS_CHOICE=!LOLBAS_CHOICE:3=!"
set "LOLBAS_PADDED=,!LOLBAS_CHOICE!,"
echo.

:CHECK_POWERSHELL
echo !LOLBAS_PADDED! | findstr /c:",13," >nul 2>&1
if not errorlevel 1 goto WARN_POWERSHELL
goto CHECK_MSIEXEC

:WARN_POWERSHELL
echo.
echo   CRITICAL: powershell.exe (option 13)
echo   ---------------------------------------------------------
echo   Denying powershell.exe will block:
echo     - ALL PowerShell usage on this machine
echo     - This deployment script itself (uses PowerShell internally)
echo     - Windows Remote Management (WinRM / PSRemoting)
echo     - Many Windows admin and management tools
echo     - Some Windows Update and maintenance components
echo.
echo   This is an extreme lockdown measure. Only select this if:
echo     - PowerShell has already been replaced by another remote
echo       management solution on this machine
echo     - You have an alternative way to manage the machine
echo     - You understand the rollback script also uses PowerShell
echo.
echo   RECOMMENDATION: Do not deny powershell.exe. Use script
echo   enforcement (Step 2 option 4) to block unsigned .ps1 files
echo   instead - this is the right balance for most environments.
echo   ---------------------------------------------------------
echo.
set "PS_CONFIRM="
set /p PS_CONFIRM="  Confirm deny powershell.exe? [Y/N]: "
if /i "!PS_CONFIRM!"=="Y" goto CHECK_MSIEXEC
echo   Removing powershell.exe from selection.
set "LOLBAS_CHOICE=!LOLBAS_CHOICE:,13,=,!"
set "LOLBAS_CHOICE=!LOLBAS_CHOICE:13,=!"
set "LOLBAS_CHOICE=!LOLBAS_CHOICE:,13=!"
set "LOLBAS_CHOICE=!LOLBAS_CHOICE:13=!"
set "LOLBAS_PADDED=,!LOLBAS_CHOICE!,"
echo.

:CHECK_MSIEXEC
echo !LOLBAS_PADDED! | findstr /c:",28," >nul 2>&1
if not errorlevel 1 goto WARN_MSIEXEC
goto LOLBAS_SAVE

:WARN_MSIEXEC
echo.
echo   CRITICAL: msiexec.exe (option 28)
echo   ---------------------------------------------------------
echo   Denying msiexec.exe will block:
echo     - ALL MSI-based software installation
echo     - Some Windows Update components that deliver MSI packages
echo     - Software removal and repair via Programs and Features
echo     - Group Policy software deployment if it uses MSI
echo.
echo   This is appropriate only on fully locked-down machines
echo   where software is managed through a different mechanism
echo   (e.g. MSIX packages, SCCM without MSI, or image-based).
echo   ---------------------------------------------------------
echo.
set "MSI_CONFIRM="
set /p MSI_CONFIRM="  Confirm deny msiexec.exe? [Y/N]: "
if /i "!MSI_CONFIRM!"=="Y" goto LOLBAS_SAVE
echo   Removing msiexec.exe from selection.
set "LOLBAS_CHOICE=!LOLBAS_CHOICE:,28,=,!"
set "LOLBAS_CHOICE=!LOLBAS_CHOICE:28,=!"
set "LOLBAS_CHOICE=!LOLBAS_CHOICE:,28=!"
set "LOLBAS_CHOICE=!LOLBAS_CHOICE:28=!"
echo.

:CHECK_CMD
echo !LOLBAS_PADDED! | findstr /c:",30," >nul 2>&1
if not errorlevel 1 goto WARN_CMD
goto CHECK_WT

:WARN_CMD
echo.
echo   WARNING: cmd.exe (option 30)
echo   ---------------------------------------------------------
echo   Denying cmd.exe will block:
echo     - This script (Deploy-WDAC.bat) after Enforce Mode activates
echo     - All batch (.bat/.cmd) file execution including signed ones
echo     - Windows internal maintenance and installer operations
echo     - Any tool or script that shells out to cmd.exe
echo.
echo   RECOMMENDATION: Use script enforcement (Step 2 option 5) to
echo   block unsigned .bat/.cmd files instead. That stops attacker
echo   scripts without breaking Windows internals or this tool.
echo   ---------------------------------------------------------
echo.
set "CMD_CONFIRM="
set /p CMD_CONFIRM="  Confirm deny cmd.exe? [Y/N]: "
if /i "!CMD_CONFIRM!"=="Y" goto CHECK_WT
echo   Removing cmd.exe from selection.
set "LOLBAS_CHOICE=!LOLBAS_CHOICE:,30,=,!"
set "LOLBAS_CHOICE=!LOLBAS_CHOICE:30,=!"
set "LOLBAS_CHOICE=!LOLBAS_CHOICE:,30=!"
set "LOLBAS_CHOICE=!LOLBAS_CHOICE:30=!"
set "LOLBAS_PADDED=,!LOLBAS_CHOICE!,"
echo.

:CHECK_WT

:LOLBAS_SAVE
echo   [+] LOLBAS deny list: !LOLBAS_CHOICE!
echo !LOLBAS_CHOICE!> "%WDAC_FOLDER%\lolbas_deny.txt"
echo.

:LOLBAS_DONE

:: ============================================================
:: STEP 7 - BUILD POLICY
:: ============================================================
echo [STEP 7] Building WDAC policy...
echo.

set "BS=%WDAC_FOLDER%\build_policy.ps1"
if exist "%BS%" del "%BS%"

>> "%BS%" echo $xmlPath    = "C:\WDAC\WSSentinel.xml"
>> "%BS%" echo $base       = "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml"
>> "%BS%" echo $enforceDLL = [int]%ENFORCE_DLL%
>> "%BS%" echo $enforceScr = ([int]%ENFORCE_SCRIPTS%) -bor ([int]%ENFORCE_PS1%)
>> "%BS%" echo $enforcePkg = [int]%ENFORCE_PKG%
>> "%BS%" echo $copyPaste  = [int]%ALLOW_COPYPASTE%
>> "%BS%" echo $exRaw      = (Get-Content "C:\WDAC\app_exclusions.txt" -ErrorAction SilentlyContinue) -join ""
>> "%BS%" echo $exNums     = $exRaw -split ',' ^| ForEach-Object { $_.Trim() } ^| Where-Object { [int32]::TryParse($_, [ref]$null) } ^| ForEach-Object { [int]$_ }
>> "%BS%" echo Write-Host "  Copying base template..."
>> "%BS%" echo Copy-Item $base $xmlPath -Force
>> "%BS%" echo $g        = Set-CIPolicyIdInfo -FilePath $xmlPath -PolicyName "WindowsSentinelPolicy" -ResetPolicyID
>> "%BS%" echo $guidOnly = [regex]::Match($g, '\{[0-9a-fA-F-]+\}').Value
>> "%BS%" echo Write-Host "  GUID: $guidOnly"
>> "%BS%" echo $guidOnly ^| Out-File "C:\WDAC\policy_guid.txt" -Encoding ASCII -NoNewline
>> "%BS%" echo if ($enforceDLL -eq 0) {
>> "%BS%" echo     Set-RuleOption -FilePath $xmlPath -Option 19
>> "%BS%" echo     Write-Host "  [Option 19] DLL enforcement: OFF"
>> "%BS%" echo } else {
>> "%BS%" echo     Set-RuleOption -FilePath $xmlPath -Option 19 -Delete -ErrorAction SilentlyContinue
>> "%BS%" echo     Write-Host "  [Option 19] DLL enforcement: ON"
>> "%BS%" echo }
>> "%BS%" echo if ($enforceScr -eq 0) {
>> "%BS%" echo     Set-RuleOption -FilePath $xmlPath -Option 16
>> "%BS%" echo     Write-Host "  [Option 16] Script enforcement: OFF"
>> "%BS%" echo } else {
>> "%BS%" echo     Set-RuleOption -FilePath $xmlPath -Option 16 -Delete -ErrorAction SilentlyContinue
>> "%BS%" echo     Write-Host "  [Option 16] Script enforcement: ON"
>> "%BS%" echo }
>> "%BS%" echo if ($enforcePkg -eq 1) {
>> "%BS%" echo     Set-RuleOption -FilePath $xmlPath -Option 20 -Delete -ErrorAction SilentlyContinue
>> "%BS%" echo     Write-Host "  [Option 20] Package enforcement: ON"
>> "%BS%" echo } else {
>> "%BS%" echo     Set-RuleOption -FilePath $xmlPath -Option 20
>> "%BS%" echo     Write-Host "  [Option 20] Package enforcement: OFF"
>> "%BS%" echo }
>> "%BS%" echo Set-RuleOption -FilePath $xmlPath -Option 3
>> "%BS%" echo Write-Host "  [Option  3] Audit Mode: ON"
>> "%BS%" echo $rules      = @()
>> "%BS%" echo $ruleErrors = [System.Collections.Generic.List[string]]::new()
>> "%BS%" echo # AV/EDR rules - publisher first, path fallback (AV/EDR must never be blocked)
>> "%BS%" echo if (Test-Path "C:\WDAC\detected_av_paths.txt") {
>> "%BS%" echo     Get-Content "C:\WDAC\detected_av_paths.txt" ^| ForEach-Object {
>> "%BS%" echo         $p = $_.Trim()
>> "%BS%" echo         if ($p -eq "") { return }
>> "%BS%" echo         $dir = $p -replace "\\\*$", ""
>> "%BS%" echo         # Try publisher rule - find a signed exe in the AV/EDR folder
>> "%BS%" echo         $signedExe = $null
>> "%BS%" echo         $candidates = @(Get-ChildItem $dir -Filter "*.exe" -Recurse -Depth 2 -ErrorAction SilentlyContinue)
>> "%BS%" echo         foreach ($candidate in $candidates) {
>> "%BS%" echo             $sig = Get-AuthenticodeSignature $candidate.FullName -ErrorAction SilentlyContinue
>> "%BS%" echo             if ($sig -and $sig.Status -eq "Valid" -and $sig.SignerCertificate) {
>> "%BS%" echo                 $signedExe = $candidate.FullName
>> "%BS%" echo                 break
>> "%BS%" echo             }
>> "%BS%" echo         }
>> "%BS%" echo         if ($signedExe) {
>> "%BS%" echo             $exeDir      = Split-Path $signedExe -Parent
>> "%BS%" echo             $driverFiles = Get-SystemDriver -ScanPath $exeDir -UserPEs -ErrorAction Stop -WarningAction SilentlyContinue 2^>$null ^| Where-Object { $_ -isnot [string] }
>> "%BS%" echo             if ($driverFiles) {
>> "%BS%" echo                 try {
>> "%BS%" echo                     $r = New-CIPolicyRule -DriverFiles $driverFiles -Level Publisher -ErrorAction Stop
>> "%BS%" echo                     if ($r -and $r.Count -gt 0) {
>> "%BS%" echo                         $pub = (Get-AuthenticodeSignature $signedExe -EA SilentlyContinue).SignerCertificate.Subject
>> "%BS%" echo                         Write-Host "  [Publisher] AV/EDR: $dir - $pub"
>> "%BS%" echo                         foreach ($rl in $r) { $rules += $rl }
>> "%BS%" echo                     } else {
>> "%BS%" echo                         Write-Host "  [Path] AV/EDR (fallback - no publisher rules): $p"
>> "%BS%" echo                         $rules += (New-CIPolicyRule -FilePathRule $p)
>> "%BS%" echo                     }
>> "%BS%" echo                 } catch {
>> "%BS%" echo                     Write-Host "  [Path] AV/EDR (fallback - publisher error): $p"
>> "%BS%" echo                     $rules += (New-CIPolicyRule -FilePathRule $p)
>> "%BS%" echo                 }
>> "%BS%" echo             } else {
>> "%BS%" echo                 Write-Host "  [Path] AV/EDR (fallback - no signed files): $p"
>> "%BS%" echo                 $rules += (New-CIPolicyRule -FilePathRule $p)
>> "%BS%" echo             }
>> "%BS%" echo         } else {
>> "%BS%" echo             Write-Host "  [Path] AV/EDR (fallback - no signed exe found): $p"
>> "%BS%" echo             $rules += (New-CIPolicyRule -FilePathRule $p)
>> "%BS%" echo         }
>> "%BS%" echo     }
>> "%BS%" echo }
>> "%BS%" echo # VMware Tools path rules
>> "%BS%" echo if ($copyPaste -eq 1) {
>> "%BS%" echo     @("C:\Program Files\VMware\*", "C:\Program Files\Common Files\VMware\*") ^| ForEach-Object {
>> "%BS%" echo         $chk = $_ -replace "\\\*", ""
>> "%BS%" echo         if (Test-Path $chk) {
>> "%BS%" echo             Write-Host "  [Path] VMware Tools: $_"
>> "%BS%" echo             $rules += (New-CIPolicyRule -FilePathRule $_)
>> "%BS%" echo         }
>> "%BS%" echo     }
>> "%BS%" echo }
>> "%BS%" echo # Installed apps - publisher rules via Get-SystemDriver
>> "%BS%" echo # -ErrorAction Stop is required - SilentlyContinue causes empty results
>> "%BS%" echo if (Test-Path "C:\WDAC\detected_apps.json") {
>> "%BS%" echo     $apps = Get-Content "C:\WDAC\detected_apps.json" ^| ConvertFrom-Json
>> "%BS%" echo     foreach ($app in $apps) {
>> "%BS%" echo         if ($exNums -contains $app.Index) {
>> "%BS%" echo             Write-Host "  [SKIP] Excluded: $($app.Name)"
>> "%BS%" echo             continue
>> "%BS%" echo         }
>> "%BS%" echo         if ($app.Signed) {
>> "%BS%" echo             try {
>> "%BS%" echo                 $scanDir     = Split-Path $app.MainExe -Parent
>> "%BS%" echo                 $driverFiles = Get-SystemDriver -ScanPath $scanDir -UserPEs -ErrorAction Stop -WarningAction SilentlyContinue 2^>$null ^| Where-Object { $_ -isnot [string] }
>> "%BS%" echo                 if ($driverFiles) {
>> "%BS%" echo                     $r = New-CIPolicyRule -DriverFiles $driverFiles -Level Publisher -ErrorAction Stop
>> "%BS%" echo                     Write-Host "  [Publisher] $($app.Name) - $($app.Publisher)"
>> "%BS%" echo                     foreach ($rl in $r) { $rules += $rl }
>> "%BS%" echo                 } else {
>> "%BS%" echo                     throw "No driver files returned"
>> "%BS%" echo                 }
>> "%BS%" echo             } catch {
>> "%BS%" echo                 Write-Host "  [Skip] $($app.Name) - no publisher rule available"
>> "%BS%" echo                 $ruleErrors.Add("$($app.Name)")
>> "%BS%" echo             }
>> "%BS%" echo         } else {
>> "%BS%" echo             Write-Host "  [Skip] $($app.Name) - unsigned, not whitelisted"
>> "%BS%" echo         }
>> "%BS%" echo     }
>> "%BS%" echo }
>> "%BS%" echo if ($rules.Count -gt 0) {
>> "%BS%" echo     Write-Host ""
>> "%BS%" echo     Write-Host "  Merging $($rules.Count) rules into policy..."
>> "%BS%" echo     Merge-CIPolicy -PolicyPaths $xmlPath -Rules $rules -OutputFilePath $xmlPath ^| Out-Null
>> "%BS%" echo     Write-Host "  [+] Rules merged."
>> "%BS%" echo } else {
>> "%BS%" echo     Write-Host "  No additional rules to add."
>> "%BS%" echo }
>> "%BS%" echo # LOLBAS deny rules
>> "%BS%" echo $lolbasFile = "C:\WDAC\lolbas_deny.txt"
>> "%BS%" echo if (Test-Path $lolbasFile) {
>> "%BS%" echo     $lolbasRaw  = (Get-Content $lolbasFile -Raw -ErrorAction SilentlyContinue) -join ""
>> "%BS%" echo     $lolbasNums = $lolbasRaw -split ',' ^| ForEach-Object { $_.Trim() } ^| Where-Object { [int32]::TryParse($_, [ref]$null) } ^| ForEach-Object { [int]$_ }
>> "%BS%" echo     $denyRules  = @()
>> "%BS%" echo     if ($lolbasNums -contains 1) {
>> "%BS%" echo         Write-Host "  [DENY] msbuild.exe"
>> "%BS%" echo         @("C:\Windows\Microsoft.NET\Framework*\MSBuild.exe","C:\Windows\Microsoft.NET\Framework64*\MSBuild.exe") ^| ForEach-Object { $denyRules += (New-CIPolicyRule -FilePathRule $_ -Deny) }
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 2) {
>> "%BS%" echo         Write-Host "  [DENY] regsvr32.exe"
>> "%BS%" echo         @("C:\Windows\System32\regsvr32.exe","C:\Windows\SysWOW64\regsvr32.exe") ^| ForEach-Object { $denyRules += (New-CIPolicyRule -FilePathRule $_ -Deny) }
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 3) {
>> "%BS%" echo         Write-Host "  [DENY] rundll32.exe"
>> "%BS%" echo         @("C:\Windows\System32\rundll32.exe","C:\Windows\SysWOW64\rundll32.exe") ^| ForEach-Object { $denyRules += (New-CIPolicyRule -FilePathRule $_ -Deny) }
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 4) {
>> "%BS%" echo         Write-Host "  [DENY] certutil.exe"
>> "%BS%" echo         $denyRules += (New-CIPolicyRule -FilePathRule "C:\Windows\System32\certutil.exe" -Deny)
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 5) {
>> "%BS%" echo         Write-Host "  [DENY] installutil.exe"
>> "%BS%" echo         @("C:\Windows\Microsoft.NET\Framework*\InstallUtil.exe","C:\Windows\Microsoft.NET\Framework64*\InstallUtil.exe") ^| ForEach-Object { $denyRules += (New-CIPolicyRule -FilePathRule $_ -Deny) }
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 6) {
>> "%BS%" echo         Write-Host "  [DENY] regasm.exe"
>> "%BS%" echo         @("C:\Windows\Microsoft.NET\Framework*\RegAsm.exe","C:\Windows\Microsoft.NET\Framework64*\RegAsm.exe") ^| ForEach-Object { $denyRules += (New-CIPolicyRule -FilePathRule $_ -Deny) }
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 7) {
>> "%BS%" echo         Write-Host "  [DENY] regsvcs.exe"
>> "%BS%" echo         @("C:\Windows\Microsoft.NET\Framework*\RegSvcs.exe","C:\Windows\Microsoft.NET\Framework64*\RegSvcs.exe") ^| ForEach-Object { $denyRules += (New-CIPolicyRule -FilePathRule $_ -Deny) }
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 8) {
>> "%BS%" echo         Write-Host "  [DENY] cmstp.exe"
>> "%BS%" echo         $denyRules += (New-CIPolicyRule -FilePathRule "C:\Windows\System32\cmstp.exe" -Deny)
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 9) {
>> "%BS%" echo         Write-Host "  [DENY] odbcconf.exe"
>> "%BS%" echo         $denyRules += (New-CIPolicyRule -FilePathRule "C:\Windows\System32\odbcconf.exe" -Deny)
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 10) {
>> "%BS%" echo         Write-Host "  [DENY] cscript.exe"
>> "%BS%" echo         @("C:\Windows\System32\cscript.exe","C:\Windows\SysWOW64\cscript.exe") ^| ForEach-Object { $denyRules += (New-CIPolicyRule -FilePathRule $_ -Deny) }
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 11) {
>> "%BS%" echo         Write-Host "  [DENY] wscript.exe"
>> "%BS%" echo         @("C:\Windows\System32\wscript.exe","C:\Windows\SysWOW64\wscript.exe") ^| ForEach-Object { $denyRules += (New-CIPolicyRule -FilePathRule $_ -Deny) }
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 12) {
>> "%BS%" echo         Write-Host "  [DENY] mshta.exe"
>> "%BS%" echo         @("C:\Windows\System32\mshta.exe","C:\Windows\SysWOW64\mshta.exe") ^| ForEach-Object { $denyRules += (New-CIPolicyRule -FilePathRule $_ -Deny) }
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 13) {
>> "%BS%" echo         Write-Host "  [DENY] powershell.exe"
>> "%BS%" echo         @("C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe","C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe") ^| ForEach-Object { $denyRules += (New-CIPolicyRule -FilePathRule $_ -Deny) }
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 14) {
>> "%BS%" echo         Write-Host "  [DENY] pwsh.exe"
>> "%BS%" echo         $denyRules += (New-CIPolicyRule -FilePathRule "C:\Program Files\PowerShell\*\pwsh.exe" -Deny)
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 15) {
>> "%BS%" echo         Write-Host "  [DENY] presentationhost.exe"
>> "%BS%" echo         $denyRules += (New-CIPolicyRule -FilePathRule "C:\Windows\System32\presentationhost.exe" -Deny)
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 16) {
>> "%BS%" echo         Write-Host "  [DENY] ieexec.exe"
>> "%BS%" echo         @("C:\Windows\Microsoft.NET\Framework*\ieexec.exe","C:\Windows\Microsoft.NET\Framework64*\ieexec.exe") ^| ForEach-Object { $denyRules += (New-CIPolicyRule -FilePathRule $_ -Deny) }
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 17) {
>> "%BS%" echo         Write-Host "  [DENY] microsoft.workflow.compiler.exe"
>> "%BS%" echo         @("C:\Windows\Microsoft.NET\Framework*\microsoft.workflow.compiler.exe","C:\Windows\Microsoft.NET\Framework64*\microsoft.workflow.compiler.exe") ^| ForEach-Object { $denyRules += (New-CIPolicyRule -FilePathRule $_ -Deny) }
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 18) {
>> "%BS%" echo         Write-Host "  [DENY] desktopimgdownldr.exe"
>> "%BS%" echo         $denyRules += (New-CIPolicyRule -FilePathRule "C:\Windows\System32\desktopimgdownldr.exe" -Deny)
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 19) {
>> "%BS%" echo         Write-Host "  [DENY] syncappvpublishingserver.exe"
>> "%BS%" echo         @("C:\Windows\System32\syncappvpublishingserver.exe","C:\Windows\SysWOW64\syncappvpublishingserver.exe") ^| ForEach-Object { $denyRules += (New-CIPolicyRule -FilePathRule $_ -Deny) }
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 20) {
>> "%BS%" echo         Write-Host "  [DENY] bash.exe"
>> "%BS%" echo         $denyRules += (New-CIPolicyRule -FilePathRule "C:\Windows\System32\bash.exe" -Deny)
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 21) {
>> "%BS%" echo         Write-Host "  [DENY] wsl.exe"
>> "%BS%" echo         $denyRules += (New-CIPolicyRule -FilePathRule "C:\Windows\System32\wsl.exe" -Deny)
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 22) {
>> "%BS%" echo         Write-Host "  [DENY] ftp.exe"
>> "%BS%" echo         $denyRules += (New-CIPolicyRule -FilePathRule "C:\Windows\System32\ftp.exe" -Deny)
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 23) {
>> "%BS%" echo         Write-Host "  [DENY] bitsadmin.exe"
>> "%BS%" echo         $denyRules += (New-CIPolicyRule -FilePathRule "C:\Windows\System32\bitsadmin.exe" -Deny)
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 24) {
>> "%BS%" echo         Write-Host "  [DENY] forfiles.exe"
>> "%BS%" echo         $denyRules += (New-CIPolicyRule -FilePathRule "C:\Windows\System32\forfiles.exe" -Deny)
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 25) {
>> "%BS%" echo         Write-Host "  [DENY] pcalua.exe"
>> "%BS%" echo         $denyRules += (New-CIPolicyRule -FilePathRule "C:\Windows\System32\pcalua.exe" -Deny)
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 26) {
>> "%BS%" echo         Write-Host "  [DENY] verclsid.exe"
>> "%BS%" echo         $denyRules += (New-CIPolicyRule -FilePathRule "C:\Windows\System32\verclsid.exe" -Deny)
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 27) {
>> "%BS%" echo         Write-Host "  [DENY] mofcomp.exe"
>> "%BS%" echo         $denyRules += (New-CIPolicyRule -FilePathRule "C:\Windows\System32\wbem\mofcomp.exe" -Deny)
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 28) {
>> "%BS%" echo         Write-Host "  [DENY] msiexec.exe"
>> "%BS%" echo         @("C:\Windows\System32\msiexec.exe","C:\Windows\SysWOW64\msiexec.exe") ^| ForEach-Object { $denyRules += (New-CIPolicyRule -FilePathRule $_ -Deny) }
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 29) {
>> "%BS%" echo         Write-Host "  [DENY] dxcap.exe"
>> "%BS%" echo         $denyRules += (New-CIPolicyRule -FilePathRule "C:\Windows\System32\dxcap.exe" -Deny)
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 30) {
>> "%BS%" echo         Write-Host "  [DENY] cmd.exe"
>> "%BS%" echo         @("C:\Windows\System32\cmd.exe","C:\Windows\SysWOW64\cmd.exe") ^| ForEach-Object { $denyRules += (New-CIPolicyRule -FilePathRule $_ -Deny) }
>> "%BS%" echo     }
>> "%BS%" echo     if ($lolbasNums -contains 31) {
>> "%BS%" echo         Write-Host "  [DENY] wt.exe"
>> "%BS%" echo         @("C:\Program Files\WindowsApps\Microsoft.WindowsTerminal*\wt.exe","C:\Program Files\WindowsApps\Microsoft.WindowsTerminalPreview*\wt.exe") ^| ForEach-Object { $denyRules += (New-CIPolicyRule -FilePathRule $_ -Deny) }
>> "%BS%" echo     }
>> "%BS%" echo     if ($denyRules.Count -gt 0) {
>> "%BS%" echo         Write-Host ""
>> "%BS%" echo         Write-Host "  Merging $($denyRules.Count) LOLBAS deny rules into policy..."
>> "%BS%" echo         Merge-CIPolicy -PolicyPaths $xmlPath -Rules $denyRules -OutputFilePath $xmlPath ^| Out-Null
>> "%BS%" echo         Write-Host "  [+] LOLBAS deny rules merged."
>> "%BS%" echo     }
>> "%BS%" echo }
>> "%BS%" echo if ($ruleErrors.Count -gt 0) {
>> "%BS%" echo     Write-Host ""
>> "%BS%" echo     Write-Host "  Note: these apps had no extractable publisher rule and were skipped:"
>> "%BS%" echo     $ruleErrors ^| ForEach-Object { Write-Host "    - $_" }
>> "%BS%" echo }
>> "%BS%" echo Write-Host ""
>> "%BS%" echo Write-Host "[+] Policy build complete."
powershell -ExecutionPolicy Bypass -File "%BS%"
echo.

:: ============================================================
:: STEP 8 - GENERATE ROLLBACK SCRIPT
:: ============================================================
echo [STEP 8] Generating rollback script...

set "RB=%WDAC_FOLDER%\Remove-WDAC.ps1"
if exist "%RB%" del "%RB%"

>> "%RB%" echo # Remove-WDAC.ps1
>> "%RB%" echo # Removes the WindowsSentinel WDAC policy from this machine.
>> "%RB%" echo # Run as Administrator, then reboot to complete removal.
>> "%RB%" echo $guidFile  = "C:\WDAC\policy_guid.txt"
>> "%RB%" echo $activeDir = "$env:SystemRoot\System32\CodeIntegrity\CIPolicies\Active"
>> "%RB%" echo if (-not (Test-Path $guidFile)) {
>> "%RB%" echo     Write-Host "ERROR: policy_guid.txt not found. Cannot determine which policy to remove."
>> "%RB%" echo     Write-Host "Manually delete .cip files from: $activeDir"
>> "%RB%" echo     exit 1
>> "%RB%" echo }
>> "%RB%" echo $guid    = (Get-Content $guidFile -Raw).Trim()
>> "%RB%" echo $cipPath = "$activeDir\$guid.cip"
>> "%RB%" echo Write-Host "Removing policy: $guid"
>> "%RB%" echo if (Test-Path $cipPath) {
>> "%RB%" echo     Remove-Item $cipPath -Force
>> "%RB%" echo     Write-Host "[+] Removed: $cipPath"
>> "%RB%" echo } else {
>> "%RB%" echo     Write-Host "WARNING: .cip file not found at expected location: $cipPath"
>> "%RB%" echo     Write-Host "Files currently in Active directory:"
>> "%RB%" echo     Get-ChildItem $activeDir -Filter "*.cip" -ErrorAction SilentlyContinue ^| ForEach-Object {
>> "%RB%" echo         Write-Host "  $($_.FullName)"
>> "%RB%" echo     }
>> "%RB%" echo }
>> "%RB%" echo try {
>> "%RB%" echo     Invoke-CimMethod -Namespace "root\Microsoft\Windows\CI" -ClassName "PS_UpdateAndCompareCIPolicy" -MethodName "Update" -Arguments @{FilePath=$cipPath} ^| Out-Null
>> "%RB%" echo     Write-Host "[+] Policy refresh triggered."
>> "%RB%" echo } catch {
>> "%RB%" echo     Write-Host "Note: CIM refresh skipped - a reboot is required to fully remove the policy."
>> "%RB%" echo }
>> "%RB%" echo Write-Host ""
>> "%RB%" echo Write-Host "Reboot the machine to complete policy removal."

echo   [+] Rollback script created: %WDAC_FOLDER%\Remove-WDAC.ps1
echo   Keep this file safe. Run it as Administrator then reboot to remove the policy.
echo.

:: ============================================================
:: STEP 9 - DEPLOY IN AUDIT MODE
:: ============================================================
echo [STEP 9] Deploying policy in Audit Mode...
echo.

set "DP=%WDAC_FOLDER%\deploy_policy.ps1"
if exist "%DP%" del "%DP%"

>> "%DP%" echo $xmlPath   = "C:\WDAC\WSSentinel.xml"
>> "%DP%" echo $activeDir = "$env:SystemRoot\System32\CodeIntegrity\CIPolicies\Active"
>> "%DP%" echo New-Item -ItemType Directory -Force -Path $activeDir ^| Out-Null
>> "%DP%" echo $guid = (Get-Content "C:\WDAC\policy_guid.txt" -Raw).Trim()
>> "%DP%" echo $cip  = "C:\WDAC\$guid.cip"
>> "%DP%" echo $dest = "$activeDir\$guid.cip"
>> "%DP%" echo ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $cip ^| Out-Null
>> "%DP%" echo Write-Host "  Compiled: $cip"
>> "%DP%" echo Copy-Item $cip $dest -Force
>> "%DP%" echo Write-Host "  Copied to Active: $dest"
>> "%DP%" echo $r = Invoke-CimMethod -Namespace "root\Microsoft\Windows\CI" -ClassName "PS_UpdateAndCompareCIPolicy" -MethodName "Update" -Arguments @{FilePath=$dest}
>> "%DP%" echo if ($r.ReturnValue -eq 0) { Write-Host "[+] Policy loaded successfully (Audit Mode)." }
>> "%DP%" echo else { Write-Host "Warning: CIM ReturnValue = $($r.ReturnValue)" }

powershell -ExecutionPolicy Bypass -File "%DP%"
echo.

if "!ENFORCE_MODE!"=="1" goto DO_ENFORCE_ENTRY

:: ============================================================
:: FAST DEPLOY PROMPT - shown after /setup step 9
:: ============================================================
echo.
echo ============================================================
echo    OPTIONAL: ENFORCE + HARDEN NOW IN ONE GO
echo ============================================================
echo.
echo   Your policy is deployed in Audit Mode. Nothing is blocked yet.
echo.
echo   If your LOLBAS selection includes cmd.exe, PowerShell, or
echo   script enforcement is ON, you will NOT be able to run this
echo   script again once Enforce Mode activates. Choosing YES here
echo   does Enforce + Harden in one shot before the reboot.
echo.
echo   YES = Remove Audit Mode, enforce policy, apply NTFS ACLs,
echo         GPO settings and WDAC path deny rules, then reboot.
echo.
echo   NO  = Reboot into Audit Mode. Review /report first, then
echo         run /enforce and /harden separately while you still can.
echo.
set "FAST_CONF="
set /p FAST_CONF="  Enforce + Harden now? [YES/NO]: "
if /i "!FAST_CONF!"=="YES" (
    set FAST_DEPLOY=1
    goto DO_ENFORCE
)
goto SHOW_AUDIT_SUMMARY

:: ============================================================
:: ENFORCE MODE
:: Entry point when called directly with /enforce flag
:: ============================================================
:DO_ENFORCE_ENTRY
echo ============================================================
echo    SWITCHING TO ENFORCE MODE
echo ============================================================
echo.
echo   WARNING: After reboot ONLY whitelisted apps will run.
echo   Everything else will be BLOCKED.
echo.
echo   Extensions : !EXT_LIST!
echo.
if "!ENFORCE_SCRIPTS!"=="1" (
    echo   CRITICAL: Script enforcement is ON.
    echo   This .bat file will be BLOCKED after the reboot.
    echo   Use %WDAC_FOLDER%\Remove-WDAC.ps1 to recover if needed.
    echo.
)

:ASK_ENFORCE
set "CONFIRM="
set /p CONFIRM="  Type YES to enforce or NO to stay in Audit Mode: "
if /i "!CONFIRM!"=="NO"  goto CANCEL_ENFORCE
if /i "!CONFIRM!"=="YES" goto DO_ENFORCE
echo   Please type YES or NO.
goto ASK_ENFORCE

:CANCEL_ENFORCE
echo   Cancelled. Staying in Audit Mode.
goto SHOW_AUDIT_SUMMARY

:DO_ENFORCE
set "ES=%WDAC_FOLDER%\enforce_policy.ps1"
if exist "%ES%" del "%ES%"

>> "%ES%" echo $xmlPath   = "C:\WDAC\WSSentinel.xml"
>> "%ES%" echo $activeDir = "$env:SystemRoot\System32\CodeIntegrity\CIPolicies\Active"
>> "%ES%" echo $guid      = (Get-Content "C:\WDAC\policy_guid.txt" -Raw).Trim()
>> "%ES%" echo $cip       = "C:\WDAC\$guid.cip"
>> "%ES%" echo $dest      = "$activeDir\$guid.cip"
>> "%ES%" echo # Remove Audit Mode option from XML
>> "%ES%" echo Set-RuleOption -FilePath $xmlPath -Option 3 -Delete
>> "%ES%" echo $stillAudit = Select-String -Path $xmlPath -Pattern "Audit" -Quiet
>> "%ES%" echo if ($stillAudit) {
>> "%ES%" echo     Write-Host "ERROR: Audit Mode option still present in XML. Aborting to prevent policy corruption."
>> "%ES%" echo     exit 1
>> "%ES%" echo }
>> "%ES%" echo Write-Host "[+] Audit Mode removed from policy."
>> "%ES%" echo ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $cip ^| Out-Null
>> "%ES%" echo Write-Host "[+] Recompiled in Enforce Mode."
>> "%ES%" echo Copy-Item $cip $dest -Force
>> "%ES%" echo $r = Invoke-CimMethod -Namespace "root\Microsoft\Windows\CI" -ClassName "PS_UpdateAndCompareCIPolicy" -MethodName "Update" -Arguments @{FilePath=$dest}
>> "%ES%" echo if ($r.ReturnValue -eq 0) { Write-Host "[+] Enforce Mode deployed." }
>> "%ES%" echo else { Write-Host "Warning: CIM ReturnValue = $($r.ReturnValue)" }

powershell -ExecutionPolicy Bypass -File "%ES%"
echo.

if "!FAST_DEPLOY!"=="1" goto RUN_FAST_HARDEN
goto GENERATE_REPORT_THEN_REBOOT

:: ============================================================
:: RUN_FAST_HARDEN - called from fast deploy path after enforce
:: Generates and runs harden.ps1 inline then reboots via report
:: ============================================================
:RUN_FAST_HARDEN
echo.
echo ============================================================
echo    APPLYING INSIDER THREAT HARDENING
echo ============================================================
echo.
echo [*] Step 0 - Switching to Enforce Mode...
echo.

set "ES=%WDAC_FOLDER%\enforce_policy.ps1"
if exist "%ES%" del "%ES%"

>> "%ES%" echo $xmlPath   = "C:\WDAC\WSSentinel.xml"
>> "%ES%" echo $activeDir = "$env:SystemRoot\System32\CodeIntegrity\CIPolicies\Active"
>> "%ES%" echo $guid      = (Get-Content "C:\WDAC\policy_guid.txt" -Raw).Trim()
>> "%ES%" echo $cip       = "C:\WDAC\$guid.cip"
>> "%ES%" echo $dest      = "$activeDir\$guid.cip"
>> "%ES%" echo Set-RuleOption -FilePath $xmlPath -Option 3 -Delete
>> "%ES%" echo $stillAudit = Select-String -Path $xmlPath -Pattern "Audit" -Quiet
>> "%ES%" echo if ($stillAudit) {
>> "%ES%" echo     Write-Host "ERROR: Audit Mode still present. Aborting."
>> "%ES%" echo     exit 1
>> "%ES%" echo }
>> "%ES%" echo Write-Host "[+] Audit Mode removed from policy."
>> "%ES%" echo ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $cip ^| Out-Null
>> "%ES%" echo Write-Host "[+] Recompiled in Enforce Mode."
>> "%ES%" echo Copy-Item $cip $dest -Force
>> "%ES%" echo $r = Invoke-CimMethod -Namespace "root\Microsoft\Windows\CI" -ClassName "PS_UpdateAndCompareCIPolicy" -MethodName "Update" -Arguments @{FilePath=$dest}
>> "%ES%" echo if ($r.ReturnValue -eq 0) { Write-Host "[+] Enforce Mode deployed." }
>> "%ES%" echo else { Write-Host "Warning: CIM ReturnValue = $($r.ReturnValue)" }

powershell -ExecutionPolicy Bypass -File "%ES%"
echo.

echo [*] Step 1-3 - Applying insider threat hardening...
echo.

set "HS=%WDAC_FOLDER%\harden.ps1"
if exist "%HS%" del "%HS%"

>> "%HS%" echo $xmlPath    = "C:\WDAC\WSSentinel.xml"
>> "%HS%" echo $lolbasFile = "C:\WDAC\lolbas_deny.txt"
>> "%HS%" echo $lolbasRaw  = (Get-Content $lolbasFile -Raw -ErrorAction SilentlyContinue) -join ""
>> "%HS%" echo $lolbasNums = $lolbasRaw -split ',' ^| ForEach-Object { $_.Trim() } ^| Where-Object { [int32]::TryParse($_, [ref]$null) } ^| ForEach-Object { [int]$_ }
>> "%HS%" echo $pathMap = @{}
>> "%HS%" echo $pathMap[1]  = @("C:\Windows\Microsoft.NET\Framework*\MSBuild.exe","C:\Windows\Microsoft.NET\Framework64*\MSBuild.exe")
>> "%HS%" echo $pathMap[2]  = @("C:\Windows\System32\regsvr32.exe","C:\Windows\SysWOW64\regsvr32.exe")
>> "%HS%" echo $pathMap[3]  = @("C:\Windows\System32\rundll32.exe","C:\Windows\SysWOW64\rundll32.exe")
>> "%HS%" echo $pathMap[4]  = @("C:\Windows\System32\certutil.exe")
>> "%HS%" echo $pathMap[5]  = @("C:\Windows\Microsoft.NET\Framework*\InstallUtil.exe","C:\Windows\Microsoft.NET\Framework64*\InstallUtil.exe")
>> "%HS%" echo $pathMap[6]  = @("C:\Windows\Microsoft.NET\Framework*\RegAsm.exe","C:\Windows\Microsoft.NET\Framework64*\RegAsm.exe")
>> "%HS%" echo $pathMap[7]  = @("C:\Windows\Microsoft.NET\Framework*\RegSvcs.exe","C:\Windows\Microsoft.NET\Framework64*\RegSvcs.exe")
>> "%HS%" echo $pathMap[8]  = @("C:\Windows\System32\cmstp.exe")
>> "%HS%" echo $pathMap[9]  = @("C:\Windows\System32\odbcconf.exe")
>> "%HS%" echo $pathMap[10] = @("C:\Windows\System32\cscript.exe","C:\Windows\SysWOW64\cscript.exe")
>> "%HS%" echo $pathMap[11] = @("C:\Windows\System32\wscript.exe","C:\Windows\SysWOW64\wscript.exe")
>> "%HS%" echo $pathMap[12] = @("C:\Windows\System32\mshta.exe","C:\Windows\SysWOW64\mshta.exe")
>> "%HS%" echo $pathMap[13] = @("C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe","C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe")
>> "%HS%" echo $pathMap[14] = @("C:\Program Files\PowerShell\*\pwsh.exe")
>> "%HS%" echo $pathMap[15] = @("C:\Windows\System32\presentationhost.exe")
>> "%HS%" echo $pathMap[16] = @("C:\Windows\Microsoft.NET\Framework*\ieexec.exe","C:\Windows\Microsoft.NET\Framework64*\ieexec.exe")
>> "%HS%" echo $pathMap[17] = @("C:\Windows\Microsoft.NET\Framework*\microsoft.workflow.compiler.exe","C:\Windows\Microsoft.NET\Framework64*\microsoft.workflow.compiler.exe")
>> "%HS%" echo $pathMap[18] = @("C:\Windows\System32\desktopimgdownldr.exe")
>> "%HS%" echo $pathMap[19] = @("C:\Windows\System32\syncappvpublishingserver.exe","C:\Windows\SysWOW64\syncappvpublishingserver.exe")
>> "%HS%" echo $pathMap[20] = @("C:\Windows\System32\bash.exe")
>> "%HS%" echo $pathMap[21] = @("C:\Windows\System32\wsl.exe")
>> "%HS%" echo $pathMap[22] = @("C:\Windows\System32\ftp.exe")
>> "%HS%" echo $pathMap[23] = @("C:\Windows\System32\bitsadmin.exe")
>> "%HS%" echo $pathMap[24] = @("C:\Windows\System32\forfiles.exe")
>> "%HS%" echo $pathMap[25] = @("C:\Windows\System32\pcalua.exe")
>> "%HS%" echo $pathMap[26] = @("C:\Windows\System32\verclsid.exe")
>> "%HS%" echo $pathMap[27] = @("C:\Windows\System32\wbem\mofcomp.exe")
>> "%HS%" echo $pathMap[28] = @("C:\Windows\System32\msiexec.exe","C:\Windows\SysWOW64\msiexec.exe")
>> "%HS%" echo $pathMap[29] = @("C:\Windows\System32\dxcap.exe")
>> "%HS%" echo $pathMap[30] = @("C:\Windows\System32\cmd.exe","C:\Windows\SysWOW64\cmd.exe")
>> "%HS%" echo $pathMap[31] = @("C:\Program Files\WindowsApps\Microsoft.WindowsTerminal*\wt.exe","C:\Program Files\WindowsApps\Microsoft.WindowsTerminalPreview*\wt.exe")
>> "%HS%" echo Write-Host "[Section 1] Applying NTFS ACLs to denied LOLBAS binaries..."
>> "%HS%" echo $usersSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-545")
>> "%HS%" echo $aclCount = 0
>> "%HS%" echo foreach ($num in $lolbasNums) {
>> "%HS%" echo     if (-not $pathMap.ContainsKey($num)) { continue }
>> "%HS%" echo     foreach ($pattern in $pathMap[$num]) {
>> "%HS%" echo         $resolved = @(Get-Item -Path $pattern -ErrorAction SilentlyContinue)
>> "%HS%" echo         foreach ($file in $resolved) {
>> "%HS%" echo             try {
>> "%HS%" echo                 $acl  = Get-Acl $file.FullName -ErrorAction Stop
>> "%HS%" echo                 $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($usersSid,"ReadAndExecute","Deny")
>> "%HS%" echo                 $acl.AddAccessRule($rule)
>> "%HS%" echo                 Set-Acl $file.FullName $acl -ErrorAction Stop
>> "%HS%" echo                 Write-Host "  [ACL] $($file.FullName)"
>> "%HS%" echo                 $aclCount++
>> "%HS%" echo             } catch { Write-Host "  [SKIP] $($file.FullName) - $($_.Exception.Message)" }
>> "%HS%" echo         }
>> "%HS%" echo     }
>> "%HS%" echo }
>> "%HS%" echo Write-Host "  [+] ACLs applied to $aclCount binaries."
>> "%HS%" echo Write-Host ""
>> "%HS%" echo Write-Host "[Section 2] Applying GPO registry settings..."
>> "%HS%" echo $sysPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
>> "%HS%" echo if (-not (Test-Path $sysPath)) { New-Item -Path $sysPath -Force ^| Out-Null }
>> "%HS%" echo Set-ItemProperty $sysPath "DisableCMD" 1
>> "%HS%" echo Write-Host "  [GPO] cmd.exe disabled for standard users"
>> "%HS%" echo $expPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
>> "%HS%" echo if (-not (Test-Path $expPath)) { New-Item -Path $expPath -Force ^| Out-Null }
>> "%HS%" echo Set-ItemProperty $expPath "NoDrives" 4
>> "%HS%" echo Write-Host "  [GPO] C:\ hidden in Explorer"
>> "%HS%" echo Set-ItemProperty $expPath "NoViewOnDrive" 4
>> "%HS%" echo Write-Host "  [GPO] C:\ access blocked in Explorer"
>> "%HS%" echo $polPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
>> "%HS%" echo if (-not (Test-Path $polPath)) { New-Item -Path $polPath -Force ^| Out-Null }
>> "%HS%" echo Set-ItemProperty $polPath "DisableRegistryTools" 1
>> "%HS%" echo Write-Host "  [GPO] Registry Editor disabled for standard users"
>> "%HS%" echo Write-Host ""
>> "%HS%" echo Write-Host "[Section 3] Adding WDAC deny rules for user-writable paths..."
>> "%HS%" echo $denyPaths = @("C:\Users\*\Desktop\*","C:\Users\*\Downloads\*","C:\Users\*\AppData\Local\Temp\*","C:\Windows\Temp\*","C:\Temp\*")
>> "%HS%" echo $pathDenyRules = @()
>> "%HS%" echo foreach ($dp in $denyPaths) {
>> "%HS%" echo     $pathDenyRules += (New-CIPolicyRule -FilePathRule $dp -Deny)
>> "%HS%" echo     Write-Host "  [DENY PATH] $dp"
>> "%HS%" echo }
>> "%HS%" echo if ($pathDenyRules.Count -gt 0) {
>> "%HS%" echo     Merge-CIPolicy -PolicyPaths $xmlPath -Rules $pathDenyRules -OutputFilePath $xmlPath ^| Out-Null
>> "%HS%" echo     $guid = (Get-Content "C:\WDAC\policy_guid.txt" -Raw).Trim()
>> "%HS%" echo     $cip  = "C:\WDAC\$guid.cip"
>> "%HS%" echo     $dest = "$env:SystemRoot\System32\CodeIntegrity\CIPolicies\Active\$guid.cip"
>> "%HS%" echo     ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $cip ^| Out-Null
>> "%HS%" echo     Copy-Item $cip $dest -Force
>> "%HS%" echo     Invoke-CimMethod -Namespace "root\Microsoft\Windows\CI" -ClassName "PS_UpdateAndCompareCIPolicy" -MethodName "Update" -Arguments @{FilePath=$dest} ^| Out-Null
>> "%HS%" echo     Write-Host "  [+] WDAC path deny rules applied."
>> "%HS%" echo }
>> "%HS%" echo Write-Host ""
>> "%HS%" echo Write-Host "[+] Hardening complete."

powershell -ExecutionPolicy Bypass -File "%HS%"
echo.
goto GENERATE_REPORT_THEN_REBOOT

:: ============================================================
:: AUDIT MODE SUMMARY
:: ============================================================
:SHOW_AUDIT_SUMMARY
echo ============================================================
echo    AUDIT MODE ACTIVE - Nothing is blocked yet
echo ============================================================
echo.
echo   Mode       : AUDIT (monitor only)
echo   Extensions : !EXT_LIST!
if "!ALLOW_COPYPASTE!"=="1" echo   Copy/Paste : VMware Tools whitelisted
if "!ALLOW_COPYPASTE!"=="0" echo   Copy/Paste : VMware Tools blocked
echo.
echo   Next steps:
echo     1. Reboot to activate Audit Mode
echo     2. Use the machine normally for 1-7 days
echo     3. Generate a report to see what WOULD be blocked:
echo           Deploy-WDAC.bat /report
echo        Or check Event Viewer:
echo           Apps and Services / Microsoft / Windows / CodeIntegrity / Operational
echo           Look for Event ID 3076
echo     4. When satisfied with the whitelist: Deploy-WDAC.bat /enforce
echo.
echo   To remove the policy at any time:
echo     powershell -ExecutionPolicy Bypass -File %WDAC_FOLDER%\Remove-WDAC.ps1
echo     Then reboot.
echo.
echo   Rebooting in 10 seconds to activate Audit Mode...
echo   Press CTRL+C to cancel.
echo.
timeout /t 10
shutdown /r /t 0
goto END

:: ============================================================
:: GENERATE REPORT
:: ============================================================
:GENERATE_REPORT_THEN_REBOOT
:GENERATE_REPORT
echo [*] Generating WDAC report...
echo.

set "RS=%WDAC_FOLDER%\generate_report.ps1"
if exist "%RS%" del "%RS%"

>> "%RS%" echo $reportPath = "C:\WDAC\WDAC_Report.txt"
>> "%RS%" echo $sep        = "=" * 70
>> "%RS%" echo $now        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
>> "%RS%" echo $out        = [System.Collections.Generic.List[string]]::new()
>> "%RS%" echo $out.Add($sep)
>> "%RS%" echo $out.Add("  WDAC POLICY REPORT")
>> "%RS%" echo $out.Add("  Generated : $now")
>> "%RS%" echo $out.Add("  Machine   : $env:COMPUTERNAME")
>> "%RS%" echo $out.Add($sep)
>> "%RS%" echo $out.Add("")
>> "%RS%" echo $xmlBase = "C:\WDAC\WSSentinel.xml"
>> "%RS%" echo if (Test-Path $xmlBase) {
>> "%RS%" echo     $isAudit = [bool](Select-String -Path $xmlBase -Pattern "Audit" -Quiet)
>> "%RS%" echo     $mode    = if ($isAudit) { "AUDIT (monitor only - nothing is blocked)" } else { "ENFORCE (active blocking)" }
>> "%RS%" echo     $gLine   = Select-String -Path $xmlBase -Pattern "<PolicyID>\{(.+?)\}</PolicyID>"
>> "%RS%" echo     $guid    = if ($gLine) { $gLine.Matches[0].Groups[1].Value } else { "Unknown" }
>> "%RS%" echo     $out.Add("  POLICY INFORMATION")
>> "%RS%" echo     $out.Add("  Policy Name : WindowsSentinelPolicy")
>> "%RS%" echo     $out.Add("  Policy GUID : {$guid}")
>> "%RS%" echo     $out.Add("  Policy Mode : $mode")
>> "%RS%" echo     $out.Add("  Policy File : $xmlBase")
>> "%RS%" echo     $out.Add("")
>> "%RS%" echo }
>> "%RS%" echo $out.Add($sep)
>> "%RS%" echo $out.Add("  SECTION 1 - WHITELISTED ITEMS")
>> "%RS%" echo $out.Add($sep)
>> "%RS%" echo $out.Add("")
>> "%RS%" echo $out.Add("  [ALWAYS ALLOWED]")
>> "%RS%" echo $out.Add("    All files signed by Microsoft Corporation or Microsoft Windows.")
>> "%RS%" echo $out.Add("    Examples: notepad.exe, powershell.exe, cmd.exe, explorer.exe, calc.exe")
>> "%RS%" echo $out.Add("")
>> "%RS%" echo if (Test-Path "C:\WDAC\detected_av_paths.txt") {
>> "%RS%" echo     $avPaths = Get-Content "C:\WDAC\detected_av_paths.txt" ^| Where-Object { $_.Trim() -ne "" }
>> "%RS%" echo     if ($avPaths) {
>> "%RS%" echo         $out.Add("  [WHITELISTED] AV/EDR Products (path rules - anything in these folders runs)")
>> "%RS%" echo         foreach ($p in $avPaths) {
>> "%RS%" echo             $out.Add("    Folder: $p")
>> "%RS%" echo             $dir = $p -replace "\\\*", ""
>> "%RS%" echo             $exe = Get-ChildItem $dir -Filter "*.exe" -ErrorAction SilentlyContinue ^| Select-Object -First 1
>> "%RS%" echo             if ($exe) {
>> "%RS%" echo                 $sig = Get-AuthenticodeSignature $exe.FullName -ErrorAction SilentlyContinue
>> "%RS%" echo                 if ($sig.SignerCertificate) { $out.Add("    Signed By: $($sig.SignerCertificate.Subject)") }
>> "%RS%" echo             }
>> "%RS%" echo         }
>> "%RS%" echo         $out.Add("")
>> "%RS%" echo     }
>> "%RS%" echo }
>> "%RS%" echo if (Test-Path "C:\WDAC\detected_apps.json") {
>> "%RS%" echo     $apps   = Get-Content "C:\WDAC\detected_apps.json" ^| ConvertFrom-Json
>> "%RS%" echo     $exRaw  = (Get-Content "C:\WDAC\app_exclusions.txt" -ErrorAction SilentlyContinue) -join ""
>> "%RS%" echo     $exNums = $exRaw -split ',' ^| ForEach-Object { $_.Trim() } ^| Where-Object { [int32]::TryParse($_, [ref]$null) } ^| ForEach-Object { [int]$_ }
>> "%RS%" echo     $allowed = @($apps ^| Where-Object { $exNums -notcontains $_.Index })
>> "%RS%" echo     $denied  = @($apps ^| Where-Object { $exNums -contains $_.Index })
>> "%RS%" echo     if ($allowed.Count -gt 0) {
>> "%RS%" echo         $out.Add("  [WHITELISTED] Installed Applications")
>> "%RS%" echo         foreach ($app in $allowed) {
>> "%RS%" echo             $out.Add("    [$($app.RuleType)] $($app.Name)")
>> "%RS%" echo             $out.Add("      Path      : $($app.Path)")
>> "%RS%" echo             $out.Add("      Publisher : $($app.Publisher)")
>> "%RS%" echo             $out.Add("")
>> "%RS%" echo         }
>> "%RS%" echo     }
>> "%RS%" echo     if ($denied.Count -gt 0) {
>> "%RS%" echo         $out.Add("  [BLOCKED] Manually excluded applications")
>> "%RS%" echo         foreach ($app in $denied) {
>> "%RS%" echo             $out.Add("    Blocked: $($app.Name) at $($app.Path)")
>> "%RS%" echo         }
>> "%RS%" echo         $out.Add("")
>> "%RS%" echo     }
>> "%RS%" echo }
>> "%RS%" echo $out.Add($sep)
>> "%RS%" echo $out.Add("  SECTION 2 - EXTENSION ENFORCEMENT STATUS")
>> "%RS%" echo $out.Add($sep)
>> "%RS%" echo $out.Add("")
>> "%RS%" echo if (Test-Path $xmlBase) {
>> "%RS%" echo     $xc     = Get-Content $xmlBase -Raw
>> "%RS%" echo     $dllOff = $xc -match "Disabled:DLL Code Integrity"
>> "%RS%" echo     $scrOff = $xc -match "Disabled:Script Enforcement"
>> "%RS%" echo     $pkgOff = $xc -match "Disabled:UMCI"
>> "%RS%" echo     $out.Add("  Extension      Status       Notes")
>> "%RS%" echo     $out.Add("  ------------   ----------   ------------------------------------------------")
>> "%RS%" echo     $out.Add("  .exe           ENFORCED     Always enforced by base template")
>> "%RS%" echo     if ($dllOff) { $out.Add("  .dll           ALLOWED      Option 19 set - DLL enforcement off") }
>> "%RS%" echo     else         { $out.Add("  .dll           ENFORCED     Libraries must be signed or whitelisted") }
>> "%RS%" echo     $out.Add("  .sys           ENFORCED     Kernel drivers always enforced")
>> "%RS%" echo     if ($scrOff) { $out.Add("  .ps1           ALLOWED      Option 16 set - script enforcement off") }
>> "%RS%" echo     else         { $out.Add("  .ps1           ENFORCED     PowerShell scripts must be signed") }
>> "%RS%" echo     if ($scrOff) { $out.Add("  .bat / .cmd    ALLOWED      Script enforcement off") }
>> "%RS%" echo     else         { $out.Add("  .bat / .cmd    ENFORCED     Batch scripts must be signed") }
>> "%RS%" echo     if ($scrOff) { $out.Add("  .vbs / .js     ALLOWED      Script enforcement off") }
>> "%RS%" echo     else         { $out.Add("  .vbs / .js     ENFORCED     VBScript and JScript must be signed") }
>> "%RS%" echo     if ($scrOff) { $out.Add("  .hta           ALLOWED      Script enforcement off") }
>> "%RS%" echo     else         { $out.Add("  .hta           ENFORCED     HTML Applications must be signed") }
>> "%RS%" echo     if ($scrOff) { $out.Add("  .wsf / .wsh    ALLOWED      Script enforcement off") }
>> "%RS%" echo     else         { $out.Add("  .wsf / .wsh    ENFORCED     Windows Script Host files must be signed") }
>> "%RS%" echo     if ($pkgOff) { $out.Add("  .appx / .msix  ALLOWED      Package enforcement off") }
>> "%RS%" echo     else         { $out.Add("  .appx / .msix  ENFORCED     Only Microsoft-signed packages allowed") }
>> "%RS%" echo     $out.Add("")
>> "%RS%" echo }
>> "%RS%" echo $out.Add($sep)
>> "%RS%" echo $out.Add("  SECTION 3 - SETUP CONFIGURATION")
>> "%RS%" echo $out.Add($sep)
>> "%RS%" echo $out.Add("")
>> "%RS%" echo # VMware Tools status - check for VMware path rules in XML
>> "%RS%" echo if (Test-Path $xmlBase) {
>> "%RS%" echo     $xc = Get-Content $xmlBase -Raw
>> "%RS%" echo     if ($xc -match "VMware") {
>> "%RS%" echo         $out.Add("  VMware Tools   : WHITELISTED (path rules applied)")
>> "%RS%" echo     } else {
>> "%RS%" echo         $out.Add("  VMware Tools   : NOT whitelisted")
>> "%RS%" echo     }
>> "%RS%" echo     $out.Add("")
>> "%RS%" echo }
>> "%RS%" echo # LOLBAS deny rules
>> "%RS%" echo $lolbasNames = @{}
>> "%RS%" echo $lolbasNames[1]  = "msbuild.exe"
>> "%RS%" echo $lolbasNames[2]  = "regsvr32.exe"
>> "%RS%" echo $lolbasNames[3]  = "rundll32.exe"
>> "%RS%" echo $lolbasNames[4]  = "certutil.exe"
>> "%RS%" echo $lolbasNames[5]  = "installutil.exe"
>> "%RS%" echo $lolbasNames[6]  = "regasm.exe"
>> "%RS%" echo $lolbasNames[7]  = "regsvcs.exe"
>> "%RS%" echo $lolbasNames[8]  = "cmstp.exe"
>> "%RS%" echo $lolbasNames[9]  = "odbcconf.exe"
>> "%RS%" echo $lolbasNames[10] = "cscript.exe"
>> "%RS%" echo $lolbasNames[11] = "wscript.exe"
>> "%RS%" echo $lolbasNames[12] = "mshta.exe"
>> "%RS%" echo $lolbasNames[13] = "powershell.exe"
>> "%RS%" echo $lolbasNames[14] = "pwsh.exe"
>> "%RS%" echo $lolbasNames[15] = "presentationhost.exe"
>> "%RS%" echo $lolbasNames[16] = "ieexec.exe"
>> "%RS%" echo $lolbasNames[17] = "microsoft.workflow.compiler.exe"
>> "%RS%" echo $lolbasNames[18] = "desktopimgdownldr.exe"
>> "%RS%" echo $lolbasNames[19] = "syncappvpublishingserver.exe"
>> "%RS%" echo $lolbasNames[20] = "bash.exe"
>> "%RS%" echo $lolbasNames[21] = "wsl.exe"
>> "%RS%" echo $lolbasNames[22] = "ftp.exe"
>> "%RS%" echo $lolbasNames[23] = "bitsadmin.exe"
>> "%RS%" echo $lolbasNames[24] = "forfiles.exe"
>> "%RS%" echo $lolbasNames[25] = "pcalua.exe"
>> "%RS%" echo $lolbasNames[26] = "verclsid.exe"
>> "%RS%" echo $lolbasNames[27] = "mofcomp.exe"
>> "%RS%" echo $lolbasNames[28] = "msiexec.exe"
>> "%RS%" echo $lolbasNames[29] = "dxcap.exe"
>> "%RS%" echo $lolbasNames[30] = "cmd.exe"
>> "%RS%" echo $lolbasNames[31] = "wt.exe"
>> "%RS%" echo $lolbasFile = "C:\WDAC\lolbas_deny.txt"
>> "%RS%" echo if (Test-Path $lolbasFile) {
>> "%RS%" echo     $lolbasRaw  = (Get-Content $lolbasFile -Raw -ErrorAction SilentlyContinue) -join ""
>> "%RS%" echo     $lolbasNums = $lolbasRaw -split ',' ^| ForEach-Object { $_.Trim() } ^| Where-Object { [int32]::TryParse($_, [ref]$null) } ^| ForEach-Object { [int]$_ }
>> "%RS%" echo     if ($lolbasNums.Count -gt 0) {
>> "%RS%" echo         $out.Add("  LOLBAS Deny Rules Applied:")
>> "%RS%" echo         foreach ($num in ($lolbasNums ^| Sort-Object)) {
>> "%RS%" echo             $name = if ($lolbasNames.ContainsKey($num)) { $lolbasNames[$num] } else { "Unknown ($num)" }
>> "%RS%" echo             $out.Add("    [DENIED] $name")
>> "%RS%" echo         }
>> "%RS%" echo         $out.Add("")
>> "%RS%" echo         $out.Add("  Note: deny rules block these binaries even if they are Microsoft-signed.")
>> "%RS%" echo         $out.Add("        They take precedence over all whitelist rules.")
>> "%RS%" echo     } else {
>> "%RS%" echo         $out.Add("  LOLBAS Deny Rules : NONE (skipped during setup)")
>> "%RS%" echo     }
>> "%RS%" echo } else {
>> "%RS%" echo     $out.Add("  LOLBAS Deny Rules : File not found (run /setup to configure)")
>> "%RS%" echo }
>> "%RS%" echo $out.Add("")
>> "%RS%" echo $out.Add($sep)
>> "%RS%" echo $out.Add("  SECTION 4 - AUDIT EVENTS  (Event ID 3076 - Would Be Blocked)")
>> "%RS%" echo $out.Add($sep)
>> "%RS%" echo $out.Add("")
>> "%RS%" echo try {
>> "%RS%" echo     $evts = Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -EA SilentlyContinue ^|
>> "%RS%" echo             Where-Object { $_.Id -eq 3076 } ^| Select-Object -First 100
>> "%RS%" echo     if ($evts -and $evts.Count -gt 0) {
>> "%RS%" echo         $out.Add("  Total: $($evts.Count) audit events (showing first 100)")
>> "%RS%" echo         $out.Add("")
>> "%RS%" echo         $grouped = @{}
>> "%RS%" echo         foreach ($ev in $evts) {
>> "%RS%" echo             $m = [regex]::Match($ev.Message, 'File Name:\s+\\Device\\[^\\]+\\(.+)')
>> "%RS%" echo             if (-not $m.Success) { $m = [regex]::Match($ev.Message, 'attempted to load ([^\s]+\.[A-Za-z0-9]+)') }
>> "%RS%" echo             if ($m.Success) {
>> "%RS%" echo                 $fp  = $m.Groups[1].Value
>> "%RS%" echo                 $ext = [System.IO.Path]::GetExtension($fp).ToLower()
>> "%RS%" echo                 if (-not $grouped.ContainsKey($ext)) { $grouped[$ext] = [System.Collections.Generic.List[string]]::new() }
>> "%RS%" echo                 if (-not $grouped[$ext].Contains($fp)) { $grouped[$ext].Add($fp) }
>> "%RS%" echo             }
>> "%RS%" echo         }
>> "%RS%" echo         foreach ($ext in ($grouped.Keys ^| Sort-Object)) {
>> "%RS%" echo             $out.Add("  Extension: $ext  ($($grouped[$ext].Count) unique files)")
>> "%RS%" echo             foreach ($f in $grouped[$ext]) {
>> "%RS%" echo                 $out.Add("    WOULD BLOCK: $f")
>> "%RS%" echo                 $full = "C:\" + $f.TrimStart('\')
>> "%RS%" echo                 if (Test-Path $full) {
>> "%RS%" echo                     $sig = Get-AuthenticodeSignature $full -EA SilentlyContinue
>> "%RS%" echo                     $out.Add("    Signature  : $($sig.StatusMessage)")
>> "%RS%" echo                     if ($sig.SignerCertificate) { $out.Add("    Signed By  : $($sig.SignerCertificate.Subject)") }
>> "%RS%" echo                 }
>> "%RS%" echo             }
>> "%RS%" echo             $out.Add("")
>> "%RS%" echo         }
>> "%RS%" echo     } else {
>> "%RS%" echo         $out.Add("  No audit events found (Event ID 3076).")
>> "%RS%" echo         $out.Add("  This is expected right after setup or if the machine has not been used yet.")
>> "%RS%" echo     }
>> "%RS%" echo } catch { $out.Add("  Error reading event log: $_") }
>> "%RS%" echo $out.Add("")
>> "%RS%" echo $out.Add($sep)
>> "%RS%" echo $out.Add("  SECTION 5 - BLOCKED EVENTS  (Event ID 3077 - Actively Blocked)")
>> "%RS%" echo $out.Add($sep)
>> "%RS%" echo $out.Add("")
>> "%RS%" echo try {
>> "%RS%" echo     $bevts = Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -EA SilentlyContinue ^|
>> "%RS%" echo              Where-Object { $_.Id -eq 3077 } ^| Select-Object -First 100
>> "%RS%" echo     if ($bevts -and $bevts.Count -gt 0) {
>> "%RS%" echo         $out.Add("  Total: $($bevts.Count) blocked events (showing first 100)")
>> "%RS%" echo         $out.Add("")
>> "%RS%" echo         $bgrouped = @{}
>> "%RS%" echo         foreach ($ev in $bevts) {
>> "%RS%" echo             $m = [regex]::Match($ev.Message, 'File Name:\s+\\Device\\[^\\]+\\(.+)')
>> "%RS%" echo             if (-not $m.Success) { $m = [regex]::Match($ev.Message, 'attempted to load ([^\s]+\.[A-Za-z0-9]+)') }
>> "%RS%" echo             if ($m.Success) {
>> "%RS%" echo                 $fp  = $m.Groups[1].Value
>> "%RS%" echo                 $ext = [System.IO.Path]::GetExtension($fp).ToLower()
>> "%RS%" echo                 if (-not $bgrouped.ContainsKey($ext)) { $bgrouped[$ext] = [System.Collections.Generic.List[string]]::new() }
>> "%RS%" echo                 if (-not $bgrouped[$ext].Contains($fp)) { $bgrouped[$ext].Add($fp) }
>> "%RS%" echo             }
>> "%RS%" echo         }
>> "%RS%" echo         foreach ($ext in ($bgrouped.Keys ^| Sort-Object)) {
>> "%RS%" echo             $out.Add("  Extension: $ext  ($($bgrouped[$ext].Count) unique files)")
>> "%RS%" echo             foreach ($f in $bgrouped[$ext]) {
>> "%RS%" echo                 $out.Add("    BLOCKED  : $f")
>> "%RS%" echo                 $full = "C:\" + $f.TrimStart('\')
>> "%RS%" echo                 if (Test-Path $full) {
>> "%RS%" echo                     $sig = Get-AuthenticodeSignature $full -EA SilentlyContinue
>> "%RS%" echo                     $out.Add("    Signature: $($sig.StatusMessage)")
>> "%RS%" echo                 }
>> "%RS%" echo             }
>> "%RS%" echo             $out.Add("")
>> "%RS%" echo         }
>> "%RS%" echo     } else {
>> "%RS%" echo         $out.Add("  No blocked events (Event ID 3077). Expected if still in Audit Mode.")
>> "%RS%" echo     }
>> "%RS%" echo } catch { $out.Add("  Error reading event log: $_") }
>> "%RS%" echo $out.Add("")
>> "%RS%" echo $out.Add($sep)
>> "%RS%" echo $out.Add("  SECTION 6 - ACTIVE POLICIES ON THIS MACHINE")
>> "%RS%" echo $out.Add($sep)
>> "%RS%" echo $out.Add("")
>> "%RS%" echo $polDir = "$env:SystemRoot\System32\CodeIntegrity\CIPolicies\Active"
>> "%RS%" echo $pols   = Get-ChildItem $polDir -Filter "*.cip" -EA SilentlyContinue
>> "%RS%" echo if ($pols) {
>> "%RS%" echo     foreach ($pol in $pols) {
>> "%RS%" echo         $out.Add("  File : $($pol.Name)")
>> "%RS%" echo         $out.Add("  Size : $($pol.Length) bytes")
>> "%RS%" echo         $out.Add("  Date : $($pol.LastWriteTime)")
>> "%RS%" echo         $out.Add("")
>> "%RS%" echo     }
>> "%RS%" echo } else {
>> "%RS%" echo     $out.Add("  No active .cip policy files found.")
>> "%RS%" echo }
>> "%RS%" echo $out.Add($sep)
>> "%RS%" echo $out.Add("  END OF REPORT")
>> "%RS%" echo $out.Add($sep)
>> "%RS%" echo $out ^| Out-File -FilePath $reportPath -Encoding UTF8
>> "%RS%" echo Write-Host "[+] Report saved: $reportPath"

powershell -ExecutionPolicy Bypass -File "%RS%"
echo.
echo [+] Report saved to: %WDAC_FOLDER%\WDAC_Report.txt
echo.
start notepad "%WDAC_FOLDER%\WDAC_Report.txt"

if "!REPORT_ONLY!"=="1" goto END

echo ============================================================
echo    Rebooting in 10 seconds to activate Enforce Mode...
echo    Press CTRL+C to cancel.
echo ============================================================
echo.
timeout /t 10
shutdown /r /t 0
goto END

:: ============================================================
:: HARDEN MODE - Insider Threat Hardening
:: ============================================================
:DO_HARDEN
echo ============================================================
echo    ENFORCE + INSIDER THREAT HARDENING
echo ============================================================
echo.
echo   This will ENFORCE the policy and apply insider threat hardening.
echo.
echo     0. Enforce    - Switch policy from Audit to Enforce Mode.
echo                     After reboot all non-whitelisted apps are blocked.
echo.
echo     1. NTFS ACLs  - Deny read access on denied LOLBAS binaries.
echo                     Standard users cannot read or copy the tools.
echo.
echo     2. GPO Policy - Disable cmd.exe for standard users.
echo                     Hide C:\ drive from Explorer.
echo                     Disable Registry Editor for standard users.
echo.
echo     3. WDAC Rules - Deny execution from user-writable paths.
echo                     Desktop, Downloads and Temp blocked.
echo.
echo   Requires Deploy-WDAC.bat /setup to have been run first.
echo   Admin and SYSTEM accounts are NOT affected by hardening.
echo   A reboot is required to fully activate all changes.
echo.

if not exist "%WDAC_FOLDER%\lolbas_deny.txt" (
    echo   ERROR: lolbas_deny.txt not found. Run /setup first.
    goto END_NOCLEAN
)
if not exist "%WDAC_FOLDER%\policy_guid.txt" (
    echo   ERROR: policy_guid.txt not found. Run /setup first.
    goto END_NOCLEAN
)
if not exist "%XML_PATH%" (
    echo   ERROR: WSSentinel.xml not found. Run /setup first.
    goto END_NOCLEAN
)

set "HARDEN_CONF="
set /p HARDEN_CONF="  Enforce + Apply insider threat hardening? [YES/NO]: "
if /i "!HARDEN_CONF!" neq "YES" (
    echo   Cancelled.
    goto END_NOCLEAN
)
echo.
echo [*] Step 0 - Switching to Enforce Mode...
echo.

set "ES=%WDAC_FOLDER%\enforce_policy.ps1"
if exist "%ES%" del "%ES%"

>> "%ES%" echo $xmlPath   = "C:\WDAC\WSSentinel.xml"
>> "%ES%" echo $activeDir = "$env:SystemRoot\System32\CodeIntegrity\CIPolicies\Active"
>> "%ES%" echo $guid      = (Get-Content "C:\WDAC\policy_guid.txt" -Raw).Trim()
>> "%ES%" echo $cip       = "C:\WDAC\$guid.cip"
>> "%ES%" echo $dest      = "$activeDir\$guid.cip"
>> "%ES%" echo Set-RuleOption -FilePath $xmlPath -Option 3 -Delete
>> "%ES%" echo $stillAudit = Select-String -Path $xmlPath -Pattern "Audit" -Quiet
>> "%ES%" echo if ($stillAudit) {
>> "%ES%" echo     Write-Host "ERROR: Audit Mode still present. Aborting."
>> "%ES%" echo     exit 1
>> "%ES%" echo }
>> "%ES%" echo Write-Host "[+] Audit Mode removed from policy."
>> "%ES%" echo ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $cip ^| Out-Null
>> "%ES%" echo Write-Host "[+] Recompiled in Enforce Mode."
>> "%ES%" echo Copy-Item $cip $dest -Force
>> "%ES%" echo $r = Invoke-CimMethod -Namespace "root\Microsoft\Windows\CI" -ClassName "PS_UpdateAndCompareCIPolicy" -MethodName "Update" -Arguments @{FilePath=$dest}
>> "%ES%" echo if ($r.ReturnValue -eq 0) { Write-Host "[+] Enforce Mode deployed." }
>> "%ES%" echo else { Write-Host "Warning: CIM ReturnValue = $($r.ReturnValue)" }

powershell -ExecutionPolicy Bypass -File "%ES%"
echo.

echo [*] Step 1-3 - Applying insider threat hardening...
echo.

set "HS=%WDAC_FOLDER%\harden.ps1"
if exist "%HS%" del "%HS%"

>> "%HS%" echo $xmlPath    = "C:\WDAC\WSSentinel.xml"
>> "%HS%" echo $lolbasFile = "C:\WDAC\lolbas_deny.txt"
>> "%HS%" echo $lolbasRaw  = (Get-Content $lolbasFile -Raw -ErrorAction SilentlyContinue) -join ""
>> "%HS%" echo $lolbasNums = $lolbasRaw -split ',' ^| ForEach-Object { $_.Trim() } ^| Where-Object { [int32]::TryParse($_, [ref]$null) } ^| ForEach-Object { [int]$_ }
>> "%HS%" echo $pathMap = @{}
>> "%HS%" echo $pathMap[1]  = @("C:\Windows\Microsoft.NET\Framework*\MSBuild.exe","C:\Windows\Microsoft.NET\Framework64*\MSBuild.exe")
>> "%HS%" echo $pathMap[2]  = @("C:\Windows\System32\regsvr32.exe","C:\Windows\SysWOW64\regsvr32.exe")
>> "%HS%" echo $pathMap[3]  = @("C:\Windows\System32\rundll32.exe","C:\Windows\SysWOW64\rundll32.exe")
>> "%HS%" echo $pathMap[4]  = @("C:\Windows\System32\certutil.exe")
>> "%HS%" echo $pathMap[5]  = @("C:\Windows\Microsoft.NET\Framework*\InstallUtil.exe","C:\Windows\Microsoft.NET\Framework64*\InstallUtil.exe")
>> "%HS%" echo $pathMap[6]  = @("C:\Windows\Microsoft.NET\Framework*\RegAsm.exe","C:\Windows\Microsoft.NET\Framework64*\RegAsm.exe")
>> "%HS%" echo $pathMap[7]  = @("C:\Windows\Microsoft.NET\Framework*\RegSvcs.exe","C:\Windows\Microsoft.NET\Framework64*\RegSvcs.exe")
>> "%HS%" echo $pathMap[8]  = @("C:\Windows\System32\cmstp.exe")
>> "%HS%" echo $pathMap[9]  = @("C:\Windows\System32\odbcconf.exe")
>> "%HS%" echo $pathMap[10] = @("C:\Windows\System32\cscript.exe","C:\Windows\SysWOW64\cscript.exe")
>> "%HS%" echo $pathMap[11] = @("C:\Windows\System32\wscript.exe","C:\Windows\SysWOW64\wscript.exe")
>> "%HS%" echo $pathMap[12] = @("C:\Windows\System32\mshta.exe","C:\Windows\SysWOW64\mshta.exe")
>> "%HS%" echo $pathMap[13] = @("C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe","C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe")
>> "%HS%" echo $pathMap[14] = @("C:\Program Files\PowerShell\*\pwsh.exe")
>> "%HS%" echo $pathMap[15] = @("C:\Windows\System32\presentationhost.exe")
>> "%HS%" echo $pathMap[16] = @("C:\Windows\Microsoft.NET\Framework*\ieexec.exe","C:\Windows\Microsoft.NET\Framework64*\ieexec.exe")
>> "%HS%" echo $pathMap[17] = @("C:\Windows\Microsoft.NET\Framework*\microsoft.workflow.compiler.exe","C:\Windows\Microsoft.NET\Framework64*\microsoft.workflow.compiler.exe")
>> "%HS%" echo $pathMap[18] = @("C:\Windows\System32\desktopimgdownldr.exe")
>> "%HS%" echo $pathMap[19] = @("C:\Windows\System32\syncappvpublishingserver.exe","C:\Windows\SysWOW64\syncappvpublishingserver.exe")
>> "%HS%" echo $pathMap[20] = @("C:\Windows\System32\bash.exe")
>> "%HS%" echo $pathMap[21] = @("C:\Windows\System32\wsl.exe")
>> "%HS%" echo $pathMap[22] = @("C:\Windows\System32\ftp.exe")
>> "%HS%" echo $pathMap[23] = @("C:\Windows\System32\bitsadmin.exe")
>> "%HS%" echo $pathMap[24] = @("C:\Windows\System32\forfiles.exe")
>> "%HS%" echo $pathMap[25] = @("C:\Windows\System32\pcalua.exe")
>> "%HS%" echo $pathMap[26] = @("C:\Windows\System32\verclsid.exe")
>> "%HS%" echo $pathMap[27] = @("C:\Windows\System32\wbem\mofcomp.exe")
>> "%HS%" echo $pathMap[28] = @("C:\Windows\System32\msiexec.exe","C:\Windows\SysWOW64\msiexec.exe")
>> "%HS%" echo $pathMap[29] = @("C:\Windows\System32\dxcap.exe")
>> "%HS%" echo $pathMap[30] = @("C:\Windows\System32\cmd.exe","C:\Windows\SysWOW64\cmd.exe")
>> "%HS%" echo $pathMap[31] = @("C:\Program Files\WindowsApps\Microsoft.WindowsTerminal*\wt.exe","C:\Program Files\WindowsApps\Microsoft.WindowsTerminalPreview*\wt.exe")
>> "%HS%" echo # -------------------------------------------------------
>> "%HS%" echo # SECTION 1 - NTFS ACLs
>> "%HS%" echo # -------------------------------------------------------
>> "%HS%" echo Write-Host "[Section 1] Applying NTFS ACLs to denied LOLBAS binaries..."
>> "%HS%" echo Write-Host "  Deny read+execute for BUILTIN\Users. SYSTEM and Admins unaffected."
>> "%HS%" echo Write-Host ""
>> "%HS%" echo $usersSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-545")
>> "%HS%" echo $aclCount = 0
>> "%HS%" echo foreach ($num in $lolbasNums) {
>> "%HS%" echo     if (-not $pathMap.ContainsKey($num)) { continue }
>> "%HS%" echo     foreach ($pattern in $pathMap[$num]) {
>> "%HS%" echo         $resolved = @(Get-Item -Path $pattern -ErrorAction SilentlyContinue)
>> "%HS%" echo         foreach ($file in $resolved) {
>> "%HS%" echo             try {
>> "%HS%" echo                 $acl  = Get-Acl $file.FullName -ErrorAction Stop
>> "%HS%" echo                 $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($usersSid,"ReadAndExecute","Deny")
>> "%HS%" echo                 $acl.AddAccessRule($rule)
>> "%HS%" echo                 Set-Acl $file.FullName $acl -ErrorAction Stop
>> "%HS%" echo                 Write-Host "  [ACL] $($file.FullName)"
>> "%HS%" echo                 $aclCount++
>> "%HS%" echo             } catch {
>> "%HS%" echo                 Write-Host "  [SKIP] $($file.FullName) - $($_.Exception.Message)"
>> "%HS%" echo             }
>> "%HS%" echo         }
>> "%HS%" echo     }
>> "%HS%" echo }
>> "%HS%" echo Write-Host ""
>> "%HS%" echo Write-Host "  [+] ACLs applied to $aclCount binaries."
>> "%HS%" echo # -------------------------------------------------------
>> "%HS%" echo # SECTION 2 - GPO Registry
>> "%HS%" echo # -------------------------------------------------------
>> "%HS%" echo Write-Host ""
>> "%HS%" echo Write-Host "[Section 2] Applying GPO registry settings..."
>> "%HS%" echo Write-Host ""
>> "%HS%" echo $sysPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
>> "%HS%" echo if (-not (Test-Path $sysPath)) { New-Item -Path $sysPath -Force ^| Out-Null }
>> "%HS%" echo Set-ItemProperty $sysPath "DisableCMD" 1
>> "%HS%" echo Write-Host "  [GPO] cmd.exe disabled for standard users"
>> "%HS%" echo $expPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
>> "%HS%" echo if (-not (Test-Path $expPath)) { New-Item -Path $expPath -Force ^| Out-Null }
>> "%HS%" echo Set-ItemProperty $expPath "NoDrives" 4
>> "%HS%" echo Write-Host "  [GPO] C:\ hidden in Explorer (NoDrives=4)"
>> "%HS%" echo Set-ItemProperty $expPath "NoViewOnDrive" 4
>> "%HS%" echo Write-Host "  [GPO] C:\ contents blocked in Explorer (NoViewOnDrive=4)"
>> "%HS%" echo $polPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
>> "%HS%" echo if (-not (Test-Path $polPath)) { New-Item -Path $polPath -Force ^| Out-Null }
>> "%HS%" echo Set-ItemProperty $polPath "DisableRegistryTools" 1
>> "%HS%" echo Write-Host "  [GPO] Registry Editor disabled for standard users"
>> "%HS%" echo Write-Host ""
>> "%HS%" echo Write-Host "  [+] GPO settings applied. Takes effect at next logon."
>> "%HS%" echo # -------------------------------------------------------
>> "%HS%" echo # SECTION 3 - WDAC deny rules for user-writable paths
>> "%HS%" echo # -------------------------------------------------------
>> "%HS%" echo Write-Host ""
>> "%HS%" echo Write-Host "[Section 3] Adding WDAC deny rules for user-writable paths..."
>> "%HS%" echo Write-Host "  Blocks execution from Desktop, Downloads and Temp"
>> "%HS%" echo Write-Host "  even for Microsoft-signed binaries copied there."
>> "%HS%" echo Write-Host ""
>> "%HS%" echo $denyPaths = @("C:\Users\*\Desktop\*","C:\Users\*\Downloads\*","C:\Users\*\AppData\Local\Temp\*","C:\Windows\Temp\*","C:\Temp\*")
>> "%HS%" echo $pathDenyRules = @()
>> "%HS%" echo foreach ($dp in $denyPaths) {
>> "%HS%" echo     $pathDenyRules += (New-CIPolicyRule -FilePathRule $dp -Deny)
>> "%HS%" echo     Write-Host "  [DENY PATH] $dp"
>> "%HS%" echo }
>> "%HS%" echo if ($pathDenyRules.Count -gt 0) {
>> "%HS%" echo     Write-Host ""
>> "%HS%" echo     Write-Host "  Merging $($pathDenyRules.Count) path deny rules into policy..."
>> "%HS%" echo     Merge-CIPolicy -PolicyPaths $xmlPath -Rules $pathDenyRules -OutputFilePath $xmlPath ^| Out-Null
>> "%HS%" echo     $guid = (Get-Content "C:\WDAC\policy_guid.txt" -Raw).Trim()
>> "%HS%" echo     $cip  = "C:\WDAC\$guid.cip"
>> "%HS%" echo     $dest = "$env:SystemRoot\System32\CodeIntegrity\CIPolicies\Active\$guid.cip"
>> "%HS%" echo     ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $cip ^| Out-Null
>> "%HS%" echo     Copy-Item $cip $dest -Force
>> "%HS%" echo     Invoke-CimMethod -Namespace "root\Microsoft\Windows\CI" -ClassName "PS_UpdateAndCompareCIPolicy" -MethodName "Update" -Arguments @{FilePath=$dest} ^| Out-Null
>> "%HS%" echo     Write-Host "  [+] Policy updated and redeployed."
>> "%HS%" echo }
>> "%HS%" echo Write-Host ""
>> "%HS%" echo Write-Host "============================================================"
>> "%HS%" echo Write-Host "  HARDENING COMPLETE"
>> "%HS%" echo Write-Host "============================================================"
>> "%HS%" echo Write-Host ""
>> "%HS%" echo Write-Host "  Applied:"
>> "%HS%" echo Write-Host "    - LOLBAS binaries locked  : read+execute denied for Users"
>> "%HS%" echo Write-Host "    - cmd.exe                 : disabled via GPO for standard users"
>> "%HS%" echo Write-Host "    - C:\ drive               : hidden from Explorer"
>> "%HS%" echo Write-Host "    - Registry Editor         : disabled for standard users"
>> "%HS%" echo Write-Host "    - Desktop/Downloads/Temp  : execution blocked via WDAC"
>> "%HS%" echo Write-Host ""
>> "%HS%" echo Write-Host "  Reboot recommended to apply changes to active user sessions."

powershell -ExecutionPolicy Bypass -File "%HS%"
echo.
echo [+] Enforce + Hardening complete.
echo.
goto GENERATE_REPORT_THEN_REBOOT

:: ============================================================
:: REMOVE MODE
:: ============================================================
:DO_REMOVE
echo ============================================================
echo    REMOVE WDAC POLICY
echo ============================================================
echo.
echo   This will remove the WindowsSentinel WDAC policy.
echo   After reboot, all application blocking will be disabled.
echo.

set "CONFIRM_RM="
set /p CONFIRM_RM="  Type YES to confirm removal: "
if /i "!CONFIRM_RM!" neq "YES" (
    echo   Cancelled.
    goto END_NOCLEAN
)
echo.

if not exist "%WDAC_FOLDER%\Remove-WDAC.ps1" (
    echo   ERROR: Remove-WDAC.ps1 not found at %WDAC_FOLDER%
    echo   The rollback script is created the first time you run Deploy-WDAC.bat.
    echo   You can manually delete .cip files from:
    echo     %SystemRoot%\System32\CodeIntegrity\CIPolicies\Active\
    goto END_NOCLEAN
)

powershell -ExecutionPolicy Bypass -File "%WDAC_FOLDER%\Remove-WDAC.ps1"
echo.
echo   [+] Policy removal staged.
echo.
echo   Rebooting in 10 seconds to complete removal...
echo   Press CTRL+C to cancel.
echo.
timeout /t 10
shutdown /r /t 0
goto END_NOCLEAN

:: ============================================================
:: USAGE - Printed when no valid flag is supplied
:: ============================================================
:SHOW_USAGE
echo.
echo   WindowsSentinel - WDAC Deployment Tool
echo.
echo   Usage:  Deploy-WDAC.bat [flag]
echo.
echo     /setup     Run the full setup wizard (first-time deployment)
echo     /enforce   Switch the deployed policy to Enforce Mode
echo     /report    Generate an audit report
echo     /remove    Remove the deployed policy and reboot
echo     /harden    Enforce policy + apply insider threat hardening
echo     /help      Show full help including step-by-step descriptions
echo.
echo   Run Deploy-WDAC.bat /help for detailed information.
echo.
goto END_NOCLEAN

:: ============================================================
:: HELP - Full reference printed by /help flag
:: ============================================================
:SHOW_HELP
echo.
echo ============================================================
echo    WindowsSentinel - WDAC Deployment Tool
echo    Windows Defender Application Control for SOC and Sysadmins
echo ============================================================
echo.
echo   WHAT THIS SCRIPT DOES
echo   ---------------------
echo   This script deploys a Windows Defender Application Control
echo   (WDAC) policy that restricts which programs are allowed to
echo   run on this machine. By default it trusts only Microsoft-
echo   signed binaries. Everything else - Chrome, Firefox, Office,
echo   third-party tools - is blocked unless you explicitly whitelist
echo   it during setup.
echo.
echo   There are two stages:
echo.
echo     Audit Mode   - The policy is active but nothing is blocked.
echo                    Windows logs what WOULD have been blocked so
echo                    you can review and adjust before committing.
echo                    (Event ID 3076 in CodeIntegrity event log)
echo.
echo     Enforce Mode - The policy actively blocks unauthorized files.
echo                    Blocked attempts are logged as Event ID 3077.
echo                    Only whitelisted apps will run.
echo.
echo   REQUIREMENTS
echo   ------------
echo     - Must be run as Administrator
echo     - Windows 10/11 Enterprise or Server 2016+
echo     - ConfigCI PowerShell module (ships with above editions)
echo     - citool.exe for pre-flight check (Windows 11 only)
echo.
echo   FLAGS
echo   -----
echo     /setup     Runs the full first-time setup wizard.
echo                Scans the machine, lets you choose which apps
echo                to whitelist, builds the policy, and deploys
echo                it in Audit Mode. Reboots at the end.
echo.
echo     /enforce   Switches the already-deployed policy from Audit
echo                Mode into Enforce Mode. Run this after reviewing
echo                the /report output and confirming nothing
echo                legitimate will be blocked. Reboots at the end.
echo.
echo     /report    Generates a full report without changing anything.
echo                Shows whitelisted items, extension enforcement
echo                status, audit events (what would be blocked),
echo                active block events, and policies on disk.
echo                Saves to C:\WDAC\WDAC_Report.txt and opens it.
echo.
echo     /remove    Removes the WindowsSentinel policy from this
echo                machine and reboots. All application blocking
echo                is disabled after reboot. Uses the rollback
echo                script at C:\WDAC\Remove-WDAC.ps1.
echo.
echo     /harden    Enforces the policy AND applies insider threat
echo                hardening in a single operation:
echo                  Step 0 - Switches policy to Enforce Mode
echo                  Step 1 - NTFS ACLs: denies read+execute on all
echo                           denied LOLBAS binaries for standard
echo                           users so they cannot copy the tools
echo                  Step 2 - GPO: disables cmd.exe for standard
echo                           users, hides C:\ drive in Explorer,
echo                           disables Registry Editor
echo                  Step 3 - WDAC path deny rules: blocks execution
echo                           from Desktop, Downloads and Temp even
echo                           for Microsoft-signed binaries copied there
echo                Generates a report and reboots at the end.
echo                Use this instead of /enforce when you also want
echo                the insider threat protections applied.
echo.
echo     /help      Shows this screen.
echo.
echo   SETUP WIZARD - STEP BY STEP  (/setup)
echo   --------------------------------------
echo.
echo     STEP 0  Pre-flight Check
echo             Scans all existing WDAC policies already on the
echo             machine using citool.exe. Reports:
echo               - Smart App Control status (on or off)
echo               - Microsoft platform policies (safe, listed)
echo               - Enterprise or third-party policies (conflict warning)
echo             If conflicts are found you are asked to confirm
echo             before continuing. Skipped gracefully on Windows 10
echo             where citool.exe is not available.
echo.
echo     STEP 1  Prerequisites
echo             Confirms the Microsoft base policy template exists
echo             and the ConfigCI PowerShell module is loaded.
echo             Exits early with a clear message if either is missing.
echo.
echo     STEP 2  File Extension Selection
echo             Choose which file types to enforce:
echo               1 = .exe          Executables
echo               2 = .dll          Libraries loaded into processes
echo               3 = .sys          Kernel drivers
echo               4 = .ps1          PowerShell scripts
echo               5 = .bat/.cmd     Batch scripts
echo               6 = .vbs/.js      VBScript and JScript
echo               7 = .hta          HTML Applications (common attack vector)
echo               8 = .wsf/.wsh     Windows Script Host files (attack vector)
echo               9 = .appx/.msix   Package installers
echo               A = All of the above (recommended)
echo             You can combine options, e.g. 1,2,3 or 1,2,7,8
echo             Note: options 4,5,6,7,8 all use script enforcement (Option 16).
echo             Selecting any one of them enables it for all script types.
echo             If you select 4,5,6,7 or 8, this script itself will be
echo             blocked after Enforce Mode activates.
echo.
echo     STEP 3  VMware Tools
echo             If this is a VMware virtual machine, VMware Tools
echo             provides copy/paste and display scaling between
echo             the host and VM. Choose Y to whitelist it.
echo.
echo     STEP 4  AV/EDR Auto-Detection
echo             Automatically scans for 21 known security products
echo             (CrowdStrike, SentinelOne, Cybereason, Sophos, etc.)
echo             using three methods:
echo               - Known install folder patterns
echo               - Windows Security Center registration
echo               - Running service executable paths
echo             Detected products are always whitelisted so they
echo             are never blocked by the policy.
echo.
echo     STEP 5  Installed Application Scanner
echo             Scans Program Files and Program Files (x86) for
echo             installed software. Displays a numbered table:
echo.
echo               No.  Application         Rule Type   Publisher
echo               ---  ------------------  ----------  -----------------
echo                 1  7-Zip               Path        UNSIGNED
echo                 2  Google Chrome       Publisher   Google LLC
echo                 3  Mozilla Firefox     Publisher   Mozilla Corporation
echo.
echo             Two rule types:
echo               Publisher - Rule tied to the app signing certificate.
echo                           Only files signed by that company run.
echo                           More secure. Used for signed apps.
echo               Path      - Rule tied to the install folder location.
echo                           Anything placed in that folder can run.
echo                           Used as fallback for unsigned apps.
echo.
echo             Press ENTER to whitelist ALL apps shown.
echo             Type numbers to EXCLUDE (block) specific apps, e.g. 1,4,7
echo.
echo     STEP 6  LOLBAS Deny List
echo             Living Off The Land Binaries - Microsoft-signed tools
echo             commonly abused by attackers to execute code without
echo             dropping malicious files. Select which to deny:
echo               1  = msbuild.exe                     Inline C# via .csproj/.targets
echo               2  = regsvr32.exe                    Squiblydoo COM scriptlet execution
echo               3  = rundll32.exe                    DLL/script execution (HIGH)
echo               4  = certutil.exe                    File download and base64 decode
echo               5  = installutil.exe                 .NET assembly WDAC bypass
echo               6  = regasm.exe                      .NET COM registration + execution
echo               7  = regsvcs.exe                     .NET COM+ registration + execution
echo               8  = cmstp.exe                       UAC bypass via INF file
echo               9  = odbcconf.exe                    DLL execution via ODBC config
echo               10 = cscript.exe                     JScript/VBScript execution (HIGH)
echo               11 = wscript.exe                     JScript/VBScript execution (HIGH)
echo               12 = mshta.exe                       HTA/JScript/VBScript execution
echo               13 = powershell.exe                  PowerShell execution (CRITICAL)
echo               14 = pwsh.exe                        PowerShell 7 execution (HIGH)
echo               15 = presentationhost.exe            XAML execution
echo               16 = ieexec.exe                      .NET remote execution
echo               17 = microsoft.workflow.compiler.exe Workflow compile-and-execute
echo               18 = desktopimgdownldr.exe           Payload retrieval via reg key
echo               19 = syncappvpublishingserver.exe    Script execution via App-V
echo               20 = bash.exe                        WSL abuse
echo               21 = wsl.exe                         WSL abuse
echo               22 = ftp.exe                         File transfer / exfil
echo               23 = bitsadmin.exe                   Payload download (legacy)
echo               24 = forfiles.exe                    Command execution via files
echo               25 = pcalua.exe                      App Compat Layer execution
echo               26 = verclsid.exe                    COM object execution
echo               27 = mofcomp.exe                     WMI MOF compile/execute
echo               28 = msiexec.exe                     MSI-based code execution (CRITICAL)
echo               29 = dxcap.exe                       DLL loading abuse
echo               30 = cmd.exe                         Shell / batch execution (HIGH)
echo               31 = wt.exe                          Windows Terminal launcher
echo               A  = Deny all 31 (CRIT/HIGH items prompt for confirmation)
echo               S  = Skip (no deny rules added)
echo             Options 3, 13, 28, 30 each show a confirmation warning.
echo             Options 13 (powershell.exe) and 28 (msiexec.exe) are
echo             CRITICAL - denying them can break management tools and
echo             software installation respectively.
echo             Option 30 (cmd.exe) is HIGH - blocks this script after enforce.
echo.
echo     STEP 7  Build Policy
echo             Copies the Microsoft DefaultWindows_Enforced base
echo             template and applies your selections:
echo               - Sets DLL enforcement on or off (Option 19)
echo               - Sets script enforcement on or off (Option 16)
echo               - Sets package enforcement on or off (Option 20)
echo               - Enables Audit Mode (Option 3)
echo               - Creates publisher rules for signed apps
echo               - Creates path rules for unsigned apps and AV/EDR
echo               - Merges LOLBAS deny rules into the policy
echo               - Merges all rules into a single policy XML
echo             Output: C:\WDAC\WSSentinel.xml
echo.
echo     STEP 8  Rollback Script
echo             Generates C:\WDAC\Remove-WDAC.ps1
echo             This is your recovery script. If Enforce Mode ever
echo             blocks something critical, run this as Administrator
echo             then reboot to fully remove the policy.
echo             Keep this file accessible at all times.
echo.
echo     STEP 9  Deploy in Audit Mode
echo             Compiles WSSentinel.xml to a binary .cip file,
echo             copies it to the Active policies folder, triggers
echo             a live reload, then reboots into Audit Mode.
echo             Nothing is blocked yet after this reboot.
echo.
echo   TYPICAL WORKFLOW
echo   ----------------
echo   There are two paths depending on how much review time you want.
echo.
echo   PATH A - Full audit review (recommended for production)
echo   --------------------------------------------------------
echo     1. Deploy-WDAC.bat /setup
echo        Run the wizard. Reboot into Audit Mode.
echo.
echo     2. Use the machine normally for several days.
echo        Run your apps, do your work as usual.
echo.
echo     3. Deploy-WDAC.bat /report
echo        Review WDAC_Report.txt. Section 4 lists everything
echo        that WOULD have been blocked. If you see legitimate
echo        apps there, run /setup again and add them to the
echo        whitelist before enforcing.
echo.
echo     4. Deploy-WDAC.bat /harden
echo        When satisfied nothing legitimate will be blocked,
echo        run /harden. This enforces the policy AND applies
echo        insider threat hardening (NTFS ACLs, GPO settings,
echo        WDAC path deny rules) in one shot. Reboots at end.
echo        Machine is fully locked down after reboot.
echo.
echo        If you only want enforcement without hardening:
echo          Deploy-WDAC.bat /enforce
echo.
echo     5. Deploy-WDAC.bat /report  (ongoing)
echo        Run periodically to monitor what is being blocked.
echo.
echo   PATH B - Single session lockdown (known environments)
echo   -------------------------------------------------------
echo     1. Deploy-WDAC.bat /setup
echo        At the end of Step 9, answer YES to the prompt:
echo          "Enforce + Harden now? [YES/NO]"
echo        This enforces the policy, applies all hardening,
echo        and reboots in one session - before cmd.exe or
echo        PowerShell are locked down.
echo        Use only when you know exactly what is installed
echo        and are confident nothing legitimate will be blocked.
echo.
echo   FILES WRITTEN TO C:\WDAC\
echo   --------------------------
echo     WSSentinel.xml        Policy in human-readable XML
echo     policy_guid.txt       Policy GUID used by all modes
echo     detected_av_paths.txt AV/EDR folders whitelisted in Step 4
echo     detected_apps.json    Full app scan results from Step 5
echo     app_exclusions.txt    App numbers the user chose to block
echo     Remove-WDAC.ps1       Permanent rollback script (Step 7)
echo     WDAC_Report.txt       Last generated report
echo     {guid}.cip            Compiled binary policy
echo.
echo   RECOVERY
echo   --------
echo     If Enforce Mode blocks something critical:
echo.
echo     Option 1 (recommended):
echo       powershell -ExecutionPolicy Bypass -File C:\WDAC\Remove-WDAC.ps1
echo       Then reboot.
echo.
echo     Option 2 (if script is blocked too):
echo       Boot into Windows Recovery Environment (WinRE)
echo       Open Command Prompt and run:
echo         del "%SystemRoot%\System32\CodeIntegrity\CIPolicies\Active\*.cip"
echo       Then reboot normally.
echo.
goto END_NOCLEAN

:: ============================================================
:: CLEANUP TEMP PS SCRIPTS
:: ============================================================
:END
del "%WDAC_FOLDER%\detect_av.ps1"       >nul 2>&1
del "%WDAC_FOLDER%\scan_apps.ps1"       >nul 2>&1
del "%WDAC_FOLDER%\build_policy.ps1"    >nul 2>&1
del "%WDAC_FOLDER%\deploy_policy.ps1"   >nul 2>&1
del "%WDAC_FOLDER%\enforce_policy.ps1"  >nul 2>&1
del "%WDAC_FOLDER%\generate_report.ps1" >nul 2>&1
del "%WDAC_FOLDER%\harden.ps1"         >nul 2>&1
:: Note: lolbas_deny.txt is kept - the /report mode reads it for Section 3

:END_NOCLEAN
endlocal
