<#
.SYNOPSIS
Reset-WindowsUpdate.ps1 - Resets the Windows Update components

.DESCRIPTION
This script will reset all Windows Update components to DEFAULT SETTINGS.

.OUTPUTS
Results are printed to the console and written to a log file.

.NOTES
Written by: Tyler Cox

Change Log
V1.00, 10/21/2025 - Initial version
#>

# Define log path
$LogDir = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Remediation"
$LogFile = Join-Path $LogDir "Reset-WindowsUpdate.log"

# Create log directory if it doesn't exist
if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}

# Logging function
function Write-Log {
    param([string]$Message)
    $timestamped = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    Add-Content -Path $LogFile -Value $timestamped
    Write-Host $Message
}

# Start script
Write-Log "===== Starting Windows Update Reset Script ====="

# Detect architecture
$arch = Get-WMIObject -Class Win32_Processor -ComputerName LocalHost | Select-Object -ExpandProperty AddressWidth

# 1. Stop update-related services
Write-Log "1. Stopping Windows Update Services..."
Stop-Service -Name BITS -Force -ErrorAction SilentlyContinue
Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
Stop-Service -Name appidsvc -Force -ErrorAction SilentlyContinue
Stop-Service -Name cryptsvc -Force -ErrorAction SilentlyContinue

# 2. Remove BITS queue files
Write-Log "2. Removing QMGR Data files..."
Remove-Item "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -ErrorAction SilentlyContinue

# 3. Rename cache folders
Write-Log "3. Renaming SoftwareDistribution and CatRoot2 folders..."
Rename-Item "$env:systemroot\SoftwareDistribution" "$env:systemroot\SoftwareDistribution.bak" -ErrorAction SilentlyContinue
Rename-Item "$env:systemroot\System32\Catroot2" "$env:systemroot\System32\Catroot2.bak" -ErrorAction SilentlyContinue

# 4. Delete old update log
Write-Log "4. Removing old Windows Update log..."
Remove-Item "$env:systemroot\WindowsUpdate.log" -ErrorAction SilentlyContinue

# 5. Reset Windows Update service ACLs
Write-Log "5. Resetting Windows Update Services to default security descriptors..."
cmd /c "sc.exe sdset bits D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"
cmd /c "sc.exe sdset wuauserv D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"

# 6. Register DLLs
Write-Log "6. Registering Windows Update-related DLLs..."
Set-Location "$env:systemroot\system32"
$Dlls = @(
    "atl.dll", "urlmon.dll", "mshtml.dll", "shdocvw.dll", "browseui.dll", "jscript.dll",
    "vbscript.dll", "scrrun.dll", "msxml.dll", "msxml3.dll", "msxml6.dll", "actxprxy.dll",
    "softpub.dll", "wintrust.dll", "dssenh.dll", "rsaenh.dll", "gpkcsp.dll", "sccbase.dll",
    "slbcsp.dll", "cryptdlg.dll", "oleaut32.dll", "ole32.dll", "shell32.dll", "initpki.dll",
    "wuapi.dll", "wuaueng.dll", "wuaueng1.dll", "wucltui.dll", "wups.dll", "wups2.dll",
    "wuweb.dll", "qmgr.dll", "qmgrprxy.dll", "wucltux.dll", "muweb.dll", "wuwebv.dll"
)

foreach ($dll in $Dlls) {
    try {
        regsvr32.exe /s $dll
        Write-Log "Registered $dll"
    } catch {
        Write-Log "Failed to register ${dll}: $_"
    }
}

# 7. Remove WSUS Client IDs
Write-Log "7. Removing WSUS client identifiers from registry..."
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v AccountDomainSid /f | Out-Null
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v PingID /f | Out-Null
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v SusClientId /f | Out-Null

# 8. Reset Winsock and WinHTTP proxy
Write-Log "8. Resetting WinSock and WinHTTP proxy settings..."
netsh winsock reset | Out-Null
netsh winhttp reset proxy | Out-Null

# 9. Remove all BITS jobs
Write-Log "9. Deleting all BITS transfer jobs..."
try {
    Get-BitsTransfer | Remove-BitsTransfer -ErrorAction SilentlyContinue
    Write-Log "BITS jobs removed."
} catch {
    Write-Log "Error removing BITS jobs: $_"
}

# 10. Reinstall Windows Update Agent
Write-Log "10. Attempting to install the Windows Update Agent..."
$UpdateAgent = if ($arch -eq 64) { "Windows8-RT-KB2937636-x64" } else { "Windows8-RT-KB2937636-x86" }

try {
    wusa "$UpdateAgent.msu" /quiet | Out-Null
    Write-Log "Installed update agent: $UpdateAgent"
} catch {
    Write-Log "Failed to install update agent: $_"
}

# 11. Start update-related services
Write-Log "11. Starting Windows Update Services..."
Start-Service -Name BITS -ErrorAction SilentlyContinue
Start-Service -Name wuauserv -ErrorAction SilentlyContinue
Start-Service -Name appidsvc -ErrorAction SilentlyContinue
Start-Service -Name cryptsvc -ErrorAction SilentlyContinue

# 12. Trigger update discovery
Write-Log "12. Forcing update detection..."
wuauclt /resetauthorization /detectnow

Write-Log "===== Windows Update Reset Script Completed ====="
Write-Log "Please reboot your computer to complete the process."
