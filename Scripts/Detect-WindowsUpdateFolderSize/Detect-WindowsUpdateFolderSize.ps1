# run on T2 machine after syncing SharePoint or after you place a zip on a web server:
$src = 'C:\Users\TylerCox\OneDrive - Highspring\Packaging\!Modules\Add-UsersToIntuneGroup' # or path under OneDrive
Copy-Item -Path $src -Destination "$env:USERPROFILE\Documents\PowerShell\Modules" -Recurse -Force
Import-Module Add-UsersToIntuneGroup<#
.SYNOPSIS
    Detects the size of the Windows Update download directory and logs the result.

.DESCRIPTION
    This PowerShell script checks the size of the Windows Update download folder 
    located at "C:\Windows\SoftwareDistribution\Download". It logs the folder size 
    and status to "C:\WinUpdateDirSize.txt". If the folder size exceeds the 
    defined threshold (default: 500 KB), the script exits with code 1 to trigger 
    a remediation action (e.g., in Intune or system maintenance scripts).
    
    Designed to be lightweight, silent, and reliable with full transcript logging 
    and error handling.

.PARAMETER None
    The script takes no parameters.

.NOTES
Author: Tyler Cox
Created: 2025-10-21
Blog: blog.tylercox.tech
#>

# --- Script Start ---

$Path = "C:\Windows\SoftwareDistribution\Download"
$LogFile = "C:\WinUpdateDirSize.txt"
$Threshold = 500KB  # 500 * 1024 bytes

# Start transcript (captures all Write-Output / Write-Host / errors)
Start-Transcript -Path $LogFile -Append -ErrorAction SilentlyContinue

try {
    if (Test-Path $Path) {
        $Size = (Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($Size -gt $Threshold) {
            Write-Output "[$(Get-Date)] Folder size exceeds threshold: $([math]::Round($Size / 1KB, 2)) KB"
            Stop-Transcript | Out-Null
            exit 1  # Trigger remediation
        } else {
            Write-Output "[$(Get-Date)] Folder size within limit: $([math]::Round($Size / 1KB, 2)) KB"
            Stop-Transcript | Out-Null
            exit 0  # Compliant
        }
    } else {
        Write-Output "[$(Get-Date)] Path does not exist."
        Stop-Transcript | Out-Null
        exit 0  # Considered compliant if path missing
    }
}
catch {
    Write-Output "[$(Get-Date)] ERROR: $($_.Exception.Message)"
    Stop-Transcript | Out-Null
    exit 0  # Fail safe to compliant
}


