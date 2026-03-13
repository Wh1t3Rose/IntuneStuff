<#
.SYNOPSIS
    Detects the presence of the Lenovo TPQM Assistant executable.

.DESCRIPTION
    This detection script checks whether the Lenovo TPQM Assistant executable 
    (`TPQMAssistant.exe`) exists at the expected installation path:
    `C:\Program Files (x86)\Lenovo\TPQM\Assistant\TPQMAssistant.exe`.

    It returns exit code `1` if the file is found (non-compliant), and `0` if not found (compliant).
    This is commonly used in Intune detection and remediation workflows to determine 
    whether TPQM needs removal or hardening.

.PARAMETER None
    The script takes no parameters.

.NOTES
Author: Tyler Cox
Created: 2025-10-22
Blog: blog.tylercox.tech
#>

# --- Script Start ---

# Detect presence of the TPQM Assistant folder
$exePath = "C:\Program Files (x86)\Lenovo\TPQM\Assistant\TPQMAssistant.exe"

if (Test-Path -Path $exePath) {
    Write-Output "TPQMAssistant.exe present at: $exePath"
    exit 1
} else {
    Write-Output "TPQMAssistant.exe not present"
    exit 0
}


